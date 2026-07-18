//! Kernel-observation collector (macOS, Apple Endpoint Security) — the third
//! tier, the macOS counterpart to the Linux eBPF [`KernelCollector`].
//!
//! Sees what the terminal surface (PTY) and in-process hooks cannot: the
//! processes the agent's tree `exec`s, observed directly at the kernel via the
//! Endpoint Security (ES) framework. That direct observation is trust-boundary
//! evidence, so records are `capture: Captured` — the strongest tier. Records
//! are produced through the *same* [`Event::kernel_exec`] constructor as the
//! eBPF side, so a macOS chain is byte-for-byte the shape of a Linux one (the
//! `ebpf` source tag is reused deliberately; see the crate README).
//!
//! Scope is the wrapped agent's process tree, exactly as on Linux: we seed a
//! tracked-pid set with snitchit's own pid and grow it on every ES
//! `NOTIFY_FORK` whose parent is already tracked, so unrelated host processes
//! are excluded. macOS has no pid namespaces, so `std::process::id()` is the
//! kernel-visible pid and no self-identification probe is needed.
//!
//! **Exec-only, by design.** ES exposes no IP-socket connect notification — its
//! only connect events are `UIPC_CONNECT` (Unix-domain sockets) and
//! `XPC_CONNECT`. Outbound-connection capture on macOS is therefore handled by a
//! separate collector, [`super::macos_connect`] (socket-table polling), which
//! together with this module brings the macOS kernel tier to exec + connect
//! parity with the Linux eBPF backend. Everything here mirrors the eBPF
//! collector's *exec* path.
//!
//! Observe-only (design principle #1): if the ES client can't be created
//! (missing entitlement, not root, developer mode off, TCC not granted)
//! [`start`](EndpointSecurityCollector::start) returns an error and the caller
//! keeps running PTY + hooks. It never blocks or slows the wrapped agent. This
//! is NOTIFY-only — it never subscribes to AUTH events and never makes an
//! authorization decision; snitchit is strictly an observer.
//!
//! All `unsafe`/FFI lives in the `endpoint-sec` dependency, which exposes a safe
//! Rust API; this module contains no `unsafe`, so the workspace-wide
//! `unsafe_code = "forbid"` still holds here just as it does for the eBPF side.

use std::collections::HashSet;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{bounded, Receiver, Sender};
use endpoint_sec::sys::es_event_type_t;
use endpoint_sec::{Client, Event as EsEvent, Message};
use snitchit_core::clock::{new_record_id, now_rfc3339};
use snitchit_core::event::Event;
use snitchit_core::source::{EventSink, EventSource};
use snitchit_core::CoreError;

/// Argv slots recorded per exec: the resolved program path plus `argv[1]` and
/// `argv[2]`, mirroring the eBPF program's fixed three-slot layout. `argv[0]`
/// duplicates the program name and is skipped. Bounds what we store — never the
/// full, unbounded argv.
const MAX_ARGV_EXTRA: u32 = 2;

fn seam(msg: impl std::fmt::Display) -> CoreError {
    CoreError::Source(msg.to_string())
}

/// Wraps an Endpoint Security client and the dedicated thread that owns its
/// lifetime, turning kernel exec events into records on the shared sink.
///
/// The ES `Client` is `!Send` (Apple requires it be released on the thread that
/// created it), so — unlike the eBPF collector, whose `Ebpf` handle is `Send`
/// and lives in the struct — the client is created, held, and dropped entirely
/// inside `worker`. The struct keeps only `Send` handles to it.
pub struct EndpointSecurityCollector {
    session_id: String,
    root_pid: u32,
    worker: Option<JoinHandle<()>>,
    shutdown: Option<Sender<()>>,
}

impl EndpointSecurityCollector {
    /// Build a collector scoped to `root_pid`'s process tree. Use the snitchit
    /// process's own pid so everything it spawns (the agent and its
    /// descendants) is in scope.
    #[must_use]
    pub fn new(session_id: impl Into<String>, root_pid: u32) -> Self {
        Self {
            session_id: session_id.into(),
            root_pid,
            worker: None,
            shutdown: None,
        }
    }

    /// The privilege hint shown when the ES client can't be created — kept in
    /// one place, mirroring the eBPF collector's `privilege_hint`.
    #[must_use]
    pub fn privilege_hint() -> &'static str {
        "endpoint security collector needs root plus the Endpoint Security entitlement \
         (or `systemextensionsctl developer on` for a local self-build) and TCC approval"
    }
}

impl EventSource for EndpointSecurityCollector {
    fn name(&self) -> &str {
        "endpoint-security"
    }

    fn start(&mut self, sink: EventSink) -> snitchit_core::Result<()> {
        let root = i32::try_from(self.root_pid).map_err(|_| seam("root pid out of range"))?;
        let session = self.session_id.clone();

        // The worker reports readiness synchronously so `start` can return an
        // error (client not entitled / not root / dev-mode off) and the caller
        // keeps running PTY + hooks — never blocking the agent.
        let (init_tx, init_rx) = bounded::<std::result::Result<(), String>>(1);
        let (shutdown_tx, shutdown_rx) = bounded::<()>(1);
        let worker = thread::spawn(move || worker(root, &session, &sink, &init_tx, &shutdown_rx));

        match init_rx.recv() {
            Ok(Ok(())) => {
                self.worker = Some(worker);
                self.shutdown = Some(shutdown_tx);
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = worker.join();
                Err(seam(e))
            }
            Err(_) => {
                let _ = worker.join();
                Err(seam("endpoint security worker exited before init"))
            }
        }
    }

    /// Signal the worker to release the ES client and stop. Idempotent.
    fn stop(&mut self) -> snitchit_core::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
        Ok(())
    }
}

/// Own the ES client for its whole life on one thread: create it, subscribe,
/// report readiness, then hold it alive until `stop` signals shutdown. Dropping
/// the client here — on its creating thread — releases it, per Apple's contract.
fn worker(
    root: i32,
    session: &str,
    sink: &EventSink,
    init: &Sender<std::result::Result<(), String>>,
    shutdown: &Receiver<()>,
) {
    // Tracked-pid set, seeded with the root BEFORE the client is created, so the
    // agent's very first fork is already in scope. `Client::new` requires an
    // `Fn` handler (ES may invoke it re-entrantly), so the set lives behind a
    // mutex rather than a plain `FnMut` capture.
    let tracked = std::sync::Arc::new(std::sync::Mutex::new(HashSet::from([root])));

    let handler_tracked = std::sync::Arc::clone(&tracked);
    let handler_sink = sink.clone();
    let handler_session = session.to_string();
    let client = Client::new(move |_client, message: Message| {
        handle(&message, &handler_tracked, &handler_sink, &handler_session);
    });

    let mut client = match client {
        Ok(c) => c,
        Err(e) => {
            let _ = init.send(Err(format!(
                "es_new_client failed: {e}; {}",
                EndpointSecurityCollector::privilege_hint()
            )));
            return;
        }
    };

    // NOTIFY-only: observe exec and fork, never AUTH, never a decision. Connect
    // capture is not here — ES has no IP-connect event — it lives in the sibling
    // `macos_connect` collector (socket-table polling).
    let events = [
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
    ];
    if let Err(e) = client.subscribe(&events) {
        let _ = init.send(Err(format!("es_subscribe failed: {e}")));
        return;
    }

    if std::env::var_os("SNITCHIT_ES_DEBUG").is_some() {
        eprintln!("snitchit: endpoint-security seed (tracked root) pid={root}");
    }
    let _ = init.send(Ok(()));

    // Hold the client alive on this thread until told to stop; ES invokes the
    // handler on its own dispatch queue meanwhile. Dropping the client on the
    // creating thread (below) is what releases it.
    let _ = shutdown.recv();
    drop(client);
}

/// Translate one ES message into tracked-set maintenance or a redacted exec
/// record. Never panics: lock poisoning and missing fields are treated as
/// "skip", per observe-only.
fn handle(
    message: &Message,
    tracked: &std::sync::Mutex<HashSet<i32>>,
    sink: &EventSink,
    session: &str,
) {
    match message.event() {
        // Grow the tree: a fork whose parent is tracked puts the child in scope,
        // exactly as the eBPF side grows TRACKED on sched_process_fork.
        Some(EsEvent::NotifyFork(fork)) => {
            let parent = message.process().audit_token().pid();
            let child = fork.child().audit_token().pid();
            if let Ok(mut set) = tracked.lock() {
                note_fork(&mut set, parent, child);
            }
        }
        // Record an exec for a process in the tree, and grow the tree on it.
        Some(EsEvent::NotifyExec(exec)) => {
            let process = message.process();
            let pid = process.audit_token().pid();
            let ppid = process.ppid();
            let in_tree = match tracked.lock() {
                Ok(mut set) => admit_exec(&mut set, pid, ppid),
                Err(_) => false,
            };
            if !in_tree {
                return;
            }
            let program = exec
                .target()
                .executable()
                .path()
                .to_string_lossy()
                .into_owned();
            if program.is_empty() {
                return;
            }
            let args = (1..exec.arg_count().min(1 + MAX_ARGV_EXTRA)).filter_map(|i| exec.arg(i));
            let cmdline = assemble_cmdline(&program, args);
            // Same constructor as the eBPF side — redaction/hashing happen here;
            // raw argv/paths never leave this module.
            sink.emit(Event::kernel_exec(
                session,
                new_record_id(),
                now_rfc3339(),
                &program,
                &cmdline,
            ));
        }
        _ => {}
    }
}

/// A fork grows the tree only when its parent is already tracked; then the child
/// joins. Pure so it is unit-testable without an ES client.
fn note_fork(tracked: &mut HashSet<i32>, parent: i32, child: i32) {
    if tracked.contains(&parent) {
        tracked.insert(child);
    }
}

/// An exec is in the tree when the process — or its parent — is already tracked
/// (the parent check admits `posix_spawn` children, whose fork event may not
/// precede the exec). Admitting inserts the pid so its own descendants follow.
/// Returns whether the exec should be recorded. Pure; unit-tested.
fn admit_exec(tracked: &mut HashSet<i32>, pid: i32, ppid: i32) -> bool {
    if tracked.contains(&pid) || tracked.contains(&ppid) {
        tracked.insert(pid);
        true
    } else {
        false
    }
}

/// Join a resolved program path with its (already length-capped) argv into the
/// display string, skipping empties. Mirrors the eBPF side's `program + argv[1] +
/// argv[2]`. Pure; unit-tested. Generic over the arg iterator so the caller can
/// pass ES's `&OsStr`s without allocating a vector.
fn assemble_cmdline(
    program: &str,
    args: impl Iterator<Item = impl AsRef<std::ffi::OsStr>>,
) -> String {
    let mut cmdline = program.to_string();
    for arg in args {
        let arg = arg.as_ref().to_string_lossy();
        if !arg.is_empty() {
            cmdline.push(' ');
            cmdline.push_str(&arg);
        }
    }
    cmdline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_grows_tree_only_from_a_tracked_parent() {
        let mut set = HashSet::from([100]);
        note_fork(&mut set, 100, 200); // parent tracked → child joins
        assert!(set.contains(&200));
        note_fork(&mut set, 999, 300); // parent NOT tracked → child excluded
        assert!(!set.contains(&300));
    }

    #[test]
    fn exec_admitted_by_pid_or_parent_and_records_membership() {
        let mut set = HashSet::from([100]);
        // pid already tracked (e.g. seeded root or from a prior fork).
        assert!(admit_exec(&mut set, 100, 1));
        // child seen only at exec (posix_spawn): admitted via tracked parent…
        assert!(admit_exec(&mut set, 200, 100));
        // …and now itself tracked, so its own child is admitted.
        assert!(admit_exec(&mut set, 300, 200));
        // unrelated process with an untracked parent is rejected.
        assert!(!admit_exec(&mut set, 900, 800));
        assert!(!set.contains(&900));
    }

    #[test]
    fn cmdline_joins_program_and_nonempty_args() {
        let args = ["commit", "-m"].into_iter().map(std::ffi::OsString::from);
        assert_eq!(
            assemble_cmdline("/usr/bin/git", args),
            "/usr/bin/git commit -m"
        );

        let with_empty = ["", "sub"].into_iter().map(std::ffi::OsString::from);
        assert_eq!(assemble_cmdline("prog", with_empty), "prog sub");

        let none = std::iter::empty::<std::ffi::OsString>();
        assert_eq!(assemble_cmdline("/bin/ls", none), "/bin/ls");
    }
}
