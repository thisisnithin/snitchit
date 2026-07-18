//! Kernel-observation collector (Linux, eBPF via `aya`) — the third tier.
//!
//! Sees what the terminal surface (PTY) and in-process hooks cannot: the
//! processes the agent's tree `exec`s and the outbound connections it opens,
//! observed directly at the kernel. That direct observation is trust-boundary
//! evidence, so records are `capture: Captured` — the strongest tier.
//!
//! Scope is the wrapped agent's process tree: the eBPF side seeds a tracked-pid
//! set with snitchit's own pid and grows it on every `fork` whose parent is
//! tracked, so unrelated host processes are excluded.
//!
//! Everything here is **safe** Rust: the BPF bytecode (the only `unsafe`) is a
//! separate, workspace-excluded crate, vendored as a prebuilt object and loaded
//! at runtime. Events arrive as fixed-layout bytes over a `RingBuf`, which we
//! parse with `from_ne_bytes` — no transmute, no `unsafe`. Redaction/hashing go
//! through the same `Event` constructors as every other collector; raw argv and
//! addresses never leave this module.
//!
//! Observe-only (design principle #1): if the probes can't load (no privilege,
//! unsupported kernel, no BTF) `start` returns an error and the caller keeps
//! running PTY + hooks. It never blocks or slows the wrapped agent.

use std::thread::{self, JoinHandle};
use std::time::Duration;

use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use crossbeam_channel::{bounded, Receiver, Sender};
use snitchit_core::clock::{new_record_id, now_rfc3339};
use snitchit_core::event::Event;
use snitchit_core::source::{EventSink, EventSource};
use snitchit_core::CoreError;

/// Event-kind discriminants, shared by byte value with the eBPF program.
const KIND_EXEC: u32 = 0;
const KIND_CONNECT: u32 = 1;
/// Fixed `RawEvent` layout emitted by the eBPF side: `kind`(u32) `pid`(u32)
/// `data_len`(u32) then `data`. Header is 12 bytes.
const HEADER: usize = 12;
/// Payload capacity and per-argv slot size — must match the eBPF program.
const DATA_LEN: usize = 176;
const SLOT: usize = DATA_LEN / 3;

fn seam(msg: impl std::fmt::Display) -> CoreError {
    CoreError::Source(msg.to_string())
}

/// Wraps the eBPF programs and a reader thread that turns kernel events into
/// records on the shared sink.
pub struct KernelCollector {
    session_id: String,
    root_pid: u32,
    // Kept alive for the collector's lifetime: dropping it detaches the probes.
    ebpf: Option<Ebpf>,
    reader: Option<JoinHandle<()>>,
    shutdown: Option<Sender<()>>,
}

impl KernelCollector {
    /// Build a collector scoped to `root_pid`'s process tree. Use the snitchit
    /// process's own pid so everything it spawns (the agent and its
    /// descendants) is in scope.
    #[must_use]
    pub fn new(session_id: impl Into<String>, root_pid: u32) -> Self {
        Self {
            session_id: session_id.into(),
            root_pid,
            ebpf: None,
            reader: None,
            shutdown: None,
        }
    }

    /// The privilege hint shown when loading fails — kept in one place.
    #[must_use]
    pub fn privilege_hint() -> &'static str {
        "kernel collector needs root or CAP_BPF+CAP_PERFMON (and a BTF-enabled kernel)"
    }
}

impl EventSource for KernelCollector {
    fn name(&self) -> &str {
        "ebpf"
    }

    fn start(&mut self, sink: EventSink) -> snitchit_core::Result<()> {
        // Load the vendored BPF object (built separately with nightly +
        // bpf-linker; see crates/collectors/ebpf).
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/sources/kernel/snitchit.ebpf.o"
        )))
        .map_err(|e| seam(format!("load eBPF ({e}); {}", Self::privilege_hint())))?;

        // Seed the tracked-pid set BEFORE attaching, so the very first fork of
        // the agent is already scoped in.
        {
            let mut tracked: BpfHashMap<&mut MapData, u32, u8> = BpfHashMap::try_from(
                ebpf.map_mut("TRACKED")
                    .ok_or_else(|| seam("eBPF map TRACKED missing"))?,
            )
            .map_err(seam)?;
            tracked.insert(self.root_pid, 1, 0).map_err(seam)?;
        }
        if std::env::var_os("SNITCHIT_EBPF_DEBUG").is_some() {
            eprintln!("snitchit: ebpf seed (tracked root) pid={}", self.root_pid);
        }

        attach(&mut ebpf, "snitchit_fork", "sched", "sched_process_fork")?;
        attach(&mut ebpf, "snitchit_exec", "syscalls", "sys_enter_execve")?;
        attach(
            &mut ebpf,
            "snitchit_connect",
            "syscalls",
            "sys_enter_connect",
        )?;

        // Self-identification probe: connect once to the sentinel the eBPF
        // connect handler recognizes, so it seeds snitchit's kernel-visible
        // (root-namespace) pid as the tree root. This is the reliable seed under
        // a pid namespace (WSL2/containers), where the pid we know is
        // namespace-local and never matches the kernel's view. The connect is a
        // no-op UDP association that sends nothing; failure is harmless.
        let _ = std::net::UdpSocket::bind(("127.0.0.1", 0))
            .and_then(|s| s.connect(("127.1.2.3", 48879)));

        // Own the ring buffer in the reader thread.
        let ring = RingBuf::try_from(
            ebpf.take_map("EVENTS")
                .ok_or_else(|| seam("eBPF map EVENTS missing"))?,
        )
        .map_err(seam)?;

        let (tx, rx) = bounded::<()>(1);
        let session = self.session_id.clone();
        self.reader = Some(thread::spawn(move || read_loop(ring, &sink, &session, &rx)));
        self.shutdown = Some(tx);
        self.ebpf = Some(ebpf);
        Ok(())
    }

    /// Detach probes and stop the reader. Idempotent.
    fn stop(&mut self) -> snitchit_core::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
        // Dropping the Ebpf detaches every program link.
        self.ebpf = None;
        Ok(())
    }
}

/// Load + attach one tracepoint program by function name and (category, name).
fn attach(ebpf: &mut Ebpf, prog: &str, category: &str, name: &str) -> snitchit_core::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(prog)
        .ok_or_else(|| seam(format!("eBPF program {prog} missing")))?
        .try_into()
        .map_err(seam)?;
    program
        .load()
        .map_err(|e| seam(format!("verifier rejected {prog}: {e}")))?;
    program
        .attach(category, name)
        .map_err(|e| seam(format!("attach {prog} to {category}:{name}: {e}")))?;
    Ok(())
}

/// Drain the ring buffer until told to stop. Non-blocking `next()` plus a short
/// `recv_timeout` gives shutdown responsiveness without a busy loop and without
/// any `unsafe` fd polling.
fn read_loop(mut ring: RingBuf<MapData>, sink: &EventSink, session: &str, shutdown: &Receiver<()>) {
    let debug = std::env::var_os("SNITCHIT_EBPF_DEBUG").is_some();
    let mut seen: u64 = 0;
    let mut drain = |ring: &mut RingBuf<MapData>| {
        while let Some(item) = ring.next() {
            seen += 1;
            if let Some(event) = parse(&item, session) {
                sink.emit(event);
            }
        }
    };
    loop {
        drain(&mut ring);
        if shutdown.recv_timeout(Duration::from_millis(50)).is_ok() {
            // Final drain: events produced during the last sleep must not be lost.
            drain(&mut ring);
            if debug {
                eprintln!("snitchit: ebpf reader saw {seen} raw kernel event(s)");
            }
            return;
        }
    }
}

/// Parse one fixed-layout `RawEvent` into a redacted `Event`. Returns `None` for
/// malformed or uninteresting records (e.g. non-IP sockaddr families).
fn parse(bytes: &[u8], session: &str) -> Option<Event> {
    if bytes.len() < HEADER {
        return None;
    }
    let kind = u32::from_ne_bytes(bytes[0..4].try_into().ok()?);
    let data_len = u32::from_ne_bytes(bytes[8..12].try_into().ok()?) as usize;
    let data = bytes.get(HEADER..HEADER + data_len.min(bytes.len() - HEADER))?;

    match kind {
        KIND_EXEC => {
            // Three fixed slots: program path, argv[1], argv[2].
            let program = cstr(data.get(0..SLOT)?);
            if program.is_empty() {
                return None;
            }
            let args = [
                cstr(data.get(SLOT..2 * SLOT)?),
                cstr(data.get(2 * SLOT..3 * SLOT)?),
            ];
            let mut cmdline = program.to_string();
            for a in args {
                if !a.is_empty() {
                    cmdline.push(' ');
                    cmdline.push_str(a);
                }
            }
            Some(Event::kernel_exec(
                session,
                new_record_id(),
                now_rfc3339(),
                program,
                &cmdline,
            ))
        }
        KIND_CONNECT => {
            let dest = format_sockaddr(data)?;
            Some(Event::kernel_connect(
                session,
                new_record_id(),
                now_rfc3339(),
                &dest,
            ))
        }
        _ => None,
    }
}

/// Interpret a fixed slot as a NUL-terminated string (lossy UTF-8, trimmed).
fn cstr(slot: &[u8]) -> &str {
    let end = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
    std::str::from_utf8(&slot[..end]).unwrap_or("").trim()
}

/// Format a raw `sockaddr` copy (`AF_INET` / `AF_INET6`) as `host:port`. The family
/// is host-endian; the port and address are network byte order. The final
/// `host:port` string is built by the shared [`super::netfmt::host_port`] so it
/// is byte-identical to what the macOS connect backend emits.
fn format_sockaddr(data: &[u8]) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if data.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes(data[0..2].try_into().ok()?);
    let port = u16::from_be_bytes(data[2..4].try_into().ok()?);
    match family {
        2 => {
            // AF_INET: sin_addr at offset 4 (4 bytes).
            let a = data.get(4..8)?;
            let ip = IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]));
            Some(super::netfmt::host_port(ip, port))
        }
        10 => {
            // AF_INET6: sin6_addr at offset 8 (16 bytes).
            let a = data.get(8..24)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(a);
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            Some(super::netfmt::host_port(ip, port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fixed `RawEvent` byte buffer: `kind`(u32) `pid`(u32) `data_len`(u32)
    /// then `data` — the exact layout the eBPF side emits.
    fn raw(kind: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER + data.len());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid (unused by parse)
        buf.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_ne_bytes());
        buf.extend_from_slice(data);
        buf
    }

    fn exec_slots(program: &str, arg1: &str, arg2: &str) -> Vec<u8> {
        let mut data = vec![0u8; DATA_LEN];
        for (slot, s) in [program, arg1, arg2].iter().enumerate() {
            let start = slot * SLOT;
            let bytes = s.as_bytes();
            let n = bytes.len().min(SLOT - 1); // leave room for the NUL
            data[start..start + n].copy_from_slice(&bytes[..n]);
        }
        data
    }

    #[test]
    fn cstr_reads_up_to_nul_and_trims() {
        assert_eq!(cstr(b"git\0\0\0"), "git");
        assert_eq!(cstr(b"no-nul-here"), "no-nul-here");
        assert_eq!(cstr(b"  spaced \0"), "spaced");
        assert_eq!(cstr(&[]), "");
    }

    #[test]
    fn exec_parses_program_and_two_argv_slots() {
        let bytes = raw(KIND_EXEC, &exec_slots("/usr/bin/git", "commit", "-m"));
        let ev = parse(&bytes, "sess").expect("exec event");
        let v = ev.to_value().unwrap();
        assert_eq!(v["action"]["type"], "tool_call");
        assert_eq!(v["action"]["tool"], "/usr/bin/git");
        assert_eq!(v["source"]["adapter"], "ebpf");
    }

    #[test]
    fn exec_with_empty_program_is_dropped() {
        let bytes = raw(KIND_EXEC, &exec_slots("", "", ""));
        assert!(parse(&bytes, "sess").is_none());
    }

    #[test]
    fn connect_ipv4_formats_dotted_quad() {
        // family AF_INET(2, host-endian), port 443 (be), 93.184.216.34.
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_ne_bytes());
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(&[93, 184, 216, 34]);
        let ev = parse(&raw(KIND_CONNECT, &data), "sess").expect("connect event");
        let v = ev.to_value().unwrap();
        assert_eq!(v["action"]["type"], "network");
        assert_eq!(v["source"]["adapter"], "ebpf");
    }

    #[test]
    fn connect_with_unknown_family_is_dropped() {
        let mut data = Vec::new();
        data.extend_from_slice(&7u16.to_ne_bytes()); // not AF_INET/INET6
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 0]);
        assert!(parse(&raw(KIND_CONNECT, &data), "sess").is_none());
    }

    #[test]
    fn truncated_header_is_dropped() {
        assert!(parse(&[0u8; 4], "sess").is_none());
    }
}
