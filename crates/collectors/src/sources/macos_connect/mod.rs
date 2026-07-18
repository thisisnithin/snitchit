//! Outbound-connection collector (macOS) — best-effort socket-table polling.
//!
//! The macOS counterpart to the eBPF backend's *connect* capture. Endpoint
//! Security has no IP-connect notification, and the only mechanism that sees
//! every connection at the kernel — a `NetworkExtension` content filter
//! (`NEFilterDataProvider`) — requires the restricted
//! `com.apple.developer.networking.networkextension` entitlement, i.e. an Apple
//! Developer account and an Apple-issued provisioning profile. The
//! clone-and-build / developer-mode path cannot provide that (developer mode
//! relaxes *notarization*, not entitlement signing), so this backend takes the
//! closest mechanism that works with **no entitlement** and — for the agent's
//! own process tree — **no root**: it polls the kernel socket table (`netstat2`)
//! and the process table (`libproc`) on a short interval, scopes connected TCP
//! sockets to the agent's process tree, and records each new outbound
//! destination once through the *same* [`Event::kernel_connect`] constructor as
//! the eBPF backend — byte-identical records.
//!
//! Honest limits versus the eBPF `connect()` hook (documented in README/TESTING):
//! * **Poll-based, not complete.** A connection that opens and closes entirely
//!   between two polls can be missed. eBPF hooks the syscall and sees every one.
//! * **TCP only.** The socket table exposes no remote endpoint for UDP.
//! * **Direction is inferred.** A socket-table entry is an established endpoint,
//!   not a `connect()` call, so an *accepted inbound* connection is
//!   indistinguishable from an *initiated outbound* one. Coding agents initiate
//!   outbound, which is what this targets; a listening agent would over-report.
//!
//! Observe-only (design principle #1): polling never blocks or slows the agent,
//! and a scan error is swallowed, not propagated. No `unsafe` lives here —
//! `netstat2` and `libproc` isolate all FFI behind safe APIs, so the workspace
//! `unsafe_code = "forbid"` holds, exactly as in the ES exec module.

use std::collections::HashSet;
use std::net::IpAddr;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use libproc::bsd_info::BSDInfo;
use libproc::proc_pid::pidinfo;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpSocketInfo,
};
use snitchit_core::clock::{new_record_id, now_rfc3339};
use snitchit_core::event::Event;
use snitchit_core::source::{EventSink, EventSource};
use snitchit_core::CoreError;

use super::netfmt::host_port;

/// How often to sample the socket table. Short enough to catch a normal
/// request's connection (which lives for tens of ms upward), long enough that
/// enumerating sockets is not a meaningful load. See the "poll-based" limit.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Guards the parent-walk against a pathological/cyclic proc table.
const MAX_TREE_DEPTH: u32 = 64;

fn seam(msg: impl std::fmt::Display) -> CoreError {
    CoreError::Source(msg.to_string())
}

/// A connection's identity: the TCP 4-tuple. Deliberately excludes the owning
/// pid — a held socket fd is inherited by child processes, so `associated_pids`
/// reorders across scans; keying on the 4-tuple records each connection once.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnKey {
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
}

/// Polls the socket table for outbound TCP connections made by the wrapped
/// agent's process tree. Holds only `Send` handles to its poller thread.
pub struct MacosConnectCollector {
    session_id: String,
    root_pid: u32,
    poller: Option<JoinHandle<()>>,
    shutdown: Option<Sender<()>>,
}

impl MacosConnectCollector {
    /// Build a collector scoped to `root_pid`'s process tree. Use the snitchit
    /// process's own pid so everything it spawns is in scope.
    #[must_use]
    pub fn new(session_id: impl Into<String>, root_pid: u32) -> Self {
        Self {
            session_id: session_id.into(),
            root_pid,
            poller: None,
            shutdown: None,
        }
    }

    /// Why the collector might be unavailable — kept in one place, mirroring the
    /// eBPF/ES collectors. Polling needs no entitlement and no root for the
    /// agent's own tree, so this rarely fires.
    #[must_use]
    pub fn privilege_hint() -> &'static str {
        "connect collector polls the socket table (no entitlement, no root for the agent's own tree); \
         complete kernel-level capture would need a `NetworkExtension` entitlement"
    }
}

impl EventSource for MacosConnectCollector {
    fn name(&self) -> &str {
        "macos-connect"
    }

    fn start(&mut self, sink: EventSink) -> snitchit_core::Result<()> {
        let root = i32::try_from(self.root_pid).map_err(|_| seam("root pid out of range"))?;

        // One probe up front: if the socket table can't be read at all, report
        // unavailable so the caller logs it and continues (design principle #1).
        get_sockets_info(af_flags(), ProtocolFlags::TCP).map_err(|e| {
            seam(format!(
                "socket table unavailable: {e}; {}",
                Self::privilege_hint()
            ))
        })?;

        let session = self.session_id.clone();
        let (shutdown_tx, shutdown_rx) = bounded::<()>(1);
        self.poller = Some(thread::spawn(move || {
            poll_loop(root, &session, &sink, &shutdown_rx);
        }));
        self.shutdown = Some(shutdown_tx);
        Ok(())
    }

    /// Stop the poller and join it. Idempotent.
    fn stop(&mut self) -> snitchit_core::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.poller.take() {
            let _ = h.join();
        }
        Ok(())
    }
}

fn af_flags() -> AddressFamilyFlags {
    AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6
}

/// Sample the socket table until told to stop, emitting each newly-seen outbound
/// connection once. A final scan after the shutdown signal catches connections
/// opened during the last interval.
fn poll_loop(root: i32, session: &str, sink: &EventSink, shutdown: &Receiver<()>) {
    let debug = std::env::var_os("SNITCHIT_ES_DEBUG").is_some();
    let mut seen: HashSet<ConnKey> = HashSet::new();
    loop {
        scan_once(root, session, sink, &mut seen, &live_parent_of);
        if shutdown.recv_timeout(POLL_INTERVAL).is_ok() {
            scan_once(root, session, sink, &mut seen, &live_parent_of);
            if debug {
                eprintln!(
                    "snitchit: connect poller recorded {} connection(s)",
                    seen.len()
                );
            }
            return;
        }
    }
}

/// One pass over the socket table: for every connected TCP socket owned by a
/// pid in the agent's tree, record its destination once. `parent_of` resolves a
/// pid's parent (injected so the scoping logic is unit-testable without libproc).
fn scan_once(
    root: i32,
    session: &str,
    sink: &EventSink,
    seen: &mut HashSet<ConnKey>,
    parent_of: &dyn Fn(i32) -> Option<i32>,
) {
    let Ok(sockets) = get_sockets_info(af_flags(), ProtocolFlags::TCP) else {
        return; // observe-only: a failed scan is skipped, never fatal
    };
    // Cache tree membership per pid within this scan — many sockets share a pid.
    let mut membership: std::collections::HashMap<i32, bool> = std::collections::HashMap::new();
    for socket in sockets {
        let ProtocolSocketInfo::Tcp(tcp) = &socket.protocol_socket_info else {
            continue;
        };
        if !is_outbound(tcp) {
            continue;
        }
        let in_tree = socket.associated_pids.iter().any(|&pid| {
            let pid = i32::try_from(pid).unwrap_or(-1);
            *membership
                .entry(pid)
                .or_insert_with(|| is_in_tree(pid, root, parent_of))
        });
        if !in_tree {
            continue;
        }
        let key = ConnKey {
            local_addr: tcp.local_addr,
            local_port: tcp.local_port,
            remote_addr: tcp.remote_addr,
            remote_port: tcp.remote_port,
        };
        if seen.insert(key) {
            let dest = host_port(tcp.remote_addr, tcp.remote_port);
            sink.emit(Event::kernel_connect(
                session,
                new_record_id(),
                now_rfc3339(),
                &dest,
            ));
        }
    }
}

/// Whether a TCP socket represents an outbound connection to a real peer: it has
/// a foreign endpoint (which listeners and unbound sockets do not). Pure — the
/// predicate is unit-tested.
fn is_outbound(tcp: &TcpSocketInfo) -> bool {
    tcp.remote_port != 0 && !tcp.remote_addr.is_unspecified()
}

/// Walk parent links from `pid` toward `root`. Pure given `parent_of`; the
/// depth guard bounds a pathological or cyclic process table.
fn is_in_tree(mut pid: i32, root: i32, parent_of: &dyn Fn(i32) -> Option<i32>) -> bool {
    let mut depth = 0;
    while depth < MAX_TREE_DEPTH {
        if pid == root {
            return true;
        }
        if pid <= 1 {
            return false;
        }
        match parent_of(pid) {
            Some(parent) => pid = parent,
            None => return false,
        }
        depth += 1;
    }
    false
}

/// Production parent resolver: a process's ppid via libproc's `proc_bsdinfo`
/// (a plain integer field — no `unsafe` and no union access on our side).
fn live_parent_of(pid: i32) -> Option<i32> {
    pidinfo::<BSDInfo>(pid, 0)
        .ok()
        .and_then(|info| i32::try_from(info.pbi_ppid).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn parents(map: &HashMap<i32, i32>) -> impl Fn(i32) -> Option<i32> + '_ {
        move |pid| map.get(&pid).copied()
    }

    #[test]
    fn tree_membership_includes_descendants_and_root() {
        // 100 (root/snitchit) -> 200 (agent bash) -> 300 (curl); 999 unrelated.
        let map = HashMap::from([(200, 100), (300, 200), (999, 500), (500, 1)]);
        let parent_of = parents(&map);
        assert!(is_in_tree(100, 100, &parent_of), "root is in its own tree");
        assert!(is_in_tree(200, 100, &parent_of), "direct child");
        assert!(is_in_tree(300, 100, &parent_of), "grandchild");
        assert!(!is_in_tree(999, 100, &parent_of), "unrelated host process");
        assert!(!is_in_tree(500, 100, &parent_of), "unrelated parent");
    }

    #[test]
    fn tree_walk_terminates_on_missing_parent_and_cycles() {
        let orphan = HashMap::new();
        assert!(
            !is_in_tree(42, 100, &parents(&orphan)),
            "no parent info → not in tree"
        );
        // A cycle 10 -> 11 -> 10 must not loop forever, and must not match root.
        let cyclic = HashMap::from([(10, 11), (11, 10)]);
        assert!(!is_in_tree(10, 100, &parents(&cyclic)));
    }

    #[test]
    fn outbound_predicate_excludes_listeners_and_unbound() {
        let established = TcpSocketInfo {
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 54321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 443,
            state: netstat2::TcpState::Established,
        };
        assert!(is_outbound(&established));

        let listener = TcpSocketInfo {
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 8080,
            remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
            state: netstat2::TcpState::Listen,
        };
        assert!(!is_outbound(&listener));

        let v6 = TcpSocketInfo {
            local_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            local_port: 1234,
            remote_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            remote_port: 80,
            state: netstat2::TcpState::Established,
        };
        assert!(is_outbound(&v6));
    }

    #[test]
    fn destinations_dedup_by_connection_four_tuple() {
        let mut seen = HashSet::new();
        let key = |local_port| ConnKey {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)),
            local_port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 443,
        };
        assert!(seen.insert(key(1000)), "first sighting records");
        // The same connection seen on a later poll (e.g. once fd 3 is inherited
        // by a child so associated_pids reorders) must not re-record.
        assert!(!seen.insert(key(1000)), "same 4-tuple does not re-record");
        assert!(
            seen.insert(key(1001)),
            "a different local port is a new connection"
        );
    }
}
