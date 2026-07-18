//! snitchit kernel-observation eBPF programs (Linux, `bpfel-unknown-none`).
//!
//! Three tracepoints, all scoped to the wrapped agent's process tree:
//!   * `sched_process_fork` — grow the tracked-pid set (seed = snitchit's own
//!     pid, inserted from userspace); any child of a tracked pid is tracked, so
//!     the whole subtree is covered without reading `task_struct`.
//!   * `sys_enter_execve` — a tracked process exec'ing a binary (program + argv).
//!   * `sys_enter_connect` — a tracked process opening an outbound connection
//!     (raw `sockaddr` copied out; userspace formats host:port).
//!
//! Events are pushed to a `RingBuf`; userspace redacts + hashes them. Raw argv
//! and addresses only ever live in this transient event, never in a record.
//!
//! `unsafe` is unavoidable here (eBPF context/user-memory reads); this crate is
//! excluded from the workspace, so the workspace `unsafe_code = "forbid"` does
//! not (and cannot) apply to it.
#![no_std]
#![no_main]
#![allow(unsafe_code)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

/// Event kinds packed into `RawEvent.kind`.
const KIND_EXEC: u32 = 0;
const KIND_CONNECT: u32 = 1;

/// Payload capacity. Kept small so the whole event fits the eBPF stack budget;
/// userspace truncates/redacts anyway.
const DATA_LEN: usize = 176;

/// Fixed-layout event shared with userspace by byte offset (see `kernel.rs`).
#[repr(C)]
struct RawEvent {
    kind: u32,
    pid: u32,
    data_len: u32,
    data: [u8; DATA_LEN],
}

/// pids in the agent's process tree; value is a marker. Seeded from userspace
/// with snitchit's own pid, then grown by `sched_process_fork`.
#[map]
static TRACKED: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

/// Kernel → userspace event channel.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn tracked(pid: u32) -> bool {
    // SAFETY: read-only map lookup; the returned reference is not retained.
    unsafe { TRACKED.get(&pid).is_some() }
}

// ---- sched_process_fork : grow the tracked set --------------------------------
// Layout after the 8-byte common header: parent_comm[16]@8, parent_pid@24,
// child_comm[16]@28, child_pid@44.
#[tracepoint]
pub fn snitchit_fork(ctx: TracePointContext) -> u32 {
    try_fork(&ctx).unwrap_or(0)
}

fn try_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    // SAFETY: reading fixed tracepoint fields at documented offsets.
    let parent_pid: i32 = unsafe { ctx.read_at(24)? };
    let child_pid: i32 = unsafe { ctx.read_at(44)? };
    if tracked(parent_pid as u32) {
        let child = child_pid as u32;
        let _ = TRACKED.insert(&child, &1, 0);
    }
    Ok(0)
}

// ---- sys_enter_execve : program + argv ---------------------------------------
// Syscall tracepoint args begin at offset 16: filename@16, argv@24.
#[tracepoint]
pub fn snitchit_exec(ctx: TracePointContext) -> u32 {
    try_exec(&ctx).unwrap_or(0)
}

fn try_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !tracked(pid) {
        return Ok(0);
    }
    // Read the fallible tracepoint args BEFORE reserving — a `?` between reserve
    // and submit would leak the ring-buffer reservation (verifier: "unreleased
    // reference"). After reserve, nothing fallible runs before submit.
    // SAFETY: reading fixed tracepoint fields at documented offsets.
    let filename: *const u8 = unsafe { ctx.read_at(16)? };
    let argv: *const *const u8 = unsafe { ctx.read_at(24)? };

    let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` points at reserved, writable ring-buffer storage sized for
    // exactly `RawEvent`; we initialize every field before submit.
    //
    // argv is written into three FIXED slots (constant offsets + lengths) rather
    // than a running offset — the verifier can prove those bounds, whereas a
    // variable append offset it cannot. Layout of `data` (SLOT bytes each):
    //   [0..SLOT] program path   [SLOT..2*SLOT] argv[1]   [2*SLOT..3*SLOT] argv[2]
    // Userspace joins the non-empty slots into the command line.
    unsafe {
        (*ev).kind = KIND_EXEC;
        (*ev).pid = pid;
        (*ev).data_len = DATA_LEN as u32;
        core::ptr::write_bytes((*ev).data.as_mut_ptr(), 0, DATA_LEN);

        let d = &mut (*ev).data;
        let _ = bpf_probe_read_user_str_bytes(filename, &mut d[0..SLOT]);
        write_arg(d, argv, 1);
        write_arg(d, argv, 2);
    }
    entry.submit(0);
    Ok(0)
}

/// Fixed per-argv slot size; three slots fill `data`.
const SLOT: usize = DATA_LEN / 3;

/// Read `argv[i]` (if non-null) into slot `i` at a constant offset — bounds are
/// compile-time constant, so the verifier accepts the copy.
#[inline(always)]
fn write_arg(data: &mut [u8; DATA_LEN], argv: *const *const u8, i: usize) {
    // SAFETY: reading the argv pointer array and the pointed-at user string;
    // both go through bounded probe-read helpers.
    unsafe {
        let Ok(p) = bpf_probe_read_user(argv.add(i)) else {
            return;
        };
        let p: *const u8 = p;
        if p.is_null() {
            return;
        }
        let dst = match i {
            1 => &mut data[SLOT..2 * SLOT],
            _ => &mut data[2 * SLOT..3 * SLOT],
        };
        let _ = bpf_probe_read_user_str_bytes(p, dst);
    }
}

// ---- sys_enter_connect : outbound destination --------------------------------
// Syscall tracepoint args begin at offset 16: fd@16, uservaddr@24, addrlen@32.
#[tracepoint]
pub fn snitchit_connect(ctx: TracePointContext) -> u32 {
    try_connect(&ctx).unwrap_or(0)
}

/// Self-identification sentinel: snitchit connects here once, right after
/// attach, so the kernel learns snitchit's *root-namespace* pid (which we can't
/// obtain from inside a pid namespace like WSL2). AF_INET 127.1.2.3 : 48879.
const SENTINEL_ADDR: [u8; 4] = [127, 1, 2, 3];
const SENTINEL_PORT: u16 = 48879;

fn try_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // All fallible reads BEFORE reserve (see try_exec).
    // SAFETY: fixed tracepoint field + bounded user copy of the sockaddr.
    let uservaddr: *const u8 = unsafe { ctx.read_at(24)? };
    let raw: [u8; 28] = match unsafe { bpf_probe_read_user(uservaddr.cast::<[u8; 28]>()) } {
        Ok(r) => r,
        Err(_) => return Ok(0),
    };

    // Sentinel? Seed this pid as the tree root and don't record it. Checked
    // before the tracked gate, since snitchit isn't tracked yet.
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    if family == 2 && port == SENTINEL_PORT && raw[4..8] == SENTINEL_ADDR {
        let _ = TRACKED.insert(&pid, &1, 0);
        return Ok(0);
    }

    if !tracked(pid) {
        return Ok(0);
    }

    let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    // SAFETY: reserved ring-buffer storage sized for `RawEvent`; fully init'd,
    // no fallible op between reserve and submit.
    unsafe {
        (*ev).kind = KIND_CONNECT;
        (*ev).pid = pid;
        (*ev).data_len = 28;
        core::ptr::write_bytes((*ev).data.as_mut_ptr(), 0, DATA_LEN);
        let dst = &mut (*ev).data;
        let mut i = 0usize;
        while i < 28 {
            dst[i] = raw[i];
            i += 1;
        }
    }
    entry.submit(0);
    Ok(0)
}

// TODO(ebpf-file): file open/read/write is a deliberate non-goal for this tier.
// Intended approach when added: a `sys_enter_openat` tracepoint gated by the same
// tracked-pid set, reading the `filename` argument (offset 24) into the fixed
// data buffer exactly like exec's program path, mapped to Event::Read /
// Event::Write by inspecting the open flags (O_WRONLY/O_RDWR → write). Only the
// path (redacted + hashed) would be recorded, never file contents.

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable in a loaded BPF program; the verifier rejects real panics.
    loop {}
}
