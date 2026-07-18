//! The [`EventSource`] seam — the one contract every collector fulfills.
//!
//! The core defines the trait and the [`Event`] type; collectors depend on the
//! core to satisfy it, never the reverse (brief §4). Each collector normalizes
//! its native events into [`Event`]s *before* pushing them into an
//! [`EventSink`], so nothing platform- or collector-shaped ever reaches the
//! core. Future kernel collectors (eBPF, Endpoint Security) slot in here behind
//! the same trait without touching the core.

use crossbeam_channel::{Receiver, Sender};

use crate::error::Result;
use crate::event::Event;

/// The write end of the normalized-event stream handed to a collector.
///
/// Cloneable so multiple collectors can share one sink. Emitting is
/// intentionally infallible from the caller's view: per design principle #1
/// (observe-only), a full or closed channel must never crash or block the
/// wrapped agent — a dropped event is logged by the consumer, not propagated.
#[derive(Debug, Clone)]
pub struct EventSink {
    tx: Sender<Event>,
}

impl EventSink {
    /// Emit a normalized event. If the consumer has gone away the event is
    /// simply dropped — per design principle #1 (observe-only), emitting never
    /// fails loudly and callers never have to handle a send error.
    pub fn emit(&self, event: Event) {
        let _ = self.tx.send(event);
    }
}

/// The read end of the event stream, drained by the consumer (the store writer).
#[derive(Debug, Clone)]
pub struct EventStream {
    rx: Receiver<Event>,
}

impl EventStream {
    /// Receive the next event, blocking until one arrives or all sinks drop.
    #[must_use]
    pub fn recv(&self) -> Option<Event> {
        self.rx.recv().ok()
    }

    /// Drain all currently-available events without blocking.
    pub fn try_iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.rx.try_iter()
    }
}

/// Create a connected `(sink, stream)` pair. Unbounded so a slow consumer never
/// blocks a collector (observe-only).
#[must_use]
pub fn channel() -> (EventSink, EventStream) {
    let (tx, rx) = crossbeam_channel::unbounded();
    (EventSink { tx }, EventStream { rx })
}

/// Something that produces a stream of normalized [`Event`]s.
///
/// Implementors translate their native events into [`Event`]s and push them into
/// the sink between [`start`](EventSource::start) and [`stop`](EventSource::stop).
pub trait EventSource: Send {
    /// A short name for diagnostics (e.g. `pty`, `hook`).
    fn name(&self) -> &str;

    /// Begin producing events into `sink`. May spawn background threads; should
    /// return promptly for passive sources.
    fn start(&mut self, sink: EventSink) -> Result<()>;

    /// Stop producing events and release resources. Must be idempotent.
    fn stop(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    /// A trivial source used to exercise the seam (brief build-order step 5).
    struct TestSource {
        commands: Vec<String>,
    }

    impl EventSource for TestSource {
        fn name(&self) -> &str {
            "test"
        }

        fn start(&mut self, sink: EventSink) -> Result<()> {
            for (i, cmd) in self.commands.iter().enumerate() {
                let ev = Event::shell_command(
                    "test",
                    format!("rec-{i}"),
                    "2026-07-15T00:00:00Z".to_string(),
                    cmd,
                    "",
                    0,
                );
                sink.emit(ev);
            }
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn core_consumes_events_from_any_source() {
        let (sink, stream) = channel();
        let mut src = TestSource {
            commands: vec!["ls".into(), "pwd".into(), "whoami".into()],
        };
        src.start(sink).unwrap();
        src.stop().unwrap();
        drop(src); // drops the last sink clone so the stream ends

        let collected: Vec<Event> = std::iter::from_fn(|| stream.recv()).collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].action.tool.as_deref(), Some("shell"));
    }
}
