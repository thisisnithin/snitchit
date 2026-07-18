# CLAUDE.md — coding standards

How to write code in this repo. These are rules, not suggestions. Follow them on
every change. When a rule and a request conflict, follow the rule and say so.

## Baseline

- Rust 2021, current stable toolchain (pinned via `rust-toolchain.toml`).
- Every change must leave the tree:
  - `cargo fmt --all -- --check` clean
  - `cargo clippy --all-targets --all-features -- -D warnings` clean
  - `cargo test --all` green
  - `cargo build --release` working on macOS and Linux
- Do not disable, `#[allow]`, or work around a lint to make code pass. Fix the
  code. The only pre-authorized exception is `unsafe_code` in FFI/kernel modules
  (see below), and even that is scoped, never workspace-wide.

## Error handling

- Libraries (`core`, `collectors`): return `Result` with explicit error enums via
  `thiserror`. No `unwrap()`, `expect()`, `panic!()`, `todo!()`, `unimplemented!()`,
  `unreachable!()` on any reachable path. These are lint-denied — respect them,
  don't route around them.
- Binary (`cli`): `anyhow` for propagation; add `.context("…")` at boundaries so
  failures are legible.
- Never swallow errors silently. Either handle them or propagate them. A logged
  degradation is fine; a silent one is not.
- Prefer `?` over match-and-rethrow. Prefer returning errors over booleans that
  encode failure.

## Panics and robustness

- No panics in production paths. Indexing that can go out of bounds, `.unwrap()`
  on `Option`/`Result`, integer casts that can truncate — handle them explicitly.
- Validate at the boundary (parsing, FFI, external input); once inside, types
  should make invalid states unrepresentable rather than re-checking everywhere.
- Tests may use `unwrap`/`expect` freely.

## Types and API design

- Make illegal states unrepresentable: prefer enums over stringly-typed values,
  newtypes over bare `String`/`u64` where a value has meaning (ids, hashes, pids).
- Derive `Debug` on all types. Derive `Clone`/`PartialEq`/`Eq` where it aids use.
  Derive serde on wire/record types.
- Keep public API surface small. Expose the minimum; keep helpers private. Public
  items in library crates get `///` doc comments; modules get `//!` headers.
- Constructors that enforce invariants > public fields. If a value must be built a
  certain way, funnel it through one constructor and don't offer a bypass.
- Accept borrowed types in function args (`&str`, `&[T]`) where you don't need
  ownership.

## Idioms

- Prefer iterators and combinators over manual index loops when it's clearer.
- Prefer borrowing; **clone freely when the borrow checker fights you** — a cloned
  hash string or small struct is not a performance problem. Do not contort a
  design to avoid a cheap clone. Optimize only where profiling shows a hot path.
- `impl Trait` in arg position for simple generic bounds; named generics when the
  bound is reused or complex.
- No premature abstraction. Do not add a trait/generic/layer for a single
  implementation or a hypothetical future one. Add the seam when the second real
  case arrives. (Compile-time platform selection via `#[cfg]` is not a reason to
  invent a runtime trait.)
- No premature optimization, and no unsafe for performance without a measured
  reason and sign-off.

## Modules and structure

- One concept per file. No `mod.rs` mega-files; keep modules small and focused.
- Dependency arrows point one way (toward the core/shared crate). A lower layer
  never imports an upper one.
- Platform-specific code is isolated behind `#[cfg(target_os = "…")]` at the
  lowest possible layer, so shared code contains zero `if macos / else linux`.
- Duplication: share genuinely-identical pure logic via a small helper function.
  Do NOT share by inventing an abstraction over things that only look similar.

## unsafe / FFI

- `unsafe_code` is `forbid` workspace-wide. Do not remove that.
- Where FFI/kernel APIs make `unsafe` unavoidable, scope `#[allow(unsafe_code)]`
  to the single smallest module, confine `unsafe` behind a safe public interface,
  keep each `unsafe` block minimal, and put a `// SAFETY:` comment on every one
  explaining why it's sound. Report where any `unsafe` was added.

## Concurrency

- Prefer the simplest model that works: threads + channels over async unless async
  clearly pays off. Don't pull in a runtime for something a thread does fine.
- No shared mutable state without a clear ownership/locking story. Prefer message
  passing and ownership transfer over `Arc<Mutex<…>>` sprinkled around.
- Anything spawned must have a defined shutdown; no orphaned threads/tasks.

## Testing

- Unit tests colocated (`#[cfg(test)] mod tests`) with the logic they cover.
- Integration tests in `tests/` for end-to-end behavior.
- Test the failure and tamper paths, not just the happy path. When you fix a bug,
  add the test that would have caught it.
- Tests must be deterministic — no reliance on wall-clock timing, network, or
  ordering of a HashMap. No flaky tests.
- Don't assert on exact error message strings; assert on error variants/types.

## Comments and docs

- Comment *why*, not *what*. The code says what; comments explain intent,
  tradeoffs, and non-obvious constraints.
- No commented-out code left behind. No dead code (`cargo clippy` will flag it —
  delete it, don't `#[allow]` it).
- Keep doc comments accurate when you change behavior. A stale doc is a bug.

## Change discipline

- Make the smallest change that solves the problem. Don't refactor unrelated code
  in the same change unless asked.
- Match the surrounding style and existing patterns before introducing a new one.
  Reuse existing constructors/helpers rather than adding parallel ones.
- If a change would alter a public type, a serialized/on-disk format, or a shared
  contract, prefer the option that preserves compatibility; if you can't, flag it
  explicitly rather than breaking it silently.
- Keep commits coherent: one logical change per commit, message says what and why.

## Working style

- Make judgment calls and keep moving; don't stop to ask on routine decisions.
- Never fake a green result. If you can't run or verify something in this
  environment, say so plainly and give the exact commands + expected output for
  the human to run.
- At the end of a task, summarize: what changed, decisions/tradeoffs, any `unsafe`
  added, and anything left unverified with steps to verify it.
