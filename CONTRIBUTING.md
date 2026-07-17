# Contributing

Thank you for helping improve `custos-enrich`.

## Development

Use Rust 1.85 or newer, then run:

```console
cargo fmt --all -- --check
cargo test --all-targets --all-features --locked
cargo test --no-default-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
```

Tests must use local fixtures or mock servers. Do not make the test suite depend
on live FIRST or CISA availability. When changing a provider model, verify the
official schema or documentation and add the smallest fixture that demonstrates
the contract.

Keep provider evidence separate from ranking policy. New network behavior
should preserve caller ownership of runtime, retry, cache, and scheduling
decisions.
