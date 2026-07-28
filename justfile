# Local checks that mirror what CI runs — run before pushing.

# Run everything CI checks.
check: fmt-check clippy test

# Format the codebase.
fmt:
    cargo fmt --all

# Fail if the codebase is not formatted.
fmt-check:
    cargo fmt --all -- --check

# Lint with warnings promoted to errors.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Run the test suite.
test:
    cargo test --all-features

# Build the project.
build:
    cargo build --all-features
