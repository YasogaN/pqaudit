# Contributing to pqaudit

Thank you for your interest in contributing. This document covers how to report issues,
propose changes, and submit pull requests. Please read it before opening an issue or
sending code.

---

## Code of Conduct

All contributors are expected to follow the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
Be respectful and constructive in all interactions.

---

## AI Disclosure Policy

This project was initially developed with AI assistance and welcomes contributions that also
use AI tools. However, contributors who use AI assistance are fully responsible for the code
they submit. This means:

- You have read and understand the code you are submitting.
- You have verified that it is correct, does not introduce regressions, and passes all tests.
- You are not submitting AI-generated code you have not reviewed.

If your contribution was meaningfully AI-assisted, you may note it in the pull request
description — this is appreciated for transparency but is not required.

---

## Reporting Issues

Before opening an issue:

1. Search existing issues to avoid duplicates.
2. If you have found a security vulnerability, do **not** open a public issue. See the
   security section below.

When filing a bug report, include:

- The pqaudit version (`pqaudit --version`)
- The operating system and architecture
- The exact command you ran
- The full output, including any error messages
- Expected versus actual behavior

---

## Security Vulnerabilities

Do not disclose security vulnerabilities in public issues. Report them privately by emailing
the maintainers directly or using GitHub's private vulnerability reporting feature if
enabled. Include a description of the issue, reproduction steps, and potential impact.
You will receive a response within 72 hours.

---

## Proposing Changes

For non-trivial changes, open an issue to discuss the proposal before writing code. This
avoids wasted effort if the change does not align with the project's direction.

For small fixes (typos, documentation, obvious bugs), you may open a pull request directly.

---

## Development Setup

### Prerequisites

- Rust 1.85 or later (install via [rustup](https://rustup.rs))
- A working internet connection for live integration tests (optional; most tests use fixtures)

### Build

```sh
cargo build
```

### Run tests

```sh
# Unit and fixture-based integration tests (no network required)
cargo test

# Live integration tests (requires network access to public hosts)
cargo test --features live-tests
```

### Check formatting and lints

```sh
cargo fmt --check
cargo clippy -- -D warnings
```

All of the above must pass before a pull request will be accepted. The CI pipeline runs
these checks automatically.

---

## Pull Request Guidelines

1. **Branch from `main`.** Keep your branch up to date before opening the PR.
2. **One concern per PR.** A pull request should address a single bug, feature, or
   refactor. Mixed-purpose PRs are harder to review and will be asked to be split.
3. **Write tests.** Bug fixes must include a regression test. New features must include
   tests that cover the new behavior.
4. **Keep commits clean.** Each commit should be a coherent unit of work with a clear
   message. Squash fixup commits before requesting review.
5. **Update documentation.** If your change affects CLI flags, output formats, scoring
   behavior, or the MCP interface, update the relevant documentation.
6. **Do not bump the version.** Version bumps are handled by maintainers during release.

### Commit message format

Use the conventional commits style:

```
<type>(<scope>): <short description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`

Examples:

```
feat(probe): add TLS 1.2 record layer cipher enumeration
fix(scoring): apply timeline multiplier for certs expiring after 2030
docs: add STARTTLS usage examples to README
```

---

## Code Style

- Run `cargo fmt` before committing. The project uses the default rustfmt configuration.
- Resolve all `cargo clippy` warnings. Do not use `#[allow(...)]` to silence warnings
  without a documented reason.
- Prefer explicit error types over `unwrap()` or `expect()` in library code. The `probe`
  and `audit` modules must not panic on unexpected input.
- Keep modules focused. The separation between probe, audit, and output layers is
  intentional; do not mix concerns across those boundaries.

---

## Licensing

By submitting a pull request, you agree that your contribution is licensed under the
Apache License, Version 2.0, consistent with the rest of the project. You confirm that
you have the right to submit the code under these terms.
