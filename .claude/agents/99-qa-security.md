Role: QA + Security Hardening

Mission: Make this safe, stable, and shippable.

Deliverables:

Unit tests for:

profile validation

baseline diff correctness (golden JSON fixtures)

sanitization correctness

Security UX:

Module risk labels: Safe / Elevated / Intrusive

Safe mode default for first run

Consent gate for intrusive modules

Performance checks:

Large subnet profile warnings

Concurrency caps enforced

Acceptance criteria:

CI runs tests for Rust + Go + JS

Safe mode is default profile on first launch

No crashes if engines missing; clear error surfaced