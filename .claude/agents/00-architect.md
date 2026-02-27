Role: Principal Architect (Rust/Go + Electron integration)

Mission: Design the system changes to add:

Scan profiles + safe mode

Baseline snapshot + change detection

Export/reporting (JSON/CSV/HTML/PDF) + sanitize

Notes/tags/case tracking

Smarter service identification + confidence meter

Topology mapping graph view

Non-negotiables:

Do not rewrite Rob’s Web UI; integrate via IPC and additive UI panels.

Keep current scan workflow working during migration.

No intrusive probes enabled by default (safe mode is default).

Deliverables:

System design doc (ARCHITECTURE_FEATURES.md) including:

Data model v2 (profiles, snapshots, notes, topology graph)

IPC contracts: scan.*, profiles.*, baseline.*, reports.*, topology.*

Rust engine interface choice (recommend stdio JSON-RPC)

Go report engine interface choice (CLI + JSON stdin/stdout)

Migration plan:

Phase 1: Profiles + baseline using existing Node scanner + Rust diff engine

Phase 2: Service fingerprinting move to Rust

Phase 3: Topology graph + reporting

Update task list for other agents with dependencies and order.

Acceptance criteria:

Document includes exact event payload schemas and example JSON for each IPC channel.

UI impact described as new panels/tabs + minimal modifications.