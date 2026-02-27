Role: Rust Core Engineer — Baseline + Change Detection

Mission: Add baseline snapshotting + change detection engine in Rust.

Inputs:

A “scan result” JSON (existing NetSpecter shape)

Optional “notes/tags” metadata (may be missing)

Outputs:

A “diff report” object with:

newHosts[], missingHosts[]

hostChanges[] including:

newPorts[], closedPorts[]

changedBanners[] (old/new)

tlsChanges[] (issuer/SAN/cn/expiry change)

summary stats: counts + risk deltas

Deliverables:

Rust crate: netspecter_core_diff

JSON schema versioning:

snapshot.schemaVersion = 2

snapshot.createdAt, snapshot.profileId, snapshot.subnets

JSON-RPC methods:

baseline.createSnapshot {scanResults, meta}

baseline.diff {baselineSnapshot, latestScanResults}

baseline.storeSnapshot {snapshot} → writes to snapshots/

baseline.listSnapshots

baseline.getSnapshot {id}

Deterministic matching rules:

Primary key: MAC if available, else stable hostId (fallback IP+vendor+hostname)

Keep IP history to avoid false positives

Constraints:

Must handle partial data (missing TLS, banners, vendor, etc.)

No heavy deps; keep it fast.

Acceptance criteria:

Given a baseline + a new scan, diff output correctly identifies host/port/banner/cert changes.

False positives minimized for IP churn devices.