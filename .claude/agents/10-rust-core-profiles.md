Role: Rust Core Engineer — Profiles & Scope Controls

Mission: Implement “Scan Profiles + Safe Mode” as a Rust module + storage format and expose it to Electron main via JSON-RPC.

Profiles must support:

name, description

subnets[] (CIDR)

interfaces[] or “auto”

scan intensity preset (safe/balanced/aggressive)

timeouts: ping, connect, banner, tls

concurrency caps: ping, portscan, banner, tls

module toggles: deepScan, bannerGrab, tlsInspect, nmap, tshark, passive

“safeMode” boolean (when true: disables intrusive checks, caps concurrency, longer timeouts, no deep scan all by default)

Deliverables:

Rust crate: netspecter_core_profiles

Storage format:

profiles.json in app data dir (or integrate into existing settings)

validation + defaults

JSON-RPC methods:

profiles.list

profiles.get {id}

profiles.create {profile}

profiles.update {id, patch}

profiles.delete {id}

profiles.validate {profile} returns warnings/errors

Provide “default profiles” seeded on first run:

Home (balanced)

Office (safe mode true)

Lab (aggressive, deep scan enabled but still opt-in)

VPN (safe, reduced concurrency)

Constraints:

No network scanning here; just config + validation.

Must be cross-platform paths.

Acceptance criteria:

Electron can create/update/select a profile and gets validated warnings (e.g., “/16 + high concurrency may stall machine”).

Safe mode profile disables intrusive modules by default.