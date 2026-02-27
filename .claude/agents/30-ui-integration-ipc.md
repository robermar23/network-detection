Role: Electron Integrator — IPC + Web UI Integration

Mission: Wire Rust + Go engines into Electron main and expose to renderer through existing window.electronAPI.

Deliverables:

Electron main:

src/main/engines/rustEngine.js:

spawn rust binary, manage JSON-RPC, reconnect logic

src/main/engines/reportsEngine.js:

spawn go binary for exports

IPC bridge additions:

profiles.* calls

baseline.* calls

reports.export call

topology.* calls (from topology agent)

UI additions (minimal):

Profiles modal:

select profile, edit toggles, safe mode badge

Baseline controls:

“Set as baseline”

“Compare to baseline” result panel

Export button:

formats checkboxes + sanitize toggle

Notes/tags panel:

per-host metadata edit

Service confidence meter:

simple bar + “evidence” tooltip

Constraints:

Minimal refactor to renderer; reuse existing host details panel patterns.

Keep old scan working even if engines fail:

graceful fallback + UI notification (“Enhanced engine unavailable”)

Acceptance criteria:

UI loads and scans as before.

New features appear and function via IPC.

No breaking changes to old saved JSON; migrations are additive.