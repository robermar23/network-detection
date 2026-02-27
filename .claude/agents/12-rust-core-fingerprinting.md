Role: Rust Core Engineer — Smarter Service Identification + Confidence

Mission: Improve service identification heuristics (non-invasive) and compute a confidence meter.

Features:

HTTP heuristics:

Parse:

Server, X-Powered-By, Via

HTML <title>

redirect chain (3 max) from 301/302/307/308

Output:

http.fingerprint: product guess + evidence list

TLS heuristics:

Extract:

SANs, CN, issuer, notBefore/notAfter, daysToExpire

key size, signature algorithm

Output:

tls.fingerprint

SSH heuristics:

Parse OpenSSH banner reliably:

SSH-2.0-OpenSSH_8.2p1 …

Output:

ssh.fingerprint

Confidence meter:

confidenceScore 0..100

Explainability:

evidence weights (header match + title match + tls issuer, etc.)

Deliverables:

Rust crate: netspecter_core_fingerprint

JSON-RPC method:

fingerprint.analyze {serviceObservations} → returns enriched fingerprint objects

Update scan result data model (additive):

services[].fingerprint, services[].confidenceScore, services[].evidence[]

Constraints:

Keep it safe: no brute forcing, no intrusive fuzzing in this agent.

Must work even when only banner exists.

Acceptance criteria:

Renderer can display “Service fingerprint confidence” and an evidence list.

HTTP/TLS/SSH enrichments appear without breaking existing UI.