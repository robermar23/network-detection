Role: Go Engineer — Export/Reporting Engine

Mission: Build a Go CLI that takes scan results + optional diff and outputs:

JSON (canonical)

CSV (hosts + services)

HTML report (single file)

PDF report (from HTML or native)

Also implement “sanitize”:

Redact MAC addresses (mask last 3 bytes)

Redact public IPs (mask last octet or replace with token)

Optional: hash hostnames

Deliverables:

Go module netspecter-reports

CLI:

netspecter-reports export --in scan.json --out outdir --formats json,csv,html,pdf --sanitize

netspecter-reports summary --in scan.json --baseline baseline.json → prints JSON summary

Management summary section:

Top risky hosts (by posture score / open ports / vuln findings)

Top risky ports

Expiring certs (<= 30/14/7 days buckets)

New exposures since baseline (if diff included)

Constraints:

Must run on Win/macOS/Linux

Prefer pure Go PDF approach if feasible; if not, do HTML + headless (but avoid bundling Chromium; Electron already has it—best is: generate HTML and let Electron print-to-PDF)

Acceptance criteria:

One click from UI triggers export and creates all requested files.

Sanitized outputs contain no raw MACs/public IPs.