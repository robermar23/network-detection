Role: Network Feature Engineer — Topology Mapping

Mission: Add a topology model and a simple graph view:

gateway node

hosts grouped by vendor/OS

“likely switch” nodes if discovered (best-effort)

show edges based on hints

Hints sources (best-effort, safe):

ARP table relationships

Default gateway detection per interface

Reverse DNS / mDNS names

DHCP info if available (optional; don’t require admin)

Deliverables:

Data model:

topology.nodes[] (host/gateway/switch)

topology.edges[] with evidence[]

Builder logic:

implemented in Rust or Node (pick whichever fits current code better)

expose via IPC:

topology.build {scanResults}

UI graph:

Renderer page “Topology”

Use a lightweight library or vanilla canvas/SVG

Filtering: by vendor/OS, by risk badge

Constraints:

Never claim certainty: label edges as “likely”

Must run without tshark installed

Acceptance criteria:

Topology view renders a stable graph from a scan.

Clicking a node opens existing Host Details panel.