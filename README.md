<div align="center">
  <img src="src/renderer/public/logo.png" alt="NetSpecter Logo" width="200" />
</div>

# NetSpecter: Network Host Detection & Forensic Scanner

A modern, cross-platform desktop application built with Electron, Node.js, and Vanilla JS that provides deep network visibility, OS fingerprinting, and forensic-level port scanning functionalities.

![App Dashboard Preview](https://via.placeholder.com/800x450.png?text=NetSpecter+Dashboard)

## Features

- **Blazing Fast Subnet Sweeping**: Utilizes heavily concurrent asynchronous ICMP Ping sweeps followed by localized ARP table inspection to instantly discover all physical devices on your local network.
- **Advanced Hardware Identification**: Actively intercepts discovered MAC Addresses and resolves them via a local memory cache backed by a rate-limited, dynamic lookup to the live `macvendors.com` API to provide highly accurate Manufacturer readings (e.g., *Raspberry Pi Foundation*, *Sony Interactive Entertainment*, *Apple, Inc.*).
- **Heuristic OS Fingerprinting**: Intelligently guesses the underlying Operating System (Windows, macOS, Linux, iOS, Android) by analyzing the hardware vendor combined with unique port signatures (e.g., `445` + `135` vs `22` + `548`).
- **Forensic Deep Scans**: Click on any discovered host to trigger a visually engaging, cancellable Deep Scan. The backend chunks a raw socket sweep across all **65,535 TCP ports** to bypass operating system networking limits.
- **Live Banner & Certificate Grabbing**: As the Deep Scan iterates, it automatically executes basic `GET / HTTP/1.0` and TLS Handshakes on open sockets to extract server software versions (e.g., `nginx`, `OpenSSH_8.2p1`), TLS Certificate Issuers, and Expiration Dates.
- **Native Forensic Auditing**: Triggers active vulnerability probes (such as Anonymous FTP login attempts and `/.env` or `/.git/config` web fuzzing) against discovered services. Automatically calculates a surface-level Security Posture Score (🛡️ Protected, ⚠️ Warning, 🛑 Vulnerable) for every host on the subnet.
- **Actionable Connect Bridges**: The UI intelligently parses discovered services and injects native workflow buttons. Instantly launch your OS's native SSH Terminal, RDP Client, or Default Web Browser directly against the target host with a single click.
- **Data Persistence**: Offline session persistence allows saving all network scan states, deep scan vulnerabilities, banners, and TLS traits to a local JSON file (`scan_results.json`) and instantly load it back.
- **Dashboard Filtering & Sorting**: Powerful client-side search indexing allows users to seamlessly filter discovered hosts by IP address, detected Operating System, or Hardware Vendor map. Easily sort the dashboard ascending/descending by numerical IP, Alphabetical vendor/OS, or by the mathematical total of open ports discovered to quickly bubble the most porous devices to the top of your review queue.
- **Deep Scan All**: Efficiently queue automated deep port sweeps across your entire discovered subnet via a single click. Processes iteratively execute against every discovered device asynchronously while live-streaming results directly into the UI.
- **Optional Nmap Engine Integration**: Extends native scanning functionalities by gracefully hooking into an existing system installation of [Nmap](https://nmap.org). NetSpecter acts as an independent orchestration wrapper to harness Nmap's OS fingerprinting and Vulnerability Scripting (`--script vuln`) without modifying Nmap's source code. You can target `-A` Deep Scans or singular open ports directly, streaming execution output live to the dashboard terminal.
- **CVE Discovery & Badge Injection**: NetSpecter automatically parses incoming Nmap `vuln` terminal outputs asynchronously in real-time. Matches against CVE vulnerabilities automatically map to the host's `deepAudit` cache, injecting stylized vulnerability definitions and dynamic links into the Details panel while inherently incrementing that specific server's Security Posture Badge natively on the dashboard GUI.
- **Nmap Scripting Engine (NSE) Explorer**: Contains a customized native OS file discovery module to dynamically locate and index your system's `scripts/` directory. Loads over `600+` `.nse` Lua payloads instantly into a searchable Autocomplete dropdown wrapper. Features dynamic color tags categorizing payloads by `safe`, `discovery`, `intrusive`, etc, allowing for granular `--script-args` payload executions directly against target servers with the raw TCP streams printing cleanly to the dashboard.
- **Interactive Ncat Sockets**: Embeds an active raw TCP/UDP orchestration tab backed by Netcat (`ncat`) for raw, live network exploitation and connection testing directly in the GUI.

---

## 📦 Installation

### Windows
Download the latest `.exe` (NSIS installer) or `.exe` (portable) from the [Releases](https://github.com/robermar23/netspectre/releases) page and run it. No additional setup required.

### macOS
Download the `.dmg` from the [Releases](https://github.com/robermar23/netspectre/releases) page, open it, and drag NetSpecter to your Applications folder.

### Linux (Recommended: `.deb`)
The **`.deb` package** is the recommended way to install on Debian/Ubuntu-based distributions. It automatically handles all system dependencies and provides full desktop integration (menu entry, icons, etc.)

```bash
# Download the latest .deb from Releases, then:
sudo dpkg -i netspectre_*.deb

# If there are missing dependencies, fix them with:
sudo apt-get install -f
```

To uninstall:
```bash
sudo apt remove netspectre
```

### Linux (Alternative: `.rpm`)
For Fedora, RHEL, CentOS, or openSUSE:

```bash
sudo rpm -i netspectre-*.rpm
# or on Fedora:
sudo dnf install ./netspectre-*.rpm
```

### Linux (Alternative: AppImage)
> ⚠️ **Note:** We recommend the `.deb` or `.rpm` packages for the smoothest experience. AppImage requires extra setup on modern distros.

```bash
# 1. Make it executable
chmod +x Netspectre-*.AppImage

# 2. Install FUSE2 (required on Ubuntu 22.04+)
sudo apt install libfuse2

# 3. Run (as a normal user, NOT with sudo)
./Netspectre-*.AppImage

# If you must run as root (e.g., for raw socket scanning):
./Netspectre-*.AppImage --no-sandbox
```

**Common AppImage issues:**
| Error | Solution |
|---|---|
| `dlopen(): error loading libfuse.so.2` | Install FUSE2: `sudo apt install libfuse2` |
| `running as root without --no-sandbox` | Run without `sudo`, or add `--no-sandbox` flag |
| `create mount dir error: Permission Denied` | Ensure `/tmp` is not mounted `noexec`. Try `TMPDIR=$HOME/.cache ./Netspectre-*.AppImage` |

---

## 📖 Complete Documentation
For a comprehensive breakdown of exactly how to use each feature, step-by-step UI breakdowns, and advanced Nmap exploitation techniques, please read the [Getting Started Guide](docs/getting-started-guide.md).

---

## 🚀 Developer Onboarding

This project uses a split-process architecture standard for modern Electron applications, utilizing Vite as the frontend bundler for hyper-fast hot module replacement (HMR).

### Tech Stack

- **Container**: [Electron](https://www.electronjs.org/) (Strict `contextIsolation` enabled)
- **Frontend / Bundler**: [Vite](https://vitejs.dev/) + Vanilla HTML/CSS/JS (Zero framework bloat)
- **Backend**: Node.js (`net`, `tls`, `child_process`, `os`)

### Prerequisites

Ensure you have the following installed on your machine:

- Node.js (v18 or higher recommended)
- `npm` or `yarn`
- Your OS's native ping utility (already pre-installed on Windows/macOS/Linux)

### 1. Installation

Clone the repository and install the Node dependencies.

```bash
git clone https://github.com/robermar23/NetSpecter.git
cd NetSpecter
npm install
```

### 2. Local Development

To spin up the application in a local development environment with Hot Reloading, run the concurrent dev script:

```bash
npm run dev
```

This command simultaneously boots the Vite frontend server on `localhost:5173` while compiling and launching the Electron Main process wrapper. **Note:** Edits to files located in `src/renderer/` will hot-reload instantly in the application window. Edits to the backend Node environment (`src/main/*.js` or `preload.js`) will require restarting the `npm run dev` script to take effect.

### 3. Production Build

To bundle the application into a standalone, distributable executable tailored to your current operating system, run:

```bash
npm run build
```

The compiled binaries will be output into the `dist/` and `release/` directories depending on your electron-builder configuration.

---

## Architecture Overview

The codebase is strictly separated to adhere to Electron's security model:

* **`src/main/main.js`**: The privileged Node.js backend environment. This thread executes the actual network sockets, ping commands, file system writes, and child process spawns.
* **`src/main/preload.js`**: The secure IPC (Inter-Process Communication) Bridge. This script selectively exposes specific backend functionalities to the frontend `window.electronAPI` namespace, preventing the renderer from executing arbitrary Node code.
* **`src/main/scanner.js` / `deepScanner.js`**: Reusable modules containing the core port sweeping, OS fingerprinting, and API-fetching business logic.
* **`src/renderer/*`**: The unprivileged UI presentation layer. This directory contains the raw HTML structure, glassmorphic CSS styling, and the Vanilla JS dashboard controllers that react to incoming IPC event streams.

---

## License

This project is open-sourced software licensed under the [MIT license](LICENSE).

### Third-Party Software Disclosures
- **Nmap**: This application can optionally interact with [Nmap](https://nmap.org) if the user has independently installed it on their system. NetSpecter is merely a graphical front-end that executes Nmap via standard command-line interfaces. NetSpecter does **not** distribute, incorporate, or statically link Nmap's source code, binary executables, or libraries. Nmap is a registered trademark of Insecure.Com LLC and is distributed under its own proprietary license (NPSL). NetSpecter is not affiliated with, endorsed by, or sponsored by the Nmap Project.
