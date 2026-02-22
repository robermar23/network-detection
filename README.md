# Network Host Detection & Forensic Scanner

A modern, cross-platform desktop application built with Electron, Node.js, and Vanilla JS that provides deep network visibility, OS fingerprinting, and forensic-level port scanning functionalities.

![App Dashboard Preview](https://via.placeholder.com/800x450.png?text=Network+Detection+Dashboard)

## Features

- **Blazing Fast Subnet Sweeping**: Utilizes heavily concurrent asynchronous ICMP Ping sweeps followed by localized ARP table inspection to instantly discover all physical devices on your local network.
- **Advanced Hardware Identification**: Actively intercepts discovered MAC Addresses and resolves them via a local memory cache backed by a rate-limited, dynamic lookup to the live `macvendors.com` API to provide highly accurate Manufacturer readings (e.g., *Raspberry Pi Foundation*, *Sony Interactive Entertainment*, *Apple, Inc.*).
- **Heuristic OS Fingerprinting**: Intelligently guesses the underlying Operating System (Windows, macOS, Linux, iOS, Android) by analyzing the hardware vendor combined with unique port signatures (e.g., `445` + `135` vs `22` + `548`).
- **Forensic Deep Scans**: Click on any discovered host to trigger a visually engaging, cancellable Deep Scan. The backend chunks a raw socket sweep across all **65,535 TCP ports** to bypass operating system networking limits.
- **Live Banner & Certificate Grabbing**: As the Deep Scan iterates, it automatically executes basic `GET / HTTP/1.0` and TLS Handshakes on open sockets to extract server software versions (e.g., `nginx`, `OpenSSH_8.2p1`), TLS Certificate Issuers, and Expiration Dates.
- **Native Forensic Auditing**: Triggers active vulnerability probes (such as Anonymous FTP login attempts and `/.env` or `/.git/config` web fuzzing) against discovered services. Automatically calculates a surface-level Security Posture Score (🛡️ Protected, ⚠️ Warning, 🛑 Vulnerable) for every host on the subnet.
- **Actionable Connect Bridges**: The UI intelligently parses discovered services and injects native workflow buttons. Instantly launch your OS's native SSH Terminal, RDP Client, or Default Web Browser directly against the target host with a single click.
- **Offline Session Persistence**: Export your entire network scan state—including all deep scan vulnerabilities, banners, and TLS traits—to a local JSON file (`scan_results.json`) and instantly load it back into the dashboard at a later date.

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
git clone https://github.com/robermar23/NetworkDetection.git
cd NetworkDetection
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
