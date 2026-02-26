# NetSpecter: Getting Started Guide

Welcome to NetSpecter! This guide will walk you through installing the application, its core features, and how to harness the advanced capabilities of the integrated Nmap orchestration engine.

## 0. Installation

### Windows
Download the `.exe` installer from the [Releases page](https://github.com/robermar23/netspectre/releases) and double-click to install.

### macOS
Download the `.dmg`, open it, and drag NetSpecter into your **Applications** folder.

### Linux
**Recommended:** Download the `.deb` package and install:
```bash
sudo dpkg -i netspectre_*.deb
sudo apt-get install -f   # resolve any missing dependencies
```

**Fedora/RHEL:** Download the `.rpm` package:
```bash
sudo dnf install ./netspectre-*.rpm
```

**AppImage (advanced):** Requires `libfuse2` (`sudo apt install libfuse2`). Run as a normal user — **do not use `sudo`**. If you must run as root, pass `--no-sandbox`:
```bash
chmod +x Netspectre-*.AppImage
./Netspectre-*.AppImage --no-sandbox
```

> **💡 Tip:** NetSpecter detects if you are running as root on Linux and automatically applies the `--no-sandbox` flag internally. For the `.deb` and `.rpm` packages, this is handled seamlessly.

### Optional: Nmap & Wireshark (Tshark)
For advanced scanning features, it is highly recommended to install [Nmap](https://nmap.org/download.html) and [Wireshark](https://www.wireshark.org/download.html) (which includes `tshark`).

**Nmap Installation:**
```bash
# Debian/Ubuntu
sudo apt install nmap

# Fedora/RHEL
sudo dnf install nmap

# macOS (Homebrew)
brew install nmap

# Windows — download from nmap.org and ensure it's in your PATH.
```

**Wireshark (Tshark) Installation:**
```bash
# Debian/Ubuntu
sudo apt install tshark

# Fedora/RHEL
sudo dnf install wireshark-cli

# macOS (Homebrew)
brew install wireshark

# Windows — download Wireshark from wireshark.org. Ensure you install Npcap and check the box to add Wireshark to the system PATH.
```

## 1. Initial Setup and Scanning

1. **Launch the Application**: Run the executable or `npm run dev` if you're developing locally. You will be greeted by the Dashboard.
2. **Review Settings ⚙️**: Click the **Settings** button in the top right. Here you can verify if NetSpecter has successfully detected your Nmap and Tshark installations in the system PATH. You can toggle these engines on or off at any time using the switches.
3. **Select an Interface**: At the top left, a dropdown menu populates with all detected physical network interfaces on your system (Wi-Fi, Ethernet). Select the network segment you want to scan.
4. **Scan Network**: Click the "Scan Network" button. NetSpecter will instantly sweep the `/24` subnet boundaries of your selected interface using lightweight asynchronous ICMP pings and fallback ARP resolution.

## 2. Navigating the Dashboard

Once the scan completes, a grid of "Host Cards" will populate containing newly discovered IPs on your network.

* **Status Indicators**: A pulsing green circle means the host replied successfully.
* **Metadata Extraction**: Your native devices often identify themselves via MAC Address. NetSpecter intercepts these MAC addresses and automatically fetches their hardware vendor registration (e.g. `Sony`, `Apple`).
* **View Modes**: At the top right, use the view toggles to seamlessly switch between **Grid Card View**, **Slim List View**, or the **Detailed Table View**.
* **Filtering and Sorting**: Use the search inputs above the hosts list to filter by IP, OS, or Vendor. Sort the discovered hosts by `IP` (default), `Vendor`, `OS`, or `Open Ports`.

## 3. Deep Sweeping and Native Discovery

If you see an interesting host, click its Host Card to open the **Details Lateral Panel**.

1. Click **Run Deep Scan**. 
2. NetSpecter will begin raw socket probing across all 65,535 TCP ports on that specific device.
3. Open ports will pop into the details pane dynamically.
4. If HTTP (80/443), SSH, or other recognizable banner services are found, the UI will attempt active payload grabs, extracting Software Versions, HTML Titles, and SSL/TLS Certificates.
5. **Action Shortcuts**: Any exposed standard services (HTTP, SSH, RDP) can be instantly triggered by clicking the native "Connect" buttons next to the respective ports in the Details pane.
6. **Deep Scan All**: You can proactively run a Deep Scan on all discovered targets by clicking the **"☢️ Deep Scan All"** button near the search filters! You can stop the bulk scan instantly via the same button.

## 4. Advanced: The Nmap Orchestration Engine

While NetSpecter's native engine is blazingly fast, network auditors might want greater depth. We have engineered a zero-modification native wrapper around **Nmap**.

### Installing Nmap
If Nmap is not installed in your system `$PATH` (or explicitly via standard defaults), a blue banner will appear instructing you to download it natively from `nmap.org`. NetSpecter natively attempts dynamic `$PATH` detection (`where nmap` / `which nmap`) to automatically discover custom installation prefixes.

### Leveraging Nmap
Once Nmap is installed, open the Details Panel for any Host. You'll see an "Engine" toggle button. Switch it to **Nmap**. 

You now have access to four hyper-advanced features:

1. **Nmap Deep Scan (All Ports)**: Aggressively checks all 65,535 ports using `-A` timing and fingerprinting options. 
2. **Nmap Standard Host Scan**: Scans the default 1000 top ports quickly using `-A` aggressive OS detection flags.
3. **Targeted Port Analysis**: Hover over any previously discovered Open Port blue tag in the UI and click it. NetSpecter spins up a targeted Nmap Service Scan (`-sV -sC`) directly against that specific listening socket to scrape exactly what process is running behind it.
4. **Nmap Vuln Scan (Scripts)**: Executes the aggressive `--script vuln` map against the host. 

## 5. Vulnerability Discovery (CVE Mapping)

When using the **Nmap Vuln Scan**, NetSpecter intercepts the raw terminal output buffer directly.

* It searches for `VULNERABILITY:` blocks. 
* It extracts the `CVE ID`, the `CVSS severity score` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and dynamically links directly to `vulners.com` or `exploit-db.com` if exploit PoCs are publicly available.
* All discovered vulnerabilities are cleanly mapped to a red "Vulnerabilities Discovered" list inside the Details panel. 
* The primary Dashboard Host Card security badge handles state propagation, flipping to a blazing red flag quantifying exactly how many Critical CVEs are bound to the specific host. If no vulnerabilities are found, it receives a glowing green `Audited Secure` badge.

## 6. Nmap Scripting Engine (NSE) Explorer

At the bottom of the Nmap actions list is the powerful **NSE Explorer Dropdown**.

When NetSpecter starts, it hunts your file system to discover your native Nmap installation footprint. It ingests all 600+ `.nse` lua scripts and categorizes them.

* Search for any script (e.g. `smb-`, `http-`) inside the input terminal.
* A dropdown will perfectly categorize them using dynamic color risk-badges (`safe` (Green), `discovery` (Blue), `intrusive/dos` (Yellow), `vuln/exploit` (Red)) so you know exactly how dangerous a payload is before sending it.
* You can append optional script arguments (e.g. `--script-args user=admin`) into the secondary box. 
* Click "Run Custom Script" and the execution outputs natively into the dashboard terminal blocks.

## 7. Interactive Ncat Sockets

Behind the Nmap Engine toggle is the localized **Ncat** Engine. This allows for raw TCP/UDP socket connectivity directly from the GUI.

1. Switch to the **Ncat** engine tab inside the Details panel.
2. Enter the target `Port`.
3. Fill out the `Payload` field (e.g. `GET / HTTP/1.0\r\n\r\n` or raw byte drops).
4. Click Connect & Send. The UI will keep the stream open to visualize bidirectional byte-drops mimicking raw native network connectivity.

## 8. VLAN Tag Discovery (Tshark)

NetSpecter natively integrates with Wireshark's CLI tool (`tshark`) to passively hunt for 802.1Q tags on your network interfaces, useful for uncovering misconfigured Trunk ports or preventing VLAN Hopping attacks.

1. Ensure Tshark is installed and enabled in the **Settings** modal.
2. Click the **🦈 VLAN Discovery** button located in the top control bar (next to the view toggles) to open the VLAN panel.
3. Choose the physical interface you want to listen on.
4. Click **Start Capture**. NetSpecter will transparently orchestrate a Wireshark capture filtered strictly to `vlan` packets.
5. As tagged frames are intercepted traversing the wire, the UI will extract the `VLAN ID` and the source/destination MAC addresses, appending them securely to the streaming dashboard widget in real-time.

## 9. Persisting Data (Saving and Loading)

Any Nmap Scans, NSE Explorations, and Native Port Banners queried in the current application state session are saved in the DOM.

* Click **Save Results** in the top control bar to serialize the exact state to `scan_results.json` locally.
* You can safely close the application, open it, and click **Load Results** to re-instantiate your layout perfectly, saving hours of rescanning downtime.
