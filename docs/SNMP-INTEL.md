# SNMP Intelligence Gathering Strategy

## 1. Goal
To passively and actively collect rich network intelligence during SNMP walks, converting raw OID/Value pairs into actionable application state. This transforms the SNMP walk from a simple "data dump" into an automated discovery and fingerprinting engine.

## 2. Core Concepts & OIDs
During an SNMP Walk (`session.walk` in `snmpWalker.js`), the application will inspect the incoming OIDs in real-time before emitting the standard UI render events. If an OID matches a known "intelligence target", it will emit a specialized event to the frontend.

### Primary Intelligence Targets:
1.  **System Description (`1.3.6.1.2.1.1.1.0`)**
    *   **Value:** String containing detailed OS and hardware information (e.g., `Linux ubuntu 5.15.0-76-generic...`).
    *   **Action:** Overwrite the host's guessed OS/Vendor with this 100% accurate ground-truth data.
2.  **System Name (`1.3.6.1.2.1.1.5.0`)**
    *   **Value:** String representing the configured hostname.
    *   **Action:** Update the host's Hostname field in the UI.
3.  **ARP Cache / ipNetToMediaPhysAddress (`1.3.6.1.2.1.4.22.1.2.x`)**
    *   **OID Structure:** `1.3.6.1.2.1.4.22.1.2.<ifIndex>.<ip.ad.dr.ess>`
    *   **Value:** Hex string representing the MAC address.
    *   **Action:** Parse the IP from the OID and the MAC from the value. If this IP does not exist in the current `state.hosts` list, **automatically create and render a new host card**, attributing its discovery source to `snmp-arp`.
4.  **Running Processes (`1.3.6.1.2.1.25.4.2.1.2.x`)**
    *   **Value:** String representing a running software process (e.g., `sshd`, `httpd`).
    *   **Action:** Append to a list of known processes for the host.
5.  **Routing Table (`1.3.6.1.2.1.4.21.1.1.x`)**
    *   **Value:** IP address of a routed destination subnet.
    *   **Action:** Log discovered adjacent subnets to allow the user to easily pivot their scans to new network segments.

## 3. Component Modifications Architecture

### 1. `src/main/snmpWalker.js` (The Collector)
Inside the `session.walk` callback loop, implement a routing mechanism:
```javascript
const oidString = Array.isArray(varbind.oid) ? varbind.oid.join('.') : varbind.oid;

// 1. Check for SysDescr
if (oidString === '1.3.6.1.2.1.1.1.0') {
    onIntelligence({ type: 'os', targetIp, value: val });
}
// 2. Check for SysName
else if (oidString === '1.3.6.1.2.1.1.5.0') {
    onIntelligence({ type: 'hostname', targetIp, value: val });
}
// 3. Check for ARP Cache Entries
else if (oidString.startsWith('1.3.6.1.2.1.4.22.1.2.')) {
    const parts = oidString.split('.');
    // Extract last 4 octets as IP
    const discoveredIp = parts.slice(-4).join('.');
    onIntelligence({ type: 'arp-discovery', targetIp, discoveredIp, discoveredMac: val });
}
```

### 2. `src/main/snmpIpc.js` (The Bridge)
Update the `start-snmp-walk` handler. Pass a new `onIntelligence` callback into the `snmpWalk` function. When triggered, use `event.sender.send('snmp-intel', intelData)`.

### 3. `src/main/preload.js` & `src/main/preload.cjs` (The API)
Expose the new listener to the renderer process:
```javascript
onSnmpIntel: (callback) => ipcRenderer.on(IPC_CHANNELS.SNMP_INTEL, (e, data) => callback(data))
```

### 4. `src/renderer/index.js` (The Consumer)
Register `window.electronAPI.onSnmpIntel`. Handle the payloads based on their `type`:
*   **`os` / `hostname`**: Find the host in `state.hosts` matching `targetIp`. Update `host.os` or `host.hostname`. Call the `updateSecurityBadgeDOM` or specific text element replacers to update the UI softly without a full re-render.
*   **`arp-discovery`**: Check if `discoveredIp` exists in `state.hosts` (or matches blacklists). If it doesn't, create a new host object:
    ```javascript
    state.hosts.push({
      ip: discoveredIp,
      mac: discoveredMac,
      status: 'online',
      hostname: 'Unknown',
      vendor: 'Unknown',
      source: 'snmp-arp'
    });
    debouncedRenderAllHosts();
    ```

## 4. Implementation Phasing

**Phase 1: Basic Enrichment (OS & Hostname)**
*   Implement parsing for `sysDescr` and `sysName`.
*   Wire the IPC correctly.
*   Verify the Host Details UI updates its labels live when an SNMP walk parses the root tree.

**Phase 2: The ARP Auto-Discovery Engine**
*   Implement parsing for `ipNetToMediaPhysAddress`.
*   Add the logic in `index.js` to construct and push new host cards to the grid.
*   Apply the `source-badge` logic (already existing in `index.js`) to label these new cards with an `snmp` badge so the user knows where they came from.

**Phase 3: Advanced Intelligence (Processes, Connections, Routing)**
*   Implement process parsing.
*   Update the Host Details panel HTML to include a new "Running Processes" or "Routing" collapsible section to display this denser data without cluttering the main grid.
