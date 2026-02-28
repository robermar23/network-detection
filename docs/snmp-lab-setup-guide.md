# NetSpecter: SNMP Home Lab Setup Guide

To fully utilize NetSpecter's **SNMP Walking & MIB Parsing** feature, you need target devices that have an SNMP agent enabled. In a production enterprise network, most managed switches and routers have this enabled by default. However, for local testing and home labs, you may need to configure it manually.

Follow these quick setup guides to enable SNMP on various platforms for testing.

---

## 1. Fast Track: Docker Container (Recommended)

The fastest way to test SNMP is to spin up a Docker container running `snmpd`.

```bash
# Run a lightweight SNMP daemon on port 161
docker run -d --name snmp-test -p 161:161/udp polinux/snmpd

# Verify it's running using NetSpecter!
# Target IP: 127.0.0.1
# Community: public
```

---

## 2. Linux (Ubuntu / Debian / Raspberry Pi OS)

Installing the standard `snmpd` daemon gives very detailed system, interface, and routing MIB information.

**1. Install the package:**
```bash
sudo apt update
sudo apt install snmpd snmp
```

**2. Configure `snmpd.conf`:**
Edit `/etc/snmp/snmpd.conf`:
```bash
sudo nano /etc/snmp/snmpd.conf
```
Find the `agentaddress` line and make sure it listens on your local network (or all interfaces):
```text
agentaddress  udp:161,udp6:[::1]:161
```
Configure a read-only community (e.g. `public`):
```text
rocommunity public default -V systemonly
```
*(Optionally, remove `-V systemonly` to allow walking all MIBs, creating a richer NetSpecter dashboard).*

**3. Restart the service:**
```bash
sudo systemctl restart snmpd
sudo systemctl enable snmpd
```

---

## 3. Windows (SNMP Service)

Windows includes a native SNMP service, though it is designated as an optional "Feature on Demand".

**1. Install the SNMP Service:**
- Open **Settings** > **Apps** > **Optional features**.
- Click **Add a feature**.
- Search for **SNMP**, select **Simple Network Management Protocol (SNMP)**, and click Install.

**2. Configure the Community String:**
- Press `Win + R`, type `services.msc`, and press Enter.
- Find the **SNMP Service**, right-click it, and choose **Properties**.
- Go to the **Security** tab.
- Click **Add...** under *Accepted community names*.
- Set Rights to `READ ONLY` and Community Name to `public`. Click Add.
- Check *Accept SNMP packets from any host* (or specify your NetSpecter machine's IP).
- Click OK and **Restart** the SNMP Service.

---

## 4. Advanced: Testing SNMPv3 (Linux)

If you want to test NetSpecter's secure SNMPv3 integration, you need to create a v3 user with Authentication (Auth) and Privacy (Priv) passwords.

Assuming `snmpd` is installed (as per Step 2):

1. Stop the daemon safely:
   ```bash
   sudo systemctl stop snmpd
   ```
2. Create the v3 user (`netspecter_user`) with SHA authentication (`authpass123`) and AES encryption (`privpass123`):
   ```bash
   sudo net-snmp-config --create-snmpv3-user -ro -a authpass123 -A SHA -x privpass123 -X AES netspecter_user
   ```
3. Start the daemon:
   ```bash
   sudo systemctl start snmpd
   ```

In **NetSpecter**:
- Target IP: `<your_linux_ip>`
- Version: `v3`
- Security Name: `netspecter_user`
- Auth Protocol: `SHA` | Auth Key: `authpass123`
- Priv Protocol: `AES` | Priv Key: `privpass123`

---

## 5. Network Hardware (Cisco / EdgeOS)

If you have a managed switch or router in your home lab, SNMP can usually be enabled via CLI.

**Cisco IOS:**
```text
enable
configure terminal
snmp-server community public RO
end
write memory
```

**Ubiquiti EdgeOS / VyOS:**
```text
configure
set service snmp community public authorization ro
commit
save
```
