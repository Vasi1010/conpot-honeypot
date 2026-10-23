# Conpot Honeypot — Full Setup & Attack Guide

A numbered, copy-paste walkthrough to stand up the Conpot ICS/PLC honeypot in
Docker (inside an Ubuntu VM on VirtualBox) and probe it from a Windows laptop.
Written so it can be reproduced from scratch for a viva. **Run every command
exactly as shown.** Commands are labelled with **where** to run them:

- 🐧 **[VM]** = type it in the Ubuntu virtual machine terminal
- 🪟 **[Laptop]** = type it in Windows PowerShell on your laptop
- 🖱️ **[VirtualBox]** = do it in the VirtualBox Manager window

Network design: the VM uses **NAT**, and VirtualBox **port-forwards** the ICS
ports to the laptop. So from the laptop you always attack **`127.0.0.1`**.

```
 [Laptop] 127.0.0.1:502  ──VirtualBox NAT port-forward──▶  [VM] :502 ──Docker -p──▶  [container] :5020  Conpot Modbus
```

---

## What to download / install (shopping list)

| Where | Software | How to get it | Needed? |
|-------|----------|---------------|---------|
| This laptop | **VirtualBox** (Windows host) | <https://www.virtualbox.org/wiki/Downloads> → "Windows hosts" | Yes — install first (Part 0). |
| This laptop | **Ubuntu 26.04 LTS ISO** | <https://ubuntu.com/download/desktop> → Intel/AMD 64-bit | Yes |
| Inside the VM | **Docker** | `sudo apt install docker.io` (Part A) | Yes |
| Inside the VM | **Conpot image** | `sudo docker pull honeynet/conpot` (Part B) | Yes |
| Windows laptop | **Python 3.x** | <https://www.python.org/downloads/> (tick "Add to PATH") | Already installed (3.13). |
| Windows laptop | **Probe deps** (pymodbus, pysnmp) | `pip install -r requirements.txt` (Part E) | Yes |
| Windows laptop | **Nmap** (optional, for verifying) | <https://nmap.org/download.html> | Optional |
| Windows laptop | **python-snap7** (optional, only for S7) | `pip install python-snap7` — native lib bundled, no DLL needed | Optional |
| Windows laptop | **Net-SNMP** (only if pysnmp fails) | <https://sourceforge.net/projects/net-snmp/files/> | Fallback only |

Nothing here needs a specific old version. The one trap we already hit and fixed:
the SNMP library **must be the modern pysnmp** (`requirements.txt` pins 7.x) —
the old pysnmp 4.4 is broken on Python 3.12+.

---

## Part 0 — Install VirtualBox + the Ubuntu VM (on this laptop)

0.1 🪟 **[Laptop]** Download VirtualBox (**Windows hosts**) from
    <https://www.virtualbox.org/wiki/Downloads> and run the installer with the
    defaults. Click **Yes** at the "Network Interfaces will reset" warning (Wi-Fi
    blips briefly) and **Install** any Oracle driver prompt.

0.2 🪟 **[Laptop]** Download the Ubuntu Desktop ISO (**Intel or AMD 64-bit**)
    from <https://ubuntu.com/download/desktop>.

0.3 🖱️ **[VirtualBox]** **New** → Name `conpot-vm`, Type **Linux**, Version
    **Ubuntu (64-bit)** → **ISO Image** = the downloaded `.iso` → RAM **4096 MB**,
    CPUs **2**, Disk **25 GB** → **Start** → **Install Ubuntu**, set a
    username/password, finish, and reboot.

0.4 🐧 **[VM]** Open **Terminal** inside Ubuntu. You are now ready for Part A.

---

## Part A — Install Docker in the VM

1. 🐧 **[VM]** Update the package list:
   ```bash
   sudo apt update
   ```

2. 🐧 **[VM]** Install Docker:
   ```bash
   sudo apt install -y docker.io
   ```

3. 🐧 **[VM]** Start Docker and set it to run on boot:
   ```bash
   sudo systemctl enable --now docker
   ```

4. 🐧 **[VM]** Confirm Docker works (prints a version number):
   ```bash
   sudo docker --version
   ```
   > We use `sudo docker` for every command in this guide so you don't have to
   > deal with user-group permissions. That's fine for a demo.

---

## Part B — Run Conpot in Docker

5. 🐧 **[VM]** Pull the pre-built Conpot image:
   ```bash
   sudo docker pull honeynet/conpot
   ```

6. 🐧 **[VM]** Start Conpot **detached**, named `conpot`, mapping the container's
   internal ports (8800/10201/5020/16100) to the VM's standard ICS ports
   (80/102/502/161):
   ```bash
   sudo docker run -d --name conpot --restart unless-stopped \
     -p 80:8800 \
     -p 102:10201 \
     -p 502:5020 \
     -p 161:16100/udp \
     honeynet/conpot
   ```
   > `--restart unless-stopped` makes Docker bring the container back up
   > automatically after a VM reboot, so you don't have to re-run it each time.
   > (Omit the flag if you'd rather start it manually with `sudo docker start conpot`.)
   | VM (host) port | Container port | Service |
   |----------------|----------------|---------|
   | 80             | 8800           | HTTP    |
   | 102            | 10201          | S7comm  |
   | 502            | 5020           | Modbus  |
   | 161/udp        | 16100/udp      | SNMP    |

7. 🐧 **[VM]** Check the container is running:
   ```bash
   sudo docker ps
   ```
   You should see a row for `conpot` with `Up ...` and the port mappings. The
   mappings must read **`0.0.0.0:80->8800/tcp`** etc. — **not** `127.0.0.1:80->`.
   If they say `127.0.0.1`, VirtualBox's forward won't reach them (see
   Troubleshooting T4).

8. 🐧 **[VM]** Watch the honeypot's live log (Ctrl-C to stop watching — this does
   NOT stop the container):
   ```bash
   sudo docker logs -f conpot
   ```

9. 🐧 **[VM]** Confirm the services are listening on all interfaces:
   ```bash
   sudo ss -tulnp | grep -E ':80|:102|:502|:161'
   ```

---

## Part C — Port-forward the VM in VirtualBox

Do this once. The VM can stay running (NAT rules apply live).

> ⚠️ **This NAT + `127.0.0.1` approach only works if the VM runs on the SAME
> computer you attack from.** If your VirtualBox VM is on a *different* machine,
> NAT port-forwarding won't reach it. Instead: VM **Settings → Network →
> Adapter 1 → Attached to: Bridged Adapter** (pick the Wi-Fi/Ethernet NIC),
> start the VM, run `hostname -I` to get its LAN IP (e.g. `192.168.10.x`), and
> set `VM_IP` in the scripts to that address. Skip the rest of Part C.

10. 🖱️ **[VirtualBox]** Manager → select the VM → **Settings → Network →
    Adapter 1** (leave **Attached to: NAT**) → expand **Advanced** →
    **Port Forwarding**.

11. 🖱️ **[VirtualBox]** Click **+** and add these four rules. Leave **Host IP**
    and **Guest IP** blank:

    | Name   | Protocol | Host Port | Guest Port |
    |--------|----------|-----------|------------|
    | modbus | TCP      | 502       | 502        |
    | s7     | TCP      | 102       | 102        |
    | snmp   | **UDP**  | 161       | 161        |
    | http   | TCP      | **8080**  | 80         |

    > ⚠️ `snmp` MUST be **UDP**. The `http` rule uses host **8080** because host
    > port 80 was already in use on this laptop; adjust if yours differs.

12. 🖱️ **[VirtualBox]** Click **OK** on both dialogs.

---

## Part D — Verify from the laptop (Nmap + browser)

13. 🪟 **[Laptop]** Confirm the forwarded TCP ports answer:
    ```powershell
    foreach ($p in 502,102,8080) { Test-NetConnection 127.0.0.1 -Port $p | Select-Object RemotePort, TcpTestSucceeded }
    ```
    `TcpTestSucceeded : True` means the tunnel laptop→VM→container works.

14. 🪟 **[Laptop]** Open the honeypot's fake device web page in a browser:
    ```
    http://127.0.0.1:8080
    ```
    You should see Conpot's emulated ICS device page (Siemens-style).

15. 🪟 **[Laptop]** *(Optional)* Nmap scan with ICS scripts. Install Nmap from
    <https://nmap.org/download.html> first, then:
    ```powershell
    nmap -sV -p 502,102,80 127.0.0.1
    nmap -sU -p 161 --script snmp-info 127.0.0.1
    nmap -p 502 --script modbus-discover 127.0.0.1
    nmap -p 102 --script s7-info 127.0.0.1
    ```

---

## Part E — Install the attacker scripts (laptop)

16. 🪟 **[Laptop]** Go to the project's attacker folder:
    ```powershell
    cd C:\Users\wahee\honeypot\attacker
    ```

17. 🪟 **[Laptop]** Create and activate a Python virtual environment:
    ```powershell
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    ```
    > If PowerShell blocks the activation script, run once:
    > `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` then try again.

18. 🪟 **[Laptop]** Install the dependencies:
    ```powershell
    pip install -r requirements.txt
    ```

---

## Part F — Run the probes

The scripts already target `127.0.0.1` (the NAT-forwarded ports). Keep the VM's
`sudo docker logs -f conpot` window visible so you can watch requests land.

19. 🪟 **[Laptop]** Modbus — reads (coils/inputs/registers) + a write attempt:
    ```powershell
    python modbus_probe.py
    ```

20. 🪟 **[Laptop]** SNMP — GET on system OIDs + a WALK (community `public`):
    ```powershell
    python snmp_query.py
    ```
    > Uses the modern pysnmp (async) — already verified to load on Python 3.13.
    > If it ever misbehaves, the no-Python fallback is Net-SNMP:
    > `snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.2.1.1`

21. 🪟 **[Laptop]** *(Optional)* S7comm identification read:
    ```powershell
    python s7_read.py
    ```
    > Needs `snap7.dll` on PATH (see the note in `s7_read.py`). Skip if it won't
    > load — Modbus + SNMP are enough to demonstrate the honeypot.

---

## Part G — Produce the clean `conpot.log` and hand it off

22. 🐧 **[VM]** After running the probes, dump the honeypot's full log to a file:
    ```bash
    sudo docker logs conpot > conpot.log 2>&1
    ```

23. 🐧 **[VM]** (Have a quick look — it should contain the Modbus/SNMP/S7
    requests you just sent):
    ```bash
    tail -n 40 conpot.log
    ```

24. Hand `conpot.log` to your teammate **privately** (shared folder, scp, chat
    attachment); they drop it into `logs\` in their checkout. **Don't commit
    it**: the log contains the honeypot's public IP ("Fetched <ip> as external
    ip"), and `.gitignore` excludes `logs/*.log` for that reason. If a real
    excerpt is useful for tests, anonymize it (replace public IPs with
    documentation addresses like `203.0.113.10`) and put it in `sample_logs/`.

---

## Managing the container

- Stop:    🐧 `sudo docker stop conpot`
- Start:   🐧 `sudo docker start conpot`
- Restart (fresh log): 🐧 `sudo docker restart conpot`
- Remove:  🐧 `sudo docker rm -f conpot`  (then re-run step 6 to recreate)

---

## Troubleshooting

| # | Symptom | Likely cause & fix |
|---|---------|--------------------|
| T1 | `Test-NetConnection` = False / scripts time out | Port-forward rule missing or wrong protocol. Re-check Part C; SNMP must be **UDP**. |
| T2 | Browser `127.0.0.1:8080` won't load | `http` forward not added, or host 8080 also busy — change the host port in the rule and in the URL. |
| T3 | `docker ps` shows nothing | Container exited. Run `sudo docker logs conpot` to see why, or `sudo docker start conpot`. |
| T4 | Ports show `127.0.0.1:80->8800` in `docker ps` | Docker published to loopback only. Re-run step 6 exactly (the `-p 80:8800` form publishes on `0.0.0.0`). |
| T5 | `docker: permission denied` | You dropped the `sudo`. Use `sudo docker ...`. |
| T6 | SNMP returns nothing | Wrong community or template. Confirm `public`; try `snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.2.1.1`. |
| T7 | SNMP errors / `No module named 'imp'` | You have the OLD pysnmp 4.4 (dead on Python 3.12+). Fix: `pip uninstall -y pysnmp && pip install "pysnmp==7.1.30"`. Last resort: the `snmpwalk` CLI. |
| T8 | S7 script import error (e.g. `No module named 'pkg_resources'`) | You have the old python-snap7 1.x. Fix: `pip install "python-snap7==3.3.0"` (modern wheel bundles the native lib; no DLL). S7 is optional. |
| T9 | Pulled image is very old / won't start | Build from source instead: `git clone https://github.com/mushorg/conpot.git` then `cd conpot && sudo make build-docker && sudo make run-docker`. |
