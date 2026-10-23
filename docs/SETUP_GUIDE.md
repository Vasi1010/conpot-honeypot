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
   sudo docker run -d --name conpot \
     -p 80:8800 \
     -p 102:10201 \
     -p 502:5020 \
     -p 161:16100/udp \
     honeynet/conpot
   ```
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
    > If pysnmp throws import/asyncio errors, use Net-SNMP instead:
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

24. Hand `conpot.log` to your teammate. Easiest route, since they're a repo
    collaborator — copy it into the repo and push:
    ```bash
    # copy conpot.log from the VM into C:\Users\wahee\honeypot\logs\ on the laptop
    # (shared folder, scp, or drag-and-drop), then on the laptop:
    ```
    ```powershell
    cd C:\Users\wahee\honeypot
    git add logs\conpot.log
    git commit -m "Add captured conpot.log for analysis"
    git push
    ```

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
| T7 | `pip install` fails on pysnmp | See `snmp_query.py` — fall back to the `snmpwalk` CLI; it needs no Python packages. |
| T8 | S7 script: "can't find snap7 library" | Put `snap7.dll` on PATH (next to the script or in `System32`). S7 is optional. |
| T9 | Pulled image is very old / won't start | Build from source instead: `git clone https://github.com/mushorg/conpot.git` then `cd conpot && sudo make build-docker && sudo make run-docker`. |
