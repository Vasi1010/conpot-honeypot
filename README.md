# Conpot ICS/PLC Honeypot — Project

An ICS/SCADA honeypot built on [Conpot](https://github.com/mushorg/conpot), run in
Docker inside an Ubuntu VM (VirtualBox) and probed from a Windows laptop over the
LAN. This repository holds **the attacker side** of a two-person university project:

- **This half (attacker + deployment):** get Conpot running, probe it over Modbus,
  SNMP and S7comm, and produce a clean `conpot.log`.
- **Teammate's half:** log analysis + dashboard.

> ⚠️ **Scope / ethics.** Everything here targets *our own* honeypot VM on a private
> LAN, for a university assignment. Conpot is purpose-built to be probed. Do not point
> these scripts at any host you do not own or have written permission to test.

## Layout

```
conpot-honeypot/
├── attacker/              # probe scripts run from the Windows laptop
│   ├── modbus_probe.py    # Modbus reads + a write attempt (pymodbus 3.6.9, slave=1)
│   ├── snmp_query.py      # SNMP GET/WALK (pysnmp, with snmpwalk fallback in comments)
│   ├── s7_read.py         # optional S7comm identification read (python-snap7)
│   └── requirements.txt
├── docs/
│   └── SETUP_GUIDE.md     # numbered, copy-paste setup guide (for the viva)
└── logs/                  # drop the captured conpot.log here to hand off
```

## Port map (VM)

| Service | Conpot container port | VM (host) port |
|---------|-----------------------|----------------|
| HTTP    | 8800                  | 80             |
| S7comm  | 10201                 | 102            |
| Modbus  | 5020                  | 502            |
| SNMP    | 16100/udp             | 161/udp        |

## Quick start (attacker side)

```bash
cd attacker
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# edit VM_IP at the top of each script, then:
python modbus_probe.py
python snmp_query.py
python s7_read.py        # optional
```

See `docs/SETUP_GUIDE.md` for the full, numbered walkthrough.
