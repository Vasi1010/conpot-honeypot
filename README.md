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
├── logs/                  # drop the captured conpot.log here to hand off
│
├── parser/                # analysis: conpot.log -> pandas DataFrame
│   ├── patterns.py        #   line shapes (edit this if real lines don't match)
│   ├── formats.py         #   pluggable formats: TextFormat (regex), JsonFormat
│   ├── classify.py        #   function codes -> request type + scan/read/write
│   └── conpot_parser.py   #   parse_log() + CLI
├── analysis/
│   ├── detection.py       # Low/Medium/High risk per source IP
│   └── charts.py          # report/PPT charts (PNG) + CSV export
├── dashboard/
│   ├── app.py             # Streamlit live dashboard
│   └── data.py            # log -> snapshot (KPIs, risk, gateway share)
└── tests/                 # pytest suite
```

## Analysis side

```bash
py -3 -m venv .venv
.venv\Scripts\Activate.ps1          # or .venv\Scripts\activate.bat in cmd
pip install -r requirements.txt

python -m parser logs/conpot.log --csv output/parsed.csv   # summary + parsed table
python -m parser logs/conpot.log --tz UTC                  # if the VM logs in UTC
pytest
```

```python
from parser import ParseStats, parse_log
stats = ParseStats()
df = parse_log("logs/conpot.log", tz="Asia/Kolkata", stats=stats)
```

Each row is one attacker event: `timestamp, src_ip, src_port, protocol, event,
request_type, function_code, action, details, is_private, is_docker_gateway,
session_id, pattern, raw`. `action` is `scan`, `read`, `write`, `connect` or
`other` (rules in `parser/classify.py`). `is_docker_gateway` marks 172.17.0.1-style
sources, where Docker NAT hid the real attacker IP.

Input can be `conpot.log`, `docker logs [-t] conpot` output (also when saved as
UTF-16 by PowerShell) or Conpot's JSON log. Timestamps without a timezone are read
as `--tz` (default `Asia/Kolkata`). A missing or empty file gives an empty table.
Unparseable lines are skipped and counted, and lines that only partly match but
contain an IP are kept as `pattern == "fallback"` rows. The CLI lists both kinds,
so if the real log has any, adjust `parser/patterns.py`.

### Attack-sequence detection

```bash
python -m analysis.detection logs/conpot.log --csv output/risk_by_ip.csv   # --window 60
```

One row per source IP with `risk`, `sequence` (stages in first-seen order, e.g.
`scan -> read -> write`), `write_flag`, scan/read/write counts, and whether the IP hit 2+
protocols within `--window` seconds (a multi-protocol scan).

| risk   | when |
|--------|------|
| High   | any write (read -> write, scan -> read -> write; every write is flagged) |
| Medium | reads, no write (scan -> read) |
| Low    | scans only |
| Info   | traffic, but nothing classified as scan/read/write |

Scans are: port probes (connect, no request), Modbus FC 8/17/43, S7 SZL / COTP
connect, SNMP system-group OIDs, HTTP GET of `/` or `/index.html`, and multi-protocol
contact within the window.

### Charts and CSVs for the report

```bash
python -m analysis.charts logs/conpot.log --out output/
```

Writes 16:9 PNGs (200 dpi, slide-ready) and the tables to `output/` (git-ignored):

| file | shows |
|------|-------|
| `attacks_per_protocol.png` | events per protocol |
| `event_timeline.png` | events over time, stacked by stage (scan / read / write) |
| `reads_vs_writes.png` | scans vs reads vs writes per protocol, with the write-attempt count |
| `top_source_ips.png` | busiest source IPs, coloured and labelled by risk level |
| `parsed_events.csv` | the full parsed table |
| `risk_by_ip.csv` | the detection table |

### Live dashboard (for the demo)

```bash
.venv\Scripts\Activate.ps1
streamlit run dashboard/app.py          # opens http://localhost:8501
```

- **Log source:** the sidebar takes a file path (default `logs/conpot.log`, or set the
  `CONPOT_LOG` environment variable) or an uploaded file.
- **Live view:** it re-reads the file every few seconds (adjustable, or pause it), so
  copying a fresh `conpot.log` into `logs/` updates the page within seconds. For a live
  feed from the VM, keep overwriting that file, e.g. `docker logs conpot > logs/conpot.log`.
- **What it shows:** KPI cards (total events, unique IPs, write attempts, High-risk IPs),
  the four report charts, the risk-per-IP table, and the latest events.
- **Warnings:** a red alert lists the IPs that attempted writes. A yellow warning appears
  when more than half the traffic comes from a Docker gateway IP (`172.17.0.1`), which
  means Docker NAT is hiding the real attackers; run Conpot with `--network host`.
- **Bad input:** a missing, empty or garbled log shows a waiting/empty state instead of
  crashing.

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
