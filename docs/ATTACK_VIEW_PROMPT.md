# Build prompt — live attack-visualization page

This is a ready-to-use brief for building the **live "attack view"** (a visual companion to the
Streamlit dashboard, so a live attack can be watched instead of read in a terminal). Paste the
block below into a Claude Code session opened in this repo, or follow it by hand.

---

## Build a live attack-visualization page for the Conpot honeypot project

### Context
This repo (`conpot-honeypot`) is a two-part uni project:
- **Attacker half** (`attacker/`): Python probes (`attack.py` runs Modbus → SNMP → S7comm
  against the honeypot).
- **Analysis half** (`parser/`, `analysis/`, `dashboard/`): turns the honeypot's log into
  structured events, a per-IP risk score, charts, and a Streamlit dashboard.

The honeypot is **Conpot in Docker** (a fake Siemens SIMATIC S7-200 PLC) running on the same
laptop; probes hit `127.0.0.1`. The log is captured with
`docker logs conpot > logs\conpot.log`. See `docs/PROJECT_WALKTHROUGH.md` for the full setup.

### Goal
When we run a live attack during the demo, right now we just stare at terminal output. Build a
**live "attack view" page** that visualizes the attack as it happens — something an audience can
watch. It is a *companion* to the existing `dashboard/app.py` (the analytical view), not a
replacement. Keep the dashboard as-is.

### Reuse what exists — do NOT re-parse by hand
- `dashboard/data.py` → `load(path=..., tz=..., window_s=...)` returns a `Snapshot` with:
  `.df` (one row per event), `.risk` (per-IP risk table), `.kpis`, `.gateway_share`,
  `.gateway_ips`, `.stats`, `.source`.
- Event rows (`snap.df`) have columns: `timestamp, src_ip, src_port, protocol, event,
  request_type, function_code, action, details, is_private, is_docker_gateway, session_id`.
  `action` is one of `scan | read | write | connect` — this is the key field for the visual.
- `analysis.detection.detect(df)` gives the risk level and the `scan -> read -> write` sequence.
- Default log path is `logs/conpot.log`. Run everything from the **repo root** with the
  **repo-root `.venv`** (`parser`/`analysis`/`dashboard` are packages).

### What to visualize (the important part)
1. **Attack map (centerpiece).** An "Attacker" node on the left, the "Conpot PLC (Siemens
   S7-200)" node on the right, and three protocol lanes between them — **Modbus**, **SNMP**,
   **S7comm**. When a new event of a protocol arrives, pulse/animate that lane and flash the
   PLC node. Colour each pulse by `action` (scan = blue, read = amber, write = red).
2. **Live event ticker.** The newest events streaming in, most-recent first, colour-coded by
   `action`, each line showing protocol + a short human description (e.g. "Modbus write →
   holding register", "SNMP GET system identity", "S7 connect"). Cap it (~last 30).
3. **Kill-chain strip.** Three stages — **SCAN → READ → WRITE** — that light up as the source
   escalates, ending with the risk verdict from `detect()` (show a big **HIGH** when a write
   lands). This is the "story" of the attack.
4. **Live counters.** Total events, protocols touched, current threat level. Reuse `snap.kpis`
   and `detect()` — don't recompute.

### Tech — pick one, your call
- **Option A (recommended, fits the stack):** a new Streamlit page, e.g.
  `dashboard/attack_view.py`, run with `streamlit run dashboard/attack_view.py`. Use
  `@st.fragment(run_every=1)` to poll `logs/conpot.log` each second (same pattern as
  `app.py`), and render the map + ticker as inline HTML/SVG via
  `st.markdown(..., unsafe_allow_html=True)` with CSS keyframe animations triggered when new
  event IDs appear since the last run. Fastest to integrate.
- **Option B (smoothest real-time):** a tiny `FastAPI`/`Flask` server that tails
  `logs/conpot.log` and streams new events over **Server-Sent Events** to a static
  `attack_view.html` page animating on a `<canvas>`. More work; only if you want buttery motion.

Start with A; note Option B in a comment if you want to upgrade later.

### Visual style (match the project)
Dark "control-room" look: slate background, **cyan** accent (`#0e7490` / `#22d3ee`), **IBM Plex
Sans** + **IBM Plex Mono** (Google Fonts). Risk colours: High `#b21f14`, Medium `#8a5a00`,
Low `#157a4e`. This matches `dashboard/app.py` and `docs/` so the two views feel like one product.

### Constraints
- Windows / PowerShell; run from the repo root with the root `.venv`.
- Reuse `parser`/`analysis`/`dashboard.data`; don't duplicate parsing or scoring.
- **Don't break the existing 79 tests** (`python -m pytest -q`). Add a small test for any new
  pure logic you introduce (e.g. "new events since last snapshot"); UI is fine to leave untested.
- The attacker shows up as **`172.17.0.1`** (the Docker bridge gateway) — label it as such in
  the UI, don't treat it as a real external IP.
- `logs/*.log` stays gitignored.

### How to try it end to end
1. `docker start conpot`
2. `cd attacker ; .\.venv\Scripts\python.exe attack.py ; cd ..`
3. `docker logs conpot > logs\conpot.log 2>&1`  (re-run to feed the page new events)
4. `.\.venv\Scripts\python.exe -m streamlit run dashboard\attack_view.py`

Also make it work on a static capture for a no-honeypot demo:
`sample_logs/conpot_0.6.0_real.log` (set `CONPOT_LOG` or a sidebar path input).

### Acceptance criteria
- With the honeypot up and `attack.py` run, the page shows protocol lanes pulsing, events
  streaming into the ticker, and the kill-chain reaching **WRITE → HIGH**.
- Works offline against `sample_logs/` for a safe demo fallback.
- Existing dashboard and all 79 tests still pass.

### Deliverables
- The new page (`dashboard/attack_view.py` or the Option-B pair).
- A short "Attack view" section added to `docs/PROJECT_WALKTHROUGH.md` (how to run it).
- Open it as a PR (the team merges via PRs, like #1–8).
