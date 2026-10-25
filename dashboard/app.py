"""
Live Conpot honeypot dashboard.

    streamlit run dashboard/app.py

Reads the log (path or upload) and refreshes every few seconds. The default
path is logs/conpot.log, or set CONPOT_LOG to point somewhere else.
"""

import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root, for parser/analysis

import matplotlib.pyplot as plt  # noqa: E402
import streamlit as st  # noqa: E402
import streamlit.components.v1 as components  # noqa: E402

from analysis import charts  # noqa: E402
from analysis.detection import DEFAULT_WINDOW_S  # noqa: E402
from dashboard import simulator  # noqa: E402
from dashboard.data import DEFAULT_CONTAINER, DEFAULT_LOG, file_signature, load, load_docker  # noqa: E402
from parser import DEFAULT_TZ  # noqa: E402

st.set_page_config(page_title="Conpot honeypot dashboard", page_icon="🛡️", layout="wide")


@st.cache_data(show_spinner=False, max_entries=8)
def load_path(path, signature, tz, window_s):
    # `signature` (mtime, size) is only part of the cache key: a changed log re-parses.
    return load(path=path, tz=tz, window_s=window_s)


@st.cache_data(show_spinner=False, max_entries=4)
def load_upload(data, name, tz, window_s):
    return load(data=data, name=name, tz=tz, window_s=window_s)


# --------------------------------------------------------------------------- sidebar

with st.sidebar:
    st.header("Log source")
    mode = st.radio("Source", ["File path", "Upload", "Live from Docker"],
                    label_visibility="collapsed")
    path = upload = container = None
    if mode == "File path":
        path = st.text_input("Log file path", value=os.environ.get("CONPOT_LOG", DEFAULT_LOG), key="path",
                             help="conpot.log, `docker logs conpot` output, or a JSON log")
    elif mode == "Upload":
        upload = st.file_uploader("Upload a log file", type=None, key="upload")
    else:
        container = st.text_input("Container name", value=DEFAULT_CONTAINER, key="container",
                                  help="Runs `docker logs <name>` on every refresh — no manual export needed.")

    st.header("Refresh")
    live = st.toggle("Auto-refresh", value=True, key="live")
    interval = st.slider("Every (seconds)", 2, 60, 5, key="interval", disabled=not live)

    st.header("Detection")
    window_s = st.number_input("Multi-protocol scan window (s)", 1, 3600, int(DEFAULT_WINDOW_S), key="window")
    tz = st.text_input("Log timezone", value=DEFAULT_TZ, key="tz",
                       help="Timezone of the timestamps in the log (IANA name, e.g. UTC)")


st.title("Conpot ICS honeypot")
st.caption("Attacker activity across Modbus, S7comm, SNMP and HTTP, with per-IP attack-sequence risk.")


def get_snapshot():
    try:
        if upload is not None:
            return load_upload(upload.getvalue(), upload.name, tz, window_s)
        if container is not None:
            # Not cached: we want a fresh `docker logs` read on every refresh.
            return load_docker(container.strip() or DEFAULT_CONTAINER, tz, window_s)
        if path is not None:
            return load_path(path, file_signature(path), tz, window_s)
    except Exception as exc:  # e.g. an unknown timezone typed in the sidebar
        st.error(f"Could not load the log: {exc}")
    return None


def show_kpis(snap):
    prev = st.session_state.get("prev_kpis", {})
    for col, (label, value) in zip(st.columns(4), snap.kpis.items()):
        delta = value - prev[label] if label in prev and value != prev[label] else None
        col.metric(label, f"{value:,}", delta=delta, border=True)
    st.session_state["prev_kpis"] = snap.kpis


def show_chart(col, fig):
    with col:
        st.pyplot(fig, width="stretch")
    plt.close(fig)


def show_risk_table(risk):
    st.subheader("Risk per source IP")
    table = risk.copy()
    for c in ("first_seen", "last_seen"):
        table[c] = table[c].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(
        table, hide_index=True, width="stretch",
        column_order=["src_ip", "risk", "sequence", "write_flag", "scans", "reads", "writes",
                      "multi_protocol_scan", "protocols", "events", "first_seen", "last_seen",
                      "is_private", "is_docker_gateway"],
        column_config={
            "src_ip": "Source IP", "risk": "Risk", "sequence": "Sequence",
            "write_flag": st.column_config.CheckboxColumn("Write!"),
            "multi_protocol_scan": st.column_config.CheckboxColumn("Multi-proto scan"),
            "is_private": st.column_config.CheckboxColumn("Private"),
            "is_docker_gateway": st.column_config.CheckboxColumn("Docker GW"),
            "first_seen": "First seen", "last_seen": "Last seen",
        },
    )


def show_parse_stats(snap):
    s = snap.stats
    st.caption(f"Source: `{snap.source}` · {s.lines:,} lines · {s.parsed:,} events · "
               f"{s.ignored:,} ignored · {s.unparseable:,} unparseable · "
               f"refreshed {datetime.now():%H:%M:%S}")
    if s.unmatched:
        with st.expander(f"{s.fallback + s.unparseable} line(s) not fully understood"):
            st.code("\n".join(line[:300] for line in s.unmatched), language=None)


@st.fragment(run_every=interval if live else None)
def dashboard():
    snap = get_snapshot()
    if snap is None:
        if mode == "Upload":
            st.info("Upload a Conpot log to start.")
        return
    if snap.docker_error:
        st.warning(f"Live Docker source unavailable: {snap.docker_error}  "
                   "Start the honeypot container (e.g. `docker start conpot`) or switch to a "
                   "file/upload source in the sidebar.", icon="🐳")
        return
    if snap.stats.file_missing:
        st.warning(f"Waiting for the log file: `{snap.source}`. "
                   "The dashboard will pick it up automatically once it exists.")
        return

    show_kpis(snap)
    if snap.df.empty:
        st.info("No attacker events in the log yet. Waiting for traffic.")
        show_parse_stats(snap)
        return

    if snap.gateway_warning:
        st.warning(
            f"**{snap.gateway_share:.0%} of events come from a Docker gateway IP** "
            f"({', '.join(snap.gateway_ips)}). Docker NAT is hiding the real attacker addresses, so "
            "per-IP results lump everyone together. Run the Conpot container with `--network host` "
            "so it sees real source IPs.", icon="⚠️")
    writers = snap.risk.loc[snap.risk["write_flag"], "src_ip"].tolist()
    if writers:
        st.error(f"**Write attempts** (High risk) from: {', '.join(writers)}", icon="🚨")

    left, right = st.columns(2)
    show_chart(left, charts.attacks_per_protocol(snap.df))
    show_chart(right, charts.actions_by_protocol(snap.df))
    left, right = st.columns(2)
    show_chart(left, charts.event_timeline(snap.df))
    show_chart(right, charts.top_source_ips(snap.df, snap.risk))

    show_risk_table(snap.risk)
    with st.expander("Latest events"):
        latest = snap.df.drop(columns=["raw", "session_id", "pattern"]).tail(50).iloc[::-1]
        st.dataframe(latest, hide_index=True, width="stretch")
    show_parse_stats(snap)


# --------------------------------------------------------------------------- Attack Simulator tab

def show_attack_chain(chain):
    """Three pills — Scan -> Read -> Write — lit for the stages reached."""
    cols = st.columns([3, 1, 3, 1, 3])
    pills = [("scan", "🔍 Scan"), ("read", "📖 Read"), ("write", "✍️ Write")]
    for col, (stage, label) in zip((cols[0], cols[2], cols[4]), pills):
        lit = chain[stage]
        colour = simulator.COLOUR_WRITE if stage == "write" and lit else (
            simulator.COLOUR_BUSY if lit else "#3a4553")
        fg = "#0d1117" if lit else "#8b98a9"
        col.markdown(
            f"<div style='background:{colour};color:{fg};border-radius:8px;"
            f"padding:10px 4px;text-align:center;font-weight:700;font-family:monospace'>"
            f"{label}</div>", unsafe_allow_html=True)
    for arrow_col in (cols[1], cols[3]):
        arrow_col.markdown("<div style='text-align:center;font-size:22px;"
                           "padding-top:6px;color:#8b98a9'>→</div>", unsafe_allow_html=True)


def show_plc_card(state_key):
    colour, label = simulator.PLC_STATES[state_key]
    st.markdown(
        f"<div style='background:{colour};border-radius:10px;padding:16px;text-align:center;"
        f"color:#0d1117'><div style='font-size:12px;letter-spacing:2px'>PLC STATUS</div>"
        f"<div style='font-size:20px;font-weight:800;margin-top:4px'>{label}</div></div>",
        unsafe_allow_html=True)


def stream_attack(target, phase):
    """Run the attack console and stream its output into a terminal-style panel."""
    panel = st.empty()
    lines = []
    with st.spinner(f"Running **{phase}** against `{target}` ..."):
        for line in simulator.iter_attack_output(target, phase):
            lines.append(line)
            panel.code("\n".join(lines[-400:]) or " ", language=None)
    st.session_state["sim_output"] = "\n".join(lines)


def simulator_tab():
    st.subheader("Attack Simulator")
    st.caption("Drive labelled traffic at the lab honeypot and watch the attack chain light up. "
               "Targets are restricted to loopback / private-LAN addresses.")

    target = st.text_input("Attack target", value="127.0.0.1", key="sim_target",
                           help="Loopback or private-LAN only — the attack console refuses anything else.")

    cols = st.columns(len(simulator.PHASES))
    clicked = None
    for col, (label, phase) in zip(cols, simulator.PHASES.items()):
        kind = "primary" if label == "Full Attack" else "secondary"
        if col.button(label, key=f"sim_btn_{phase}", width="stretch", type=kind):
            clicked = phase
    if clicked:
        stream_attack(target.strip() or "127.0.0.1", clicked)
    elif st.session_state.get("sim_output"):
        st.code(st.session_state["sim_output"][-6000:], language=None)

    # Read the (now-updated) log and visualise the chain for one IP.
    snap = get_snapshot()
    st.divider()
    if snap is None or snap.df.empty:
        st.info("Run an attack above (with a live honeypot source) to populate the attack chain.")
        return

    ips = list(snap.risk["src_ip"])
    default = simulator.writers(snap.risk) or ips
    chosen = st.selectbox("Source IP to track", ips,
                          index=ips.index(default[0]) if default else 0, key="sim_ip")

    chain = simulator.chain_status(snap.risk, chosen)
    state = simulator.plc_state(snap.risk, chosen)
    colour = simulator.stage_colour(snap.risk, chosen)

    left, right = st.columns([2, 1])
    with left:
        st.markdown("**Attack chain**")
        show_attack_chain(chain)
        st.markdown("**Network view**")
        components.html(simulator.network_svg(colour, attacker_label=chosen), height=130)
    with right:
        show_plc_card(state)

    # Toast when a brand-new write attempt shows up since the last run.
    current = simulator.writers(snap.risk)
    fresh = simulator.new_writers(current, st.session_state.get("sim_prev_writers", []))
    for ip in fresh:
        st.toast(f"🚨 New WRITE attempt from {ip}", icon="🚨")
    st.session_state["sim_prev_writers"] = current


tab_dashboard, tab_simulator = st.tabs(["📊 Dashboard", "🎯 Attack Simulator"])
with tab_dashboard:
    dashboard()
with tab_simulator:
    simulator_tab()
