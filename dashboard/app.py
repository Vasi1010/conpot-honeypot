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

from analysis import charts  # noqa: E402
from analysis.detection import DEFAULT_WINDOW_S  # noqa: E402
from dashboard.data import DEFAULT_LOG, file_signature, load  # noqa: E402
from parser import DEFAULT_TZ  # noqa: E402

st.set_page_config(page_title="Conpot honeypot dashboard", page_icon="🛡️", layout="wide")

# Risk → colours, shared by the posture banner and the risk table.
RISK_STYLE = {
    "High": ("#fdecea", "#b21f14"),
    "Medium": ("#fff5e6", "#8a5a00"),
    "Low": ("#e8f6ee", "#157a4e"),
    "Info": ("#eef2f6", "#5a6a7a"),
}


def inject_css():
    st.markdown(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
          html, body, [class*="css"] { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
          .block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1320px; }
          #MainMenu, footer, .stDeployButton { visibility: hidden; }

          /* header band */
          .hp-head { display:flex; align-items:center; gap:14px; padding:18px 22px; border-radius:14px;
            background: linear-gradient(100deg,#0e2a33 0%, #12313c 55%, #0e1f27 100%); color:#eaf5f8;
            box-shadow: 0 6px 22px rgba(11,34,42,.18); margin-bottom:18px; }
          .hp-head .dot { width:12px; height:12px; border-radius:50%; background:#49d39a;
            box-shadow:0 0 0 4px rgba(73,211,154,.25); flex:none; }
          .hp-head h1 { font-size:1.45rem; font-weight:700; margin:0; letter-spacing:-.01em; color:#fff; }
          .hp-head .sub { font-family:'IBM Plex Mono',monospace; font-size:.72rem; letter-spacing:.12em;
            text-transform:uppercase; color:#8fc6d4; margin-top:2px; }
          .hp-head .spacer { flex:1; }
          .hp-head .meta { font-family:'IBM Plex Mono',monospace; font-size:.72rem; color:#9fd0dc; text-align:right; }

          /* posture banner */
          .hp-posture { border-radius:14px; padding:16px 20px; margin-bottom:12px; display:flex; align-items:center;
            gap:16px; border:1px solid rgba(0,0,0,.06); }
          .hp-posture .lvl { font-family:'IBM Plex Mono',monospace; font-weight:600; font-size:1.7rem;
            letter-spacing:.02em; line-height:1; }
          .hp-posture .txt { font-size:.9rem; }
          .hp-posture .txt b { font-weight:600; }

          /* metric tiles */
          div[data-testid="stMetric"] { background:#fff; border:1px solid #e2e8ee; border-radius:12px;
            padding:14px 16px; box-shadow:0 1px 2px rgba(16,28,42,.05); }
          div[data-testid="stMetricLabel"] p { font-family:'IBM Plex Mono',monospace; font-size:.7rem;
            letter-spacing:.08em; text-transform:uppercase; color:#5a6a7a; }
          div[data-testid="stMetricValue"] { font-weight:700; }

          /* section headings */
          h2, h3 { letter-spacing:-.01em; }
          .stDataFrame { border-radius:10px; overflow:hidden; }
          hr { margin:1.1rem 0; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header():
    st.markdown(
        '<div class="hp-head"><span class="dot"></span>'
        '<div><h1>Conpot ICS Honeypot</h1>'
        '<div class="sub">Live threat monitor · Modbus · S7comm · SNMP · HTTP</div></div>'
        '<span class="spacer"></span>'
        '<div class="meta">Siemens SIMATIC S7-200<br>per-IP attack-sequence risk</div></div>',
        unsafe_allow_html=True,
    )


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
    mode = st.radio("Source", ["File path", "Upload"], horizontal=True, label_visibility="collapsed")
    if mode == "File path":
        path = st.text_input("Log file path", value=os.environ.get("CONPOT_LOG", DEFAULT_LOG), key="path",
                             help="conpot.log, `docker logs conpot` output, or a JSON log")
        upload = None
    else:
        path = None
        upload = st.file_uploader("Upload a log file", type=None, key="upload")

    st.header("Refresh")
    live = st.toggle("Auto-refresh", value=True, key="live")
    interval = st.slider("Every (seconds)", 2, 60, 5, key="interval", disabled=not live)

    st.header("Detection")
    window_s = st.number_input("Multi-protocol scan window (s)", 1, 3600, int(DEFAULT_WINDOW_S), key="window")
    tz = st.text_input("Log timezone", value=DEFAULT_TZ, key="tz",
                       help="Timezone of the timestamps in the log (IANA name, e.g. UTC)")


inject_css()
render_header()


def get_snapshot():
    try:
        if upload is not None:
            return load_upload(upload.getvalue(), upload.name, tz, window_s)
        if path is not None:
            return load_path(path, file_signature(path), tz, window_s)
    except Exception as exc:  # e.g. an unknown timezone typed in the sidebar
        st.error(f"Could not load the log: {exc}")
    return None


def show_posture(snap):
    """A single at-a-glance threat level derived from the worst per-IP risk."""
    counts = snap.risk["risk"].value_counts().to_dict() if len(snap.risk) else {}
    if counts.get("High"):
        level, blurb = "High", f"{counts['High']} source IP(s) attempted a write or multi-protocol attack."
    elif counts.get("Medium"):
        level, blurb = "Medium", f"{counts['Medium']} source IP(s) read process data after scanning."
    elif counts.get("Low"):
        level, blurb = "Low", f"{counts['Low']} source IP(s) scanned but did not read or write."
    else:
        level, blurb = "Info", "Traffic seen, but nothing classified as scan, read or write yet."
    bg, fg = RISK_STYLE[level]
    st.markdown(
        f'<div class="hp-posture" style="background:{bg};border-color:{fg}33">'
        f'<span class="lvl" style="color:{fg}">{level.upper()}</span>'
        f'<span class="txt"><b style="color:{fg}">Threat level</b><br>{blurb}</span></div>',
        unsafe_allow_html=True,
    )


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
    order = ["src_ip", "risk", "sequence", "write_flag", "scans", "reads", "writes",
             "multi_protocol_scan", "protocols", "events", "first_seen", "last_seen",
             "is_private", "is_docker_gateway"]

    def colour_risk(column):
        return [f"background-color:{RISK_STYLE.get(v, RISK_STYLE['Info'])[0]};"
                f"color:{RISK_STYLE.get(v, RISK_STYLE['Info'])[1]};font-weight:600" for v in column]

    styler = table.style.apply(colour_risk, subset=["risk"])
    st.dataframe(
        styler, hide_index=True, width="stretch", column_order=order,
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
    if snap.stats.file_missing:
        st.warning(f"Waiting for the log file: `{snap.source}`. "
                   "The dashboard will pick it up automatically once it exists.")
        return

    if snap.df.empty:
        show_kpis(snap)
        st.info("No attacker events in the log yet. Waiting for traffic.")
        show_parse_stats(snap)
        return

    show_posture(snap)
    show_kpis(snap)

    if snap.gateway_warning:
        st.warning(
            f"**{snap.gateway_share:.0%} of events come from a Docker gateway IP** "
            f"({', '.join(snap.gateway_ips)}). Docker NAT is hiding the real attacker addresses, so "
            "per-IP results lump everyone together. Run the Conpot container with `--network host` "
            "so it sees real source IPs.", icon="⚠️")
    writers = snap.risk.loc[snap.risk["write_flag"], "src_ip"].tolist()
    if writers:
        st.error(f"**Write attempts** (High risk) from: {', '.join(writers)}", icon="🚨")

    st.divider()
    left, right = st.columns(2)
    show_chart(left, charts.attacks_per_protocol(snap.df))
    show_chart(right, charts.actions_by_protocol(snap.df))
    left, right = st.columns(2)
    show_chart(left, charts.event_timeline(snap.df))
    show_chart(right, charts.top_source_ips(snap.df, snap.risk))

    st.divider()
    show_risk_table(snap.risk)
    with st.expander("Latest events"):
        latest = snap.df.drop(columns=["raw", "session_id", "pattern"]).tail(50).iloc[::-1]
        st.dataframe(latest, hide_index=True, width="stretch")
    show_parse_stats(snap)


dashboard()
