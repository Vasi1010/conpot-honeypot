"""
Data side of the dashboard, kept free of Streamlit so it can be tested.

load() turns a log path (or uploaded bytes) into a Snapshot: the parsed
events, the per-IP risk table, parse stats, KPI numbers and the share of
traffic that came from a Docker gateway IP. It never raises on a missing,
empty or garbled log.
"""

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from analysis.detection import DEFAULT_WINDOW_S, detect
from parser import DEFAULT_TZ, ParseStats, parse_bytes, parse_log

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = "logs/conpot.log"
# Warn when more than this share of events comes from a Docker gateway IP.
GATEWAY_WARN_SHARE = 0.5


@dataclass
class Snapshot:
    df: pd.DataFrame
    risk: pd.DataFrame
    stats: ParseStats
    source: str
    kpis: dict
    gateway_share: float
    gateway_ips: list

    @property
    def gateway_warning(self):
        return self.gateway_share > GATEWAY_WARN_SHARE


def resolve(path):
    """Relative paths are tried from the current folder, then from the repo root."""
    p = Path(path).expanduser()
    if p.is_absolute() or p.exists():
        return p
    return ROOT / p


def load(path=None, data=None, name=None, tz=DEFAULT_TZ, window_s=DEFAULT_WINDOW_S):
    """Parse `data` (uploaded bytes) if given, else the file at `path`."""
    stats = ParseStats()
    if data is not None:
        df = parse_bytes(data, tz, stats)
        source = name or "uploaded file"
    else:
        p = resolve(path or DEFAULT_LOG)
        df = parse_log(p, tz, stats)
        source = str(p)
    risk = detect(df, window_s)
    gw = df[df["is_docker_gateway"]]
    return Snapshot(
        df=df, risk=risk, stats=stats, source=source, kpis=kpis(df, risk),
        gateway_share=len(gw) / len(df) if len(df) else 0.0,
        gateway_ips=sorted(gw["src_ip"].unique()),
    )


def kpis(df, risk):
    return {
        "Total events": len(df),
        "Unique source IPs": int(df["src_ip"].nunique()),
        "Write attempts": int((df["action"] == "write").sum()),
        "High-risk IPs": int((risk["risk"] == "High").sum()) if len(risk) else 0,
    }


def file_signature(path):
    """(mtime, size) of the resolved log, or None if missing; used as a cache key."""
    try:
        st = resolve(path).stat()
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size
