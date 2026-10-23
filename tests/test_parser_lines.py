"""Parser unit tests on hand-written lines (no sample files needed)."""

import pytest

from parser import ParseStats, parse_lines, parse_log

WRITE = ("Modbus traffic from 10.0.0.9: "
         "{'request': b'0005000000060106000004d2', 'slave_id': 1, 'function_code': 6, 'response': b''}")


@pytest.mark.parametrize("line", [
    f"2026-10-21 10:23:10,829 {WRITE}",                                   # conpot.log
    f"conpot_1  | 2026-10-21 10:23:10,829 {WRITE}",                       # docker compose logs
    f"2026-10-21T04:53:10.829123456Z 2026-10-21 10:23:10,829 {WRITE}",    # docker logs -t
    f"\x1b[32m2026-10-21 10:23:10,829 {WRITE}\x1b[0m",                    # coloured output
    "2026-10-21 10:23:10,829 INFO conpot.protocols.modbus.modbus_server: " + WRITE,
    # No function_code key: decoded from the raw request bytes instead.
    "2026-10-21 10:23:10,829 Modbus traffic from 10.0.0.9: {'request': '0005000000060106000004d2'}",
])
def test_format_variations(line):
    df = parse_lines([line])
    row = df.iloc[0]
    assert (row["src_ip"], row["function_code"], row["action"]) == ("10.0.0.9", 6, "write")
    assert row["details"] == "addr=0 value=1234"
    assert str(row["timestamp"]) == "2026-10-21 10:23:10.829000+05:30"


def test_json_line():
    df = parse_lines(['{"timestamp": "2026-10-21T10:14:09.971000", "id": "s1", "src_ip": "10.0.0.9", '
                      '"src_port": 4000, "data_type": "modbus", "request": "133700000005012b0e0100", '
                      '"response": null, "event_type": null}'])
    row = df.iloc[0]
    assert (row["protocol"], row["request_type"], row["action"]) == ("modbus", "Read Device Identification", "scan")
    assert row["pattern"] == "json"


def test_timezone_handling():
    lines = ["2026-10-21 10:00:00,000 " + WRITE,           # naive -> read as --tz
             "2026-10-21T04:30:00Z " + WRITE]              # explicit UTC -> converted
    ist = parse_lines(lines)
    assert list(ist["timestamp"].astype(str)) == ["2026-10-21 10:00:00+05:30"] * 2
    utc = parse_lines(lines[:1], tz="UTC")
    assert str(utc.iloc[0]["timestamp"]) == "2026-10-21 10:00:00+00:00"


def test_ip_flags():
    df = parse_lines([f"2026-10-21 10:00:0{i},000 " + WRITE.replace("10.0.0.9", ip)
                      for i, ip in enumerate(["172.17.0.1", "172.18.0.1", "192.168.1.5", "8.8.8.8",
                                              "198.51.100.77"])])
    assert list(df["is_docker_gateway"]) == [True, True, False, False, False]
    assert list(df["is_private"]) == [True, True, True, False, False]


def test_connect_without_request_is_port_probe():
    sid = "a6a3a450-6513-470e-a69e-0d37f2a74de4"
    df = parse_lines([f"2026-10-21 10:14:05,331 New Modbus connection from 1.2.3.4:40112. ({sid})",
                      f"2026-10-21 10:14:05,541 Modbus client disconnected. ({sid})"])
    assert len(df) == 1
    assert (df.iloc[0]["action"], df.iloc[0]["src_port"]) == ("scan", 40112)


def test_bad_lines_are_skipped_and_counted():
    stats = ParseStats()
    df = parse_lines([
        "2026-10-21 09:58:02,413 Modbus server started on: ('0.0.0.0', 5020)",  # ignored
        "not a log line at all",                                                # unparseable
        '{"timestamp": "2026-10-21", "broken json',                              # unparseable
        '{"src_ip": "1.2.3.4"}',                                                 # unparseable (no ts)
        "2026-13-45 99:99:99,000 " + WRITE,                                      # unparseable (bad ts)
        "2026-10-21 11:00:00,000 BACnet whois from 10.0.0.7 something new",     # fallback row
        "",
        "2026-10-21 10:23:10,829 " + WRITE,
    ], stats=stats)
    assert len(df) == 2
    assert (stats.lines, stats.blank, stats.ignored, stats.unparseable, stats.fallback, stats.parsed) == \
           (8, 1, 1, 4, 1, 2)
    assert df.iloc[0]["protocol"] == "modbus" and df.iloc[1]["pattern"] == "fallback"


def test_missing_and_empty_files(tmp_path):
    stats = ParseStats()
    df = parse_log(tmp_path / "nope.log", stats=stats)
    assert df.empty and stats.file_missing
    assert str(df["timestamp"].dtype) == "datetime64[ns, Asia/Kolkata]"

    empty = tmp_path / "empty.log"
    empty.write_text("")
    stats = ParseStats()
    assert parse_log(empty, stats=stats).empty and not stats.file_missing


def test_utf16_file_from_powershell_redirect(tmp_path):
    log = tmp_path / "conpot.log"
    log.write_text(f"2026-10-21 10:23:10,829 {WRITE}\r\n", encoding="utf-16")
    assert parse_log(log).iloc[0]["action"] == "write"
