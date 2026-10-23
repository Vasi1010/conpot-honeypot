#!/usr/bin/env python3
"""
s7_read.py  —  (optional) S7comm identification read against Conpot.

Conpot emulates a Siemens S7-200/300-style PLC speaking the S7comm protocol.
It does NOT expose real data blocks, but it DOES answer the "identification"
(SZL — System Status List) requests that tools like `get_cpu_info()` send.
So the realistic, reliable S7 probe is to connect and ask the PLC to identify
itself, which is exactly what a real recon tool (e.g. PLCScan) would do first.

Target  : Conpot S7comm service, exposed on the VM at TCP/102
Library  : python-snap7

----------------------------------------------------------------------------
HEADS-UP (Windows): python-snap7 needs the native snap7 library (snap7.dll).
If you get "can't find snap7 library" at runtime:
  - pip may ship the DLL with recent python-snap7 wheels; if not, download the
    snap7 binaries and put snap7.dll somewhere on your PATH (e.g. next to this
    script or in C:\\Windows\\System32). The SETUP_GUIDE covers this.
Because of that DLL dependency this script is marked OPTIONAL in the project.
----------------------------------------------------------------------------

Edit VM_IP below, then:  python s7_read.py
"""

# ---------------------------------------------------------------------------
# CONFIG — change this to your VM's IP address
# ---------------------------------------------------------------------------
VM_IP = "127.0.0.1"       # NAT port-forward: attack localhost on the laptop
PORT = 102                # VM host port mapped to Conpot's S7comm (container 10201)
RACK = 0                  # S7 rack number (0 is standard)
SLOT = 2                  # S7 slot number (2 is typical for S7-300; try 1 if needed)

# ---------------------------------------------------------------------------
import snap7


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def main():
    banner(f"S7comm identification probe  ->  {VM_IP}:{PORT}  (rack={RACK}, slot={SLOT})")

    client = snap7.client.Client()
    try:
        # connect(address, rack, slot, tcpport) — opens the S7 ISO-on-TCP session
        client.connect(VM_IP, RACK, SLOT, PORT)
    except Exception as exc:
        print(f"[!] Could not connect: {exc}")
        print("    Check: VM reachable, container up, port 102 mapped, try slot=1.")
        return

    if not client.get_connected():
        print("[!] Connect returned but session is not established.")
        return

    print(f"[+] S7 session established to {VM_IP}:{PORT}")

    # get_cpu_info() issues SZL identification reads — Conpot answers these with
    # its emulated Siemens module/serial/AS-name strings.
    try:
        info = client.get_cpu_info()
        print("\n[+] CPU / module identification (from the honeypot):")
        print(f"    Module type name : {info.ModuleTypeName}")
        print(f"    Serial number    : {info.SerialNumber}")
        print(f"    AS name          : {info.ASName}")
        print(f"    Module name      : {info.ModuleName}")
        print(f"    Copyright        : {info.Copyright}")
    except Exception as exc:
        print(f"[-] get_cpu_info() failed: {exc}")

    # get_cpu_state() asks whether the (emulated) CPU is RUN/STOP.
    try:
        print(f"\n[+] CPU state: {client.get_cpu_state()}")
    except Exception as exc:
        print(f"[-] get_cpu_state() failed: {exc}")

    client.disconnect()
    client.destroy()
    banner("Done. Check conpot.log on the VM for the logged S7 requests.")


if __name__ == "__main__":
    main()
