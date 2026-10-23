#!/usr/bin/env python3
"""
snmp_query.py  —  SNMP probe against our Conpot honeypot.

Conpot runs an SNMP agent (default community string "public", SNMP v2c) that
answers standard system OIDs with Siemens-like identity strings. This script
issues an SNMP GET for a few well-known OIDs and then a WALK of the system
subtree, so the honeypot logs the queries.

Target   : Conpot SNMP service, exposed on the VM at UDP/161
Community : public   (read-only, Conpot default)
Version   : SNMP v2c
Library   : pysnmp  (classic hlapi sync API)

----------------------------------------------------------------------------
pysnmp can be fiddly to install on Windows/newer Python. If `pip install pysnmp`
gives you import or asyncio errors at runtime, DON'T fight it — just use the
snmpwalk command-line tool instead (Net-SNMP). Equivalent commands:

    snmpget  -v2c -c public <VM_IP> 1.3.6.1.2.1.1.1.0
    snmpwalk -v2c -c public <VM_IP> 1.3.6.1.2.1.1

On Windows you can get snmpwalk from the Net-SNMP binaries; on the Ubuntu VM
it's `sudo apt install snmp`. The SETUP_GUIDE documents both paths.
----------------------------------------------------------------------------

Edit VM_IP below, then:  python snmp_query.py
"""

# ---------------------------------------------------------------------------
# CONFIG — change this to your VM's IP address
# ---------------------------------------------------------------------------
VM_IP = "127.0.0.1"       # NAT port-forward: attack localhost on the laptop
PORT = 161                # VM host port mapped to Conpot's SNMP (container 16100/udp)
COMMUNITY = "public"      # Conpot default read community
TIMEOUT = 3               # seconds
RETRIES = 1

# A few standard "system" OIDs worth asking for:
OIDS_TO_GET = {
    "1.3.6.1.2.1.1.1.0": "sysDescr   (device description)",
    "1.3.6.1.2.1.1.3.0": "sysUpTime  (uptime)",
    "1.3.6.1.2.1.1.4.0": "sysContact (contact)",
    "1.3.6.1.2.1.1.5.0": "sysName    (hostname)",
    "1.3.6.1.2.1.1.6.0": "sysLocation(location)",
}
SYSTEM_SUBTREE = "1.3.6.1.2.1.1"   # walk the whole 'system' group

# ---------------------------------------------------------------------------
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd,
)


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def snmp_get(oid):
    """Issue a single SNMP GET for one OID; return the value as a string."""
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),              # mpModel=1 => SNMP v2c
        UdpTransportTarget((VM_IP, PORT), timeout=TIMEOUT, retries=RETRIES),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        return f"ERROR: {errorIndication}"
    if errorStatus:
        return f"ERROR: {errorStatus.prettyPrint()}"
    return " = ".join(x.prettyPrint() for x in varBinds[0])


def snmp_walk(subtree):
    """Walk an OID subtree, yielding 'OID = value' strings."""
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        UdpTransportTarget((VM_IP, PORT), timeout=TIMEOUT, retries=RETRIES),
        ContextData(),
        ObjectType(ObjectIdentity(subtree)),
        lexicographicMode=False,   # stop at the end of the subtree
    ):
        if errorIndication:
            yield f"ERROR: {errorIndication}"
            return
        if errorStatus:
            yield f"ERROR: {errorStatus.prettyPrint()}"
            return
        for varBind in varBinds:
            yield " = ".join(x.prettyPrint() for x in varBind)


def main():
    banner(f"SNMP v2c probe  ->  {VM_IP}:{PORT}  (community='{COMMUNITY}')")

    print("[*] SNMP GET on well-known system OIDs:\n")
    for oid, label in OIDS_TO_GET.items():
        print(f"  {label}")
        print(f"    {snmp_get(oid)}\n")

    banner(f"SNMP WALK of system subtree {SYSTEM_SUBTREE}")
    for line in snmp_walk(SYSTEM_SUBTREE):
        print(f"  {line}")

    banner("Done. Check conpot.log on the VM for the logged SNMP requests.")


if __name__ == "__main__":
    main()
