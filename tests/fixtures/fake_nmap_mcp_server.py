"""Fake nmap MCP server (stdio) for integration tests.

Imitates the gc-nmap-mcp server's ``do-nmap`` tool without requiring
nmap to be installed. Launch as:

    python fake_nmap_mcp_server.py            # default: one host with Modbus + S7
    python fake_nmap_mcp_server.py empty      # no hosts up
    python fake_nmap_mcp_server.py ics_heavy  # multiple ICS ports across multiple hosts
    python fake_nmap_mcp_server.py error      # do-nmap returns an error

Every call is appended to $FAKE_NMAP_CALL_LOG (if set) so tests can
assert which targets and flags were actually requested.

The output format mirrors what gc-nmap-mcp returns: a plain-text nmap
report that the agent is expected to read and interpret. The agent is
NOT expected to parse XML; it receives the same text a human would see.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.mcpserver import MCPServer  # noqa: E402


# ---------------------------------------------------------------------------
# Canned nmap output strings
# ---------------------------------------------------------------------------

_ICS_HOST_OUTPUT = """\
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-15 12:00 UTC
Nmap scan report for 192.168.95.10
Host is up (0.0012s latency).

PORT      STATE SERVICE         VERSION
22/tcp    open  ssh             OpenSSH 8.9p1 Ubuntu
80/tcp    open  http            Apache httpd 2.4.52
102/tcp   open  iso-tsap        Siemens S7 PLC
502/tcp   open  mbap            Modbus TCP
4840/tcp  open  opcua           OPC UA
44818/tcp open  EtherNet/IP-2

Nmap done: 1 IP address (1 host up) scanned in 4.21 seconds
"""

_ICS_MULTI_HOST_OUTPUT = """\
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-15 12:00 UTC
Nmap scan report for 192.168.95.10
Host is up (0.0010s latency).

PORT      STATE SERVICE    VERSION
502/tcp   open  mbap       Modbus TCP
102/tcp   open  iso-tsap   Siemens S7 PLC

Nmap scan report for 192.168.95.20
Host is up (0.0015s latency).

PORT      STATE SERVICE    VERSION
44818/tcp open  EtherNet/IP-2
20000/tcp open  dnp        DNP3

Nmap scan report for 192.168.95.200
Host is up (0.0008s latency).

PORT   STATE SERVICE  VERSION
22/tcp open  ssh      OpenSSH 8.9p1
80/tcp open  http     nginx 1.24.0

Nmap done: 3 IP addresses (3 hosts up) scanned in 7.83 seconds
"""

_EMPTY_OUTPUT = """\
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-15 12:00 UTC
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 0 IP addresses (0 hosts up) scanned in 3.01 seconds
"""

_ERROR_OUTPUT = """\
QUITTING!
Error: Failed to open device eth0
"""

_MODBUS_NSE_OUTPUT = """\
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-15 12:01 UTC
Nmap scan report for 192.168.95.10
Host is up (0.0011s latency).

PORT     STATE SERVICE VERSION
502/tcp  open  mbap    Modbus TCP
| modbus-discover:
|   Unit ID 1
|   Slave ID data: \\xFF\\xFF\\xFF\\xFF
|   Slave ID data (hex): FFFFFFFFFFFFFF

Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds
"""

_S7_NSE_OUTPUT = """\
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-15 12:01 UTC
Nmap scan report for 192.168.95.10
Host is up (0.0009s latency).

PORT     STATE SERVICE  VERSION
102/tcp  open  iso-tsap Siemens S7 PLC
| s7-info:
|   Module: 6ES7 315-2AH14-0AB0
|   Basic Hardware: 6ES7 315-2AH14-0AB0
|   Basic Firmware: V3.2.2
|_  Module Type: CPU 315-2 PN/DP

Nmap done: 1 IP address (1 host up) scanned in 1.92 seconds
"""

# Map: (scenario, target_key) -> canned output
_SCENARIO_MAP: dict[str, dict[str, str]] = {
    "default": {
        "192.168.95.0/24": _ICS_HOST_OUTPUT,
        "192.168.95.10": _ICS_HOST_OUTPUT,
        # NSE follow-up scans
        "modbus": _MODBUS_NSE_OUTPUT,
        "s7": _S7_NSE_OUTPUT,
    },
    "empty": {
        "*": _EMPTY_OUTPUT,
    },
    "ics_heavy": {
        "*": _ICS_MULTI_HOST_OUTPUT,
    },
    "error": {
        "*": _ERROR_OUTPUT,
    },
}


def _get_output(scenario: str, target: str, arguments: str) -> str:
    responses = _SCENARIO_MAP.get(scenario, _SCENARIO_MAP["default"])
    # exact match first
    if target in responses:
        return responses[target]
    # check if arguments hint at a specific NSE script
    if "modbus" in (arguments or ""):
        return responses.get("modbus", responses.get("*", _EMPTY_OUTPUT))
    if "s7" in (arguments or ""):
        return responses.get("s7", responses.get("*", _EMPTY_OUTPUT))
    # wildcard fallback
    return responses.get("*", _EMPTY_OUTPUT)


def _log(tool: str, args: dict) -> None:
    path = os.environ.get("FAKE_NMAP_CALL_LOG")
    if path:
        with open(path, "a") as fh:
            fh.write(json.dumps({"tool": tool, "args": args}) + "\n")


def build_nmap_server(scenario: str = "default") -> MCPServer:
    server = MCPServer("fake-nmap")

    @server.tool(name="do-nmap")
    def do_nmap(target: str, arguments: str = "") -> str:
        """Run nmap against the given target with optional flag string."""
        _log("do-nmap", {"target": target, "arguments": arguments})
        output = _get_output(scenario, target, arguments)
        return output

    return server


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "default"
    build_nmap_server(scenario).run("stdio")
