"""
Packet-engine selection.

``create_engine`` picks the right platform backend and returns something that
satisfies the :class:`engines.base.PacketEngine` contract:

    Windows            -> WinDivert (pydivert)
    Linux / OpenWRT    -> raw AF_PACKET sniff + AF_INET raw injection (stdlib only)
    macOS / *BSD / else -> scapy (if installed)

Backend modules are imported lazily so that, e.g., importing this package on
Linux never tries to import the Windows-only ``pydivert``.
"""

import os
import platform


def detect_backend() -> str:
    system = platform.system()
    if system == "Windows" or os.name == "nt":
        return "windivert"
    if system == "Linux":
        return "raw"
    # Darwin, FreeBSD, OpenBSD, NetBSD, SunOS, ...
    return "scapy"


def create_engine(local_ip: str, dst_ip: str, dst_port: int, backend: str = None,
                  bind_interface: bool = False, fwmark: int = 0):
    """Build a packet engine for the flow local_ip -> dst_ip:dst_port.

    ``backend`` may be forced to "windivert" / "raw" / "scapy"; otherwise it is
    auto-detected from the host platform. ``bind_interface`` and ``fwmark`` are
    Linux concepts honoured by the raw engine only.
    """
    backend = backend or detect_backend()

    if backend == "windivert":
        from engines import windivert_engine
        return windivert_engine.create(local_ip, dst_ip, dst_port)
    if backend == "raw":
        from engines.raw_socket_engine import RawSocketEngine
        return RawSocketEngine(local_ip, dst_ip, dst_port,
                               bind_interface=bind_interface, fwmark=fwmark)
    if backend == "scapy":
        from engines.scapy_engine import ScapyEngine
        return ScapyEngine(local_ip, dst_ip, dst_port)
    raise ValueError(f"unknown packet engine backend: {backend!r}")
