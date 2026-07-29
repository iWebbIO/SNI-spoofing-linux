"""
Pure-Python IPv4 / TCP packet parsing and building.

This module exists so the cross-platform (Linux / *BSD / macOS) packet engines can
hand the *exact same* object interface to the connection state-machine that
``pydivert`` gives us on Windows.  Only the small subset of fields the state
machine in ``fake_tcp.py`` actually touches is implemented:

    packet.is_inbound / packet.is_outbound
    packet.ip.src_addr / packet.ip.dst_addr        (dotted-quad strings)
    packet.ip.packet_len                           (get / set)
    packet.ipv4.ident                              (get / set)
    packet.tcp.src_port / packet.tcp.dst_port
    packet.tcp.syn / ack / rst / fin / psh         (get / set booleans)
    packet.tcp.seq_num / packet.tcp.ack_num        (get / set)
    packet.tcp.payload                             (get / set bytes)

Intentionally dependency-free (stdlib ``socket`` + ``struct`` only) so it runs
on minimal targets such as OpenWRT where scapy / netfilterqueue are unavailable.

IPv6 is not handled here; the desync technique is applied to the IPv4 flow to the
configured CONNECT_IP.  A packet that is not IPv4/TCP simply never reaches this
code because the engines filter it out first.
"""

import socket
import struct

_TCP_PROTO = 6


def _checksum(data: bytes) -> int:
    """Standard Internet 16-bit one's-complement checksum (RFC 1071)."""
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class _IPView:
    """Facade exposing the ``packet.ip.*`` attributes used by the state machine."""

    def __init__(self, pkt: "IPv4TCPPacket"):
        self._pkt = pkt

    @property
    def src_addr(self) -> str:
        return socket.inet_ntoa(self._pkt._src_ip)

    @src_addr.setter
    def src_addr(self, value: str):
        self._pkt._src_ip = socket.inet_aton(value)

    @property
    def dst_addr(self) -> str:
        return socket.inet_ntoa(self._pkt._dst_ip)

    @dst_addr.setter
    def dst_addr(self, value: str):
        self._pkt._dst_ip = socket.inet_aton(value)

    @property
    def packet_len(self) -> int:
        # Derived from live content so callers always read a truthful value,
        # regardless of any (harmless) manual assignment they made.
        return self._pkt._ihl + 20 + len(self._pkt.tcp_options) + len(self._pkt._payload)

    @packet_len.setter
    def packet_len(self, value):  # accepted for API-compat; length is recomputed on build
        pass


class _IPv4View:
    """Facade exposing ``packet.ipv4.ident`` (and truthiness) used by the state machine."""

    def __init__(self, pkt: "IPv4TCPPacket"):
        self._pkt = pkt

    def __bool__(self):
        return True

    @property
    def ident(self) -> int:
        return self._pkt._ident

    @ident.setter
    def ident(self, value: int):
        self._pkt._ident = value & 0xFFFF


class _TCPView:
    """Facade exposing the ``packet.tcp.*`` attributes used by the state machine."""

    def __init__(self, pkt: "IPv4TCPPacket"):
        self._pkt = pkt

    @property
    def src_port(self) -> int:
        return self._pkt._src_port

    @src_port.setter
    def src_port(self, value: int):
        self._pkt._src_port = value & 0xFFFF

    @property
    def dst_port(self) -> int:
        return self._pkt._dst_port

    @dst_port.setter
    def dst_port(self, value: int):
        self._pkt._dst_port = value & 0xFFFF

    @property
    def seq_num(self) -> int:
        return self._pkt._seq

    @seq_num.setter
    def seq_num(self, value: int):
        self._pkt._seq = value & 0xFFFFFFFF

    @property
    def ack_num(self) -> int:
        return self._pkt._ack

    @ack_num.setter
    def ack_num(self, value: int):
        self._pkt._ack = value & 0xFFFFFFFF

    @property
    def payload(self) -> bytes:
        return self._pkt._payload

    @payload.setter
    def payload(self, value: bytes):
        self._pkt._payload = bytes(value)

    def _flag(self, bit: int) -> bool:
        return bool(self._pkt._flags & bit)

    def _set_flag(self, bit: int, on: bool):
        if on:
            self._pkt._flags |= bit
        else:
            self._pkt._flags &= ~bit

    # Individual flag bits (per RFC 793 low byte of the flags field).
    @property
    def fin(self):
        return self._flag(0x01)

    @fin.setter
    def fin(self, v):
        self._set_flag(0x01, v)

    @property
    def syn(self):
        return self._flag(0x02)

    @syn.setter
    def syn(self, v):
        self._set_flag(0x02, v)

    @property
    def rst(self):
        return self._flag(0x04)

    @rst.setter
    def rst(self, v):
        self._set_flag(0x04, v)

    @property
    def psh(self):
        return self._flag(0x08)

    @psh.setter
    def psh(self, v):
        self._set_flag(0x08, v)

    @property
    def ack(self):
        return self._flag(0x10)

    @ack.setter
    def ack(self, v):
        self._set_flag(0x10, v)


class IPv4TCPPacket:
    """A parsed IPv4/TCP packet with a ``pydivert.Packet``-compatible facade.

    ``is_inbound`` / ``is_outbound`` are set by the engine that produced the
    packet (the raw-socket engines know direction from the capture metadata).
    """

    __slots__ = (
        "_ver_ihl", "_ihl", "_tos", "_ident", "_flags_frag", "_ttl",
        "_src_ip", "_dst_ip", "ip_options",
        "_src_port", "_dst_port", "_seq", "_ack", "_data_off", "_flags",
        "_window", "_urg", "tcp_options", "_payload",
        "is_inbound", "is_outbound", "ip", "ipv4", "tcp",
        # Which netdev the sniffing engine saw this on. Diagnostics only, but
        # essential ones: on a stacked egress path the same packet is tapped
        # once per layer, and knowing which layer a stray copy came from is the
        # difference between a guess and an answer.
        "capture_dev",
    )

    def __init__(self):
        self.is_inbound = False
        self.is_outbound = False
        self.ip = _IPView(self)
        self.ipv4 = _IPv4View(self)
        self.tcp = _TCPView(self)
        self.capture_dev = ""

    def __repr__(self):
        """Readable one-liner — the state machine prints packets in its error
        paths, and the default object repr made those messages useless."""
        flags = "".join(n for n, b in (("S", 0x02), ("A", 0x10), ("F", 0x01),
                                       ("R", 0x04), ("P", 0x08)) if self._flags & b)
        try:
            src = socket.inet_ntoa(self._src_ip)
            dst = socket.inet_ntoa(self._dst_ip)
        except (OSError, AttributeError):
            src = dst = "?"
        direction = "OUT" if self.is_outbound else ("IN " if self.is_inbound else "?  ")
        dev = f" dev={self.capture_dev}" if self.capture_dev else ""
        return (f"<{direction} {src}:{self._src_port} > {dst}:{self._dst_port} "
                f"[{flags or '-'}] seq={self._seq} ack={self._ack} "
                f"len={len(self._payload)}{dev}>")

    # -- parsing ---------------------------------------------------------
    @classmethod
    def parse(cls, data: bytes) -> "IPv4TCPPacket":
        """Parse a raw IPv4 packet (starting at the IP header). Returns None if not IPv4/TCP."""
        if len(data) < 20:
            return None
        ver_ihl = data[0]
        if (ver_ihl >> 4) != 4:
            return None
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        (tos, total_len, ident, flags_frag, ttl, proto, _ip_csum) = struct.unpack(
            "!BHHHBBH", data[1:12]
        )
        if proto != _TCP_PROTO:
            return None
        src_ip = data[12:16]
        dst_ip = data[16:20]
        ip_options = data[20:ihl]

        # Trust IP total_length over the captured buffer length when possible
        # (a captured frame may carry trailing padding).
        if 0 < total_len <= len(data):
            data = data[:total_len]
        if len(data) < ihl + 20:
            return None

        tcp = data[ihl:]
        (src_port, dst_port, seq, ack, off_flags, window, _tcp_csum, urg) = struct.unpack(
            "!HHIIHHHH", tcp[:20]
        )
        data_off = ((off_flags >> 12) & 0x0F) * 4
        flags = off_flags & 0x01FF
        if data_off < 20 or len(tcp) < data_off:
            return None
        tcp_options = tcp[20:data_off]
        payload = tcp[data_off:]

        pkt = cls()
        pkt._ver_ihl = ver_ihl
        pkt._ihl = ihl
        pkt._tos = tos
        pkt._ident = ident
        pkt._flags_frag = flags_frag
        pkt._ttl = ttl
        pkt._src_ip = src_ip
        pkt._dst_ip = dst_ip
        pkt.ip_options = ip_options
        pkt._src_port = src_port
        pkt._dst_port = dst_port
        pkt._seq = seq
        pkt._ack = ack
        pkt._data_off = data_off
        pkt._flags = flags
        pkt._window = window
        pkt._urg = urg
        pkt.tcp_options = tcp_options
        pkt._payload = payload
        return pkt

    # -- building --------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Serialise back to a raw IPv4 packet with IP and TCP checksums recomputed."""
        tcp_hdr_len = 20 + len(self.tcp_options)
        data_off_words = tcp_hdr_len // 4
        off_flags = (data_off_words << 12) | (self._flags & 0x01FF)

        tcp_header_wo_csum = struct.pack(
            "!HHIIHHHH",
            self._src_port, self._dst_port, self._seq, self._ack,
            off_flags, self._window, 0, self._urg,
        ) + self.tcp_options

        tcp_segment = tcp_header_wo_csum + self._payload
        pseudo = self._src_ip + self._dst_ip + struct.pack("!BBH", 0, _TCP_PROTO, len(tcp_segment))
        tcp_csum = _checksum(pseudo + tcp_segment)
        tcp_segment = (
            tcp_header_wo_csum[:16] + struct.pack("!H", tcp_csum)
            + tcp_header_wo_csum[18:] + self._payload
        )

        ihl_words = (20 + len(self.ip_options)) // 4
        ver_ihl = (4 << 4) | ihl_words
        total_len = ihl_words * 4 + len(tcp_segment)
        ip_header_wo_csum = struct.pack(
            "!BBHHHBBH",
            ver_ihl, self._tos, total_len, self._ident,
            self._flags_frag, self._ttl, _TCP_PROTO, 0,
        ) + self._src_ip + self._dst_ip + self.ip_options
        ip_csum = _checksum(ip_header_wo_csum)
        ip_header = (
            ip_header_wo_csum[:10] + struct.pack("!H", ip_csum) + ip_header_wo_csum[12:]
        )
        return ip_header + tcp_segment
