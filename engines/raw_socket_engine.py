"""
Linux (and OpenWRT) packet engine using only the Python standard library.

Design
------
The desync technique never needs to *drop* or *rewrite* a real packet — it lets
every real packet flow normally and merely injects one extra "fake" ClientHello
after the TCP handshake.  So instead of pulling the flow into userspace with
NFQUEUE (which needs libnetfilter_queue + a python binding not packaged on
OpenWRT), we:

  * SNIFF the flow read-only with an ``AF_PACKET`` / ``SOCK_DGRAM`` socket.  The
    kernel keeps delivering the real packets normally; we only observe them to
    learn the sequence numbers and the moment the handshake completes.  Packet
    direction comes for free from the capture metadata (``PACKET_OUTGOING`` vs.
    incoming).

  * INJECT the fake packet with an ``AF_INET`` / ``SOCK_RAW`` socket with
    ``IP_HDRINCL`` — we hand the kernel a fully-formed IP packet and it routes it.

Both socket types are in stdlib ``socket`` and work on musl / minimal Python, so
no external dependency is required — important for OpenWRT.

``send(pkt, recalc=False)`` is a no-op here: the real packet was never removed
from the wire.  ``send(pkt, recalc=True)`` serialises the mutated packet (fresh
checksums) and raw-sends it.

Root privileges are required (raw sockets).

Parity with the WinDivert engine
--------------------------------
The shared state machine in ``fake_tcp.py`` was written against WinDivert, whose
capture filter (see ``engines/windivert_engine.build_filter``) is::

    tcp and
    ((SrcAddr == local_ip and DstAddr == dst_ip and DstPort == dst_port) or
     (SrcAddr == dst_ip and DstAddr == local_ip and SrcPort == dst_port)) and
    (tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength == 0)

Every clause matters, and this engine reproduces all of them:

  * The flow is pinned to *both* endpoints and the port.  Without that, on a
    router every forwarded LAN flow to the same server would enter the state
    machine.
  * Payload-bearing packets are dropped.  The state machine has no branch for
    them: a data packet reaching ``on_outbound_packet`` falls through to
    ``on_unexpected_packet``, which tears the connection down.

Two things WinDivert gives for free that a sniffer must emulate:

  * WinDivert *removes* a packet from the stack, so it is seen exactly once.  An
    unbound ``AF_PACKET`` socket sees one copy per netdev in the egress stack —
    on OpenWRT the WAN path is routinely stacked (``pppoe-wan`` over ``eth0.2``
    over ``eth0``, or a DSA user port over its conduit).  Duplicates are fatal to
    the state machine, so exact repeats are suppressed here.
  * A WinDivert-injected packet never comes back.  A raw-injected one is tapped
    on egress like any other, once per netdev, so every echo must be absorbed.
"""

import os
import socket
import struct

from utils.rawpacket import IPv4TCPPacket
from utils.platform_utils import ifname_for_ip

# We MUST register the capture socket with ETH_P_ALL, not ETH_P_IP. The kernel's
# transmit tap (dev_queue_xmit_nit) only delivers *outgoing* packets to sockets on
# the ptype_all list — i.e. those bound to ETH_P_ALL. A socket bound to a specific
# ethertype (ETH_P_IP) receives inbound packets only, so we would never observe our
# own outbound SYN/ACK and the desync could never fire. (Verified empirically.)
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4  # linux/if_packet.h

SO_ATTACH_FILTER = getattr(socket, "SO_ATTACH_FILTER", 26)
# SKF_NET_OFF: base offset for loads relative to the *network* (IP) header, so the
# filter is independent of the L2 header length (Ethernet vs PPPoE vs tun). Linux 3.7+.
SKF_NET_OFF = -0x100000

# How many recent (direction, signature) pairs to remember for duplicate
# suppression. The interesting window is a handful of handshake packets, so this
# is generous; it only has to outlive the gap between two taps of one packet.
_DUP_WINDOW = 512


def _build_bpf(local_ip: str, dst_ip: str) -> bytes:
    """Classic-BPF mirroring the WinDivert filter's addressing clause.

    Keeps only TCP packets exchanged between ``local_ip`` and ``dst_ip`` — i.e.
    both endpoints, not just the remote one. Offsets are relative to SKF_NET_OFF
    so the filter lands inside the IP header on any link type. Returns (packed
    sock_fprog, backing buffer) — the caller must keep the buffer alive across
    the setsockopt() call (the kernel copies it there).

    The port and payload clauses of the WinDivert filter are deliberately *not*
    expressed here. Reaching the TCP header needs an ``LDX|B|MSH`` + indexed
    load, and the payload length needs arithmetic on the IP total length; both
    are more exotic opcodes than this filter has ever used on real routers. A
    wrong in-kernel filter fails *closed* (we capture nothing and the desync
    silently never fires), so the extra clauses are applied in ``recv()`` where a
    mistake is debuggable. Restricting to one address pair already discards
    essentially all of a busy router's traffic, which is what the filter is for.
    """
    dst = struct.unpack("!I", socket.inet_aton(dst_ip))[0]
    loc = struct.unpack("!I", socket.inet_aton(local_ip))[0]

    def off(o):
        return (SKF_NET_OFF + o) & 0xFFFFFFFF

    # sock_filter: (u16 code, u8 jt, u8 jf, u32 k)
    # BPF opcodes: LD|B|ABS=0x30  LD|W|ABS=0x20  JMP|JEQ|K=0x15  RET|K=0x06
    # jt/jf count instructions to SKIP, so target == index + 1 + jt.
    ACCEPT, DROP = 9, 10
    prog = [
        (0x30, 0, 0, off(9)),                      # 0: A = ip.proto
        (0x15, 0, DROP - 1 - 1, 6),                # 1: if A != TCP        -> drop
        (0x20, 0, 0, off(12)),                     # 2: A = ip.src
        (0x15, 7 - 3 - 1, 0, loc),                 # 3: if src == local_ip -> 7 (outbound)
        (0x15, 0, DROP - 4 - 1, dst),              # 4: if src != dst_ip   -> drop
        (0x20, 0, 0, off(16)),                     # 5: A = ip.dst          (inbound)
        (0x15, ACCEPT - 6 - 1, DROP - 6 - 1, loc), # 6: dst == local_ip ? accept : drop
        (0x20, 0, 0, off(16)),                     # 7: A = ip.dst          (outbound)
        (0x15, ACCEPT - 8 - 1, DROP - 8 - 1, dst), # 8: dst == dst_ip   ? accept : drop
        (0x06, 0, 0, 0x40000),                     # 9: accept (up to 256KiB)
        (0x06, 0, 0, 0),                           # 10: drop
    ]
    filters = b"".join(struct.pack("HBBI", *f) for f in prog)
    import ctypes
    buf = ctypes.create_string_buffer(filters)
    # struct sock_fprog { u16 len; struct sock_filter *filter; } (native alignment)
    return struct.pack("HP", len(prog), ctypes.addressof(buf)), buf


class RawSocketEngine:
    def __init__(self, local_ip: str, dst_ip: str, dst_port: int, bind_interface: bool = False,
                 fwmark: int = 0):
        self.local_ip = local_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self._dst_ip_packed = socket.inet_aton(dst_ip)
        self._local_ip_packed = socket.inet_aton(local_ip)
        self.ifname = ifname_for_ip(local_ip)
        self.bind_interface = bind_interface
        # The injected packet must take the same path as the connection it
        # belongs to. If the relay's TCP socket is marked to bypass an on-box
        # transparent proxy but this raw socket is not, the fake ClientHello is
        # policy-routed into the proxy while the real flow goes out the WAN.
        self.fwmark = fwmark
        self.recv_sock = None
        self.send_sock = None
        # Counters keyed by packet signature. Two distinct jobs:
        #
        #  _injected: packets WE injected. A raw-injected packet is delivered
        #    back to our own AF_PACKET capture as an outbound packet (the kernel
        #    taps egress) — once per netdev in the egress stack. Without this the
        #    state machine would see the fake ClientHello as an "unexpected
        #    outbound packet". We count echoes down rather than discarding a
        #    single one, so a stacked WAN (pppoe over vlan over eth) is handled.
        #
        #  _seen: every packet already handed to the state machine, so the extra
        #    copies produced by those same stacked netdevs are dropped. The state
        #    machine tolerates a duplicate SYN and SYN-ACK but treats a duplicate
        #    post-handshake ACK as fatal, so this is not optional on a router.
        self._injected = {}
        self._seen = {}
        self._seen_order = []
        # Set by recv() when a packet is dropped for a reason worth surfacing.
        self.stats = {"captured": 0, "delivered": 0, "dup": 0, "echo": 0, "payload": 0}

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def open(self):
        # Capture socket: cooked (L3) frames, ETH_P_ALL so we see BOTH directions
        # (see the ETH_P_ALL note above). SOCK_DGRAM strips the link-layer header,
        # so recv() data starts at the IP header regardless of Ethernet/PPPoE/tun.
        self.recv_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL)
        )
        # Attach an in-kernel BPF so only this flow's packets are copied to
        # userspace — keeps CPU near zero even on a busy router. Best-effort:
        # if it fails, the Python pre-filter in recv() still keeps us correct.
        #
        # Escape hatch: if some kernel's BPF wrongly dropped our packets, the
        # in-kernel filter would starve the (correct) Python pre-filter, breaking
        # the tool. Set SNI_NO_BPF=1 to skip the kernel filter entirely and rely
        # on the Python pre-filter alone (higher CPU, but guaranteed correct).
        if os.environ.get("SNI_NO_BPF") != "1":
            try:
                fprog, _buf = _build_bpf(self.local_ip, self.dst_ip)
                self.recv_sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
            except Exception as e:
                print(f"[Warning] Could not attach kernel BPF ({e}); "
                      f"falling back to the Python filter (higher CPU, same result).")
        # By default we do NOT bind() to a single interface: binding by name
        # proved unreliable on some virtualised NICs (it silently captured zero
        # packets), and capturing everywhere is correct because the Python filter
        # pins the flow. Binding is available for the opposite problem — a deeply
        # stacked WAN where every packet is tapped several times. Duplicate
        # suppression below handles that too, so this stays opt-in.
        if self.bind_interface and self.ifname:
            try:
                self.recv_sock.bind((self.ifname, ETH_P_ALL))
            except OSError as e:
                print(f"[Warning] Could not bind capture to {self.ifname} ({e}); "
                      f"capturing on all interfaces instead.")
        # Injection socket: we supply the full IP header ourselves.
        self.send_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        try:
            self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError:
            pass  # IPPROTO_RAW already implies HDRINCL on Linux
        if self.fwmark:
            try:
                so_mark = getattr(socket, "SO_MARK", 36)
                self.send_sock.setsockopt(socket.SOL_SOCKET, so_mark, self.fwmark)
            except OSError as e:
                print(f"[Warning] Could not set fwmark {self.fwmark:#x} on the "
                      f"injection socket ({e}).")

    def recv(self, bufsize: int = 65565):
        sock = self.recv_sock
        if sock is None:  # closed underneath us (rebind/shutdown) — stop the loop
            raise OSError("capture socket closed")
        data, addr = sock.recvfrom(bufsize)
        # addr == (ifname, proto, pkttype, hatype, hwaddr)
        pkttype = addr[2]

        # Cheap pre-filter before the full parse: must involve CONNECT_IP so we
        # stay light even on a busy router carrying unrelated traffic.
        if len(data) < 20:
            return None
        if data[12:16] != self._dst_ip_packed and data[16:20] != self._dst_ip_packed:
            return None
        if data[9] != 6:  # IP protocol == TCP
            return None

        pkt = IPv4TCPPacket.parse(data)
        if pkt is None:
            return None

        self.stats["captured"] += 1

        # --- WinDivert filter parity, clause 1: pin BOTH endpoints and the port.
        # Without this, on a router every forwarded LAN flow to the same server
        # (and Passwall2's own traffic to it) would enter the state machine.
        src, dst = pkt.ip.src_addr, pkt.ip.dst_addr
        if src == self.local_ip and dst == self.dst_ip:
            if pkt.tcp.dst_port != self.dst_port:
                return None
        elif src == self.dst_ip and dst == self.local_ip:
            if pkt.tcp.src_port != self.dst_port:
                return None
        else:
            return None

        outbound = (pkttype == PACKET_OUTGOING) or (src == self.local_ip)
        sig = self._sig(pkt)

        # Drop the echo of a packet we injected ourselves (see _injected above).
        # This runs before the payload clause below: the fake ClientHello carries
        # a payload, so the payload clause would otherwise swallow its echoes and
        # leave the _injected counters to accumulate uncollected.
        if outbound:
            n = self._injected.get(sig)
            if n:
                if n <= 1:
                    self._injected.pop(sig, None)
                else:
                    self._injected[sig] = n - 1
                self.stats["echo"] += 1
                return None

        # --- WinDivert filter parity, clause 2: control packets only.
        # (tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength == 0)
        # The state machine has no branch for payload-bearing packets; one
        # reaching it falls through to on_unexpected_packet(), which closes the
        # connection. Windows never sees them, and neither may we.
        if pkt.tcp.payload and not (pkt.tcp.syn or pkt.tcp.rst or pkt.tcp.fin):
            self.stats["payload"] += 1
            return None

        # Drop extra copies of a packet the state machine has already handled.
        # A stacked WAN device chain taps the same skb once per layer; the state
        # machine treats a repeated post-handshake ACK as a fatal protocol error.
        key = (outbound, sig)
        if key in self._seen:
            self.stats["dup"] += 1
            return None
        self._remember(key)

        pkt.is_outbound = outbound
        pkt.is_inbound = not outbound
        self.stats["delivered"] += 1
        return pkt

    def _remember(self, key):
        """Record ``key`` in the bounded duplicate-suppression window."""
        self._seen[key] = True
        self._seen_order.append(key)
        if len(self._seen_order) > _DUP_WINDOW:
            # Drop the oldest half in one go: cheaper than per-insert trimming and
            # the window only has to span the microseconds between two taps.
            for old in self._seen_order[: _DUP_WINDOW // 2]:
                self._seen.pop(old, None)
            del self._seen_order[: _DUP_WINDOW // 2]

    @staticmethod
    def _sig(pkt):
        """Identity of a packet, stable across the copies of one transmission.

        Flags are included so a duplicate ACK is never confused with the FIN or
        RST that may follow it on the same sequence number.
        """
        t = pkt.tcp
        flags = (t.syn << 4) | (t.ack << 3) | (t.rst << 2) | (t.fin << 1) | t.psh
        return (t.src_port, t.dst_port, t.seq_num, t.ack_num, flags, len(t.payload))

    def send(self, packet, recalc: bool = True):
        if not recalc:
            # Real, already-in-flight packet: nothing to do, it was never held.
            return
        # Remember this injection so we can ignore its captured echo(es). A
        # stacked egress path taps the same packet once per netdev, so allow for
        # several; leftovers are harmless and are bounded below.
        sig = self._sig(packet)
        self._injected[sig] = self._injected.get(sig, 0) + 4
        if len(self._injected) > 1024:  # safety bound; echoes normally clear it
            self._injected.clear()
        raw = packet.to_bytes()
        self.send_sock.sendto(raw, (self.dst_ip, 0))

    def close(self):
        for sock in (self.recv_sock, self.send_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self.recv_sock = None
        self.send_sock = None
