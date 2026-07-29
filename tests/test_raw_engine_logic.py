"""Logic tests for the Linux raw-socket engine that do NOT require root.

We bypass the actual AF_PACKET/AF_INET sockets by injecting fakes, then feed the
engine synthetic captured frames and assert its filtering, parsing, direction
detection and send() semantics. Run: python3 tests/test_raw_engine_logic.py
"""
import os, sys, struct, socket
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.rawpacket import IPv4TCPPacket, _checksum
from engines.raw_socket_engine import RawSocketEngine, PACKET_OUTGOING

LOCAL = "192.168.1.50"
DST = "188.114.99.0"


def make_pkt(src, dst, sp, dp, flags, payload=b"", seq=100):
    src_p = socket.inet_aton(src); dst_p = socket.inet_aton(dst)
    tcp_wo = struct.pack("!HHIIHHHH", sp, dp, seq, 0, (5 << 12) | flags, 65535, 0, 0)
    seg = tcp_wo + payload
    pseudo = src_p + dst_p + struct.pack("!BBH", 0, 6, len(seg))
    tcp = tcp_wo[:16] + struct.pack("!H", _checksum(pseudo + seg)) + tcp_wo[18:] + payload
    total = 20 + len(tcp)
    ip_wo = struct.pack("!BBHHHBBH", 0x45, 0, total, 1, 0x4000, 64, 6, 0) + src_p + dst_p
    ip = ip_wo[:10] + struct.pack("!H", _checksum(ip_wo)) + ip_wo[12:]
    return ip + tcp


class FakeRecvSock:
    def __init__(self, queue):
        self.queue = list(queue)
    def recvfrom(self, n):
        return self.queue.pop(0)


class FakeSendSock:
    def __init__(self):
        self.sent = []
    def sendto(self, data, addr):
        self.sent.append((data, addr))


def make_engine():
    eng = RawSocketEngine(LOCAL, DST, 443)  # __init__ does no socket I/O
    return eng


def test_prefilter_drops_unrelated():
    eng = make_engine()
    # A packet to an unrelated host must be dropped by the cheap prefilter.
    unrelated = make_pkt(LOCAL, "9.9.9.9", 5000, 443, 0x02)
    eng.recv_sock = FakeRecvSock([(unrelated, ("eth0", 0, PACKET_OUTGOING, 0, b""))])
    assert eng.recv() is None
    print("test_prefilter_drops_unrelated OK")


def test_outbound_syn():
    eng = make_engine()
    raw = make_pkt(LOCAL, DST, 55000, 443, 0x02)  # SYN out
    eng.recv_sock = FakeRecvSock([(raw, ("eth0", 0, PACKET_OUTGOING, 0, b""))])
    p = eng.recv()
    assert p is not None and p.is_outbound and not p.is_inbound
    assert p.tcp.syn and not p.tcp.ack and p.tcp.dst_port == 443
    assert p.ip.src_addr == LOCAL and p.ip.dst_addr == DST
    print("test_outbound_syn OK")


def test_inbound_synack():
    eng = make_engine()
    raw = make_pkt(DST, LOCAL, 443, 55000, 0x12)  # SYN-ACK in
    PACKET_HOST = 0
    eng.recv_sock = FakeRecvSock([(raw, ("eth0", 0, PACKET_HOST, 0, b""))])
    p = eng.recv()
    assert p is not None and p.is_inbound and not p.is_outbound
    assert p.tcp.syn and p.tcp.ack
    print("test_inbound_synack OK")


def test_send_semantics():
    eng = make_engine()
    eng.send_sock = FakeSendSock()
    raw = make_pkt(LOCAL, DST, 55000, 443, 0x10)
    p = IPv4TCPPacket.parse(raw)
    eng.send(p, False)               # real passthrough -> must NOT transmit
    assert eng.send_sock.sent == []
    eng.send(p, True)                # inject -> must transmit exactly the bytes
    assert len(eng.send_sock.sent) == 1
    data, addr = eng.send_sock.sent[0]
    assert data == p.to_bytes() and addr == (DST, 0)
    print("test_send_semantics OK")


OUT = ("eth0", 0, PACKET_OUTGOING, 0, b"")
IN = ("eth0", 0, 0, 0, b"")  # PACKET_HOST


def test_drops_payload_bearing():
    """WinDivert parity: (tcp.Syn or Rst or Fin or PayloadLength == 0).

    The state machine has no branch for a data packet — one reaching it falls
    through to on_unexpected_packet(), which closes the connection. Windows never
    sees them because its capture filter excludes them, so neither may we.
    """
    eng = make_engine()
    data = make_pkt(LOCAL, DST, 55000, 443, 0x18, payload=b"\x16\x03\x01hello")  # PSH+ACK
    eng.recv_sock = FakeRecvSock([(data, OUT)])
    assert eng.recv() is None
    # ... but a FIN/RST carrying a payload must still be delivered.
    eng2 = make_engine()
    fin = make_pkt(LOCAL, DST, 55000, 443, 0x11, payload=b"bye")  # FIN+ACK
    eng2.recv_sock = FakeRecvSock([(fin, OUT)])
    assert eng2.recv() is not None
    print("test_drops_payload_bearing OK")


def test_pins_both_endpoints_and_port():
    """WinDivert parity: SrcAddr/DstAddr pinned to our IP, and the port pinned.

    On a router, forwarded LAN traffic to the same server (and Passwall2's own
    connections to it) would otherwise enter the state machine.
    """
    eng = make_engine()
    # Right server, wrong port -> not our flow.
    wrong_port = make_pkt(LOCAL, DST, 55000, 8443, 0x02)
    # Right server, but a different local host (a forwarded LAN flow).
    other_host = make_pkt("192.168.1.77", DST, 55000, 443, 0x02)
    eng.recv_sock = FakeRecvSock([(wrong_port, OUT), (other_host, OUT)])
    assert eng.recv() is None
    assert eng.recv() is None
    print("test_pins_both_endpoints_and_port OK")


def test_duplicate_capture_suppressed():
    """A stacked WAN (pppoe-wan over eth0.2 over eth0) taps the same packet once
    per netdev. The state machine tolerates a duplicate SYN but treats a repeated
    post-handshake ACK as fatal, so the engine must collapse exact repeats."""
    eng = make_engine()
    ack = make_pkt(LOCAL, DST, 55000, 443, 0x10, seq=101)
    eng.recv_sock = FakeRecvSock([(ack, OUT), (ack, OUT), (ack, OUT)])
    assert eng.recv() is not None    # first copy is real
    assert eng.recv() is None        # second tap
    assert eng.recv() is None        # third tap
    # A genuinely different packet on the same flow still gets through.
    eng.recv_sock = FakeRecvSock([(make_pkt(LOCAL, DST, 55000, 443, 0x11, seq=101), OUT)])
    assert eng.recv() is not None
    print("test_duplicate_capture_suppressed OK")


def test_injected_echo_suppressed_repeatedly():
    """A raw-injected packet is tapped on egress like any other — once per netdev.
    Absorbing only the first echo let the rest reach the state machine as an
    'unexpected outbound packet after fake sent', tearing the connection down."""
    eng = make_engine()
    eng.send_sock = FakeSendSock()
    fake = make_pkt(LOCAL, DST, 55000, 443, 0x18, payload=b"fake-client-hello", seq=50)
    pkt = IPv4TCPPacket.parse(fake)
    eng.send(pkt, True)
    # Its echoes arrive as outbound captures; every one must be swallowed.
    eng.recv_sock = FakeRecvSock([(fake, OUT), (fake, OUT), (fake, OUT)])
    for _ in range(3):
        assert eng.recv() is None
    assert eng.stats["echo"] == 3
    print("test_injected_echo_suppressed_repeatedly OK")


def test_inbound_and_outbound_are_distinct():
    """Same bytes seen in both directions must not be collapsed as duplicates."""
    eng = make_engine()
    out = make_pkt(LOCAL, DST, 55000, 443, 0x10, seq=101)
    inn = make_pkt(DST, LOCAL, 443, 55000, 0x10, seq=101)
    eng.recv_sock = FakeRecvSock([(out, OUT), (inn, IN)])
    a = eng.recv(); b = eng.recv()
    assert a is not None and a.is_outbound
    assert b is not None and b.is_inbound
    print("test_inbound_and_outbound_are_distinct OK")


def test_bpf_program_is_well_formed():
    """Guard the hand-assembled jump offsets: every jump must land inside the
    program, and the last two instructions must be the accept/drop returns."""
    from engines.raw_socket_engine import _build_bpf
    fprog, buf = _build_bpf(LOCAL, DST)
    n = struct.unpack("H", fprog[:2])[0]
    prog = [struct.unpack("HBBI", buf.raw[i * 8:(i + 1) * 8]) for i in range(n)]
    for i, (code, jt, jf, k) in enumerate(prog):
        if code & 0x07 == 0x05:  # BPF_JMP
            assert i + 1 + jt < n, f"instr {i} jt escapes the program"
            assert i + 1 + jf < n, f"instr {i} jf escapes the program"
    assert prog[-2][0] == 0x06 and prog[-2][3] > 0, "second-to-last must accept"
    assert prog[-1][0] == 0x06 and prog[-1][3] == 0, "last must drop"
    print("test_bpf_program_is_well_formed OK")


if __name__ == "__main__":
    test_prefilter_drops_unrelated()
    test_outbound_syn()
    test_inbound_synack()
    test_send_semantics()
    test_drops_payload_bearing()
    test_pins_both_endpoints_and_port()
    test_duplicate_capture_suppressed()
    test_injected_echo_suppressed_repeatedly()
    test_inbound_and_outbound_are_distinct()
    test_bpf_program_is_well_formed()
    print("\nRAW ENGINE LOGIC TESTS PASSED")
