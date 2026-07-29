import os, sys, struct, socket
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.rawpacket import IPv4TCPPacket, _checksum

def build_ref_packet(src, dst, sp, dp, seq, ack, flags, payload=b"", ident=0x1234):
    # Build a reference IPv4/TCP packet with correct checksums the "manual" way.
    src_p = socket.inet_aton(src); dst_p = socket.inet_aton(dst)
    tcp_wo = struct.pack("!HHIIHHHH", sp, dp, seq, ack, (5<<12)|flags, 65535, 0, 0)
    seg = tcp_wo + payload
    pseudo = src_p + dst_p + struct.pack("!BBH", 0, 6, len(seg))
    csum = _checksum(pseudo + seg)
    tcp = tcp_wo[:16] + struct.pack("!H", csum) + tcp_wo[18:] + payload
    total = 20 + len(tcp)
    ip_wo = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0x4000, 64, 6, 0) + src_p + dst_p
    ipc = _checksum(ip_wo)
    ip = ip_wo[:10] + struct.pack("!H", ipc) + ip_wo[12:]
    return ip + tcp

def validate_checksums(raw):
    # IP header checksum over the header must be 0; TCP checksum over pseudo+seg must be 0.
    ihl = (raw[0] & 0x0F) * 4
    assert _checksum(raw[:ihl]) == 0, "IP checksum invalid"
    seg = raw[ihl:]
    pseudo = raw[12:16] + raw[16:20] + struct.pack("!BBH", 0, 6, len(seg))
    assert _checksum(pseudo + seg) == 0, "TCP checksum invalid"

def test_roundtrip():
    raw = build_ref_packet("192.168.1.50", "188.114.99.0", 55000, 443, 1000, 0, 0x02)  # SYN
    p = IPv4TCPPacket.parse(raw)
    assert p.ip.src_addr == "192.168.1.50"
    assert p.ip.dst_addr == "188.114.99.0"
    assert p.tcp.src_port == 55000 and p.tcp.dst_port == 443
    assert p.tcp.seq_num == 1000 and p.tcp.ack_num == 0
    assert p.tcp.syn and not p.tcp.ack and not p.tcp.rst and not p.tcp.fin and not p.tcp.psh
    assert len(p.tcp.payload) == 0
    assert p.ipv4.ident == 0x1234
    out = p.to_bytes()
    validate_checksums(out)
    assert out == raw, "SYN round-trip mismatch"
    print("test_roundtrip OK")

def test_mutation_like_state_machine():
    # Start from the outbound handshake ACK, then mutate into the fake ClientHello,
    # exactly as fake_send_thread does.
    raw = build_ref_packet("192.168.1.50", "188.114.99.0", 55000, 443, 1001, 5001, 0x10)  # ACK
    p = IPv4TCPPacket.parse(raw)
    syn_seq = 1000
    fake = os.urandom(200)
    p.tcp.psh = True
    p.ip.packet_len = p.ip.packet_len + len(fake)
    p.tcp.payload = fake
    p.ipv4.ident = (p.ipv4.ident + 1) & 0xffff
    p.tcp.seq_num = (syn_seq + 1 - len(fake)) & 0xffffffff
    out = p.to_bytes()
    validate_checksums(out)
    q = IPv4TCPPacket.parse(out)
    assert q.tcp.psh and q.tcp.ack
    assert q.tcp.payload == fake
    assert q.tcp.seq_num == (syn_seq + 1 - len(fake)) & 0xffffffff
    assert q.ipv4.ident == 0x1235
    assert q.ip.packet_len == 20 + 20 + len(fake)
    print("test_mutation_like_state_machine OK")

def test_flags_all():
    for name, bit in [("fin",0x01),("syn",0x02),("rst",0x04),("psh",0x08),("ack",0x10)]:
        raw = build_ref_packet("10.0.0.1","10.0.0.2",1,2,0,0,bit)
        p = IPv4TCPPacket.parse(raw)
        assert getattr(p.tcp, name) is True, name
    print("test_flags_all OK")

def test_options_preserved():
    # TCP with a 4-byte option (MSS): data offset = 6 words = 24 bytes.
    src_p = socket.inet_aton("1.1.1.1"); dst_p = socket.inet_aton("2.2.2.2")
    opt = struct.pack("!BBH", 2, 4, 1460)
    tcp_wo = struct.pack("!HHIIHHHH", 1234, 443, 7, 0, (6<<12)|0x02, 65535, 0, 0) + opt
    seg = tcp_wo
    pseudo = src_p+dst_p+struct.pack("!BBH",0,6,len(seg))
    csum=_checksum(pseudo+seg)
    tcp = tcp_wo[:16]+struct.pack("!H",csum)+tcp_wo[18:]
    total=20+len(tcp)
    ip_wo=struct.pack("!BBHHHBBH",0x45,0,total,1,0x4000,64,6,0)+src_p+dst_p
    ip=ip_wo[:10]+struct.pack("!H",_checksum(ip_wo))+ip_wo[12:]
    raw=ip+tcp
    p=IPv4TCPPacket.parse(raw)
    assert len(p.tcp_options)==4
    assert p.to_bytes()==raw, "options round-trip mismatch"
    print("test_options_preserved OK")

def test_imports():
    import engines, injecter, fake_tcp
    from engines import detect_backend, create_engine
    b = detect_backend()
    assert b in ("windivert","raw","scapy")
    # importing the POSIX engine module must not blow up on any OS
    import engines.raw_socket_engine as rse
    fprog, buf = rse._build_bpf("192.168.1.50", "188.114.99.0")
    assert isinstance(fprog, (bytes, bytearray)) and len(fprog) >= 4
    import main  # runs module-level config load; must not raise
    print(f"test_imports OK (detected backend on this host: {b})")

if __name__ == "__main__":
    test_roundtrip()
    test_mutation_like_state_machine()
    test_flags_all()
    test_options_preserved()
    test_imports()
    print("\nALL TESTS PASSED")
