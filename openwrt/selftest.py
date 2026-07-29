#!/usr/bin/env python3
"""Answer one question: does the relay's own outbound flow reach the wire?

The desync works by sniffing the relay's connection to CONNECT_IP with an
AF_PACKET socket and injecting one crafted packet into it. AF_PACKET taps the
egress path *after* NAT, so if anything on the box redirects the connection
before it leaves — Passwall2's nat/mangle OUTPUT rules being the usual suspect on
OpenWRT — the packets that egress no longer carry ``dst == CONNECT_IP``. The
injector then sees nothing, never fires, and every connection is dropped after
the 2s timeout with no clue as to why.

This makes exactly one real TCP connection to CONNECT_IP:CONNECT_PORT while
watching the wire, and reports which of the two worlds we are in. Read-only:
it injects nothing and changes no configuration.

Run: python3 /opt/sni-spoof/selftest.py
"""

import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
CAPTURE_SECONDS = 4.0


def load_config():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[FAIL] Cannot read {path}: {e}")
        sys.exit(2)


def default_route_ip(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def route_device(addr):
    """The device `ip route get` says this destination should leave by, or ''."""
    try:
        import subprocess
        out = subprocess.run(["ip", "route", "get", addr], capture_output=True,
                             text=True, timeout=5).stdout.split()
        if "dev" in out:
            return out[out.index("dev") + 1]
    except Exception:
        pass
    return ""


def main():
    cfg = load_config()
    dst_ip = cfg.get("CONNECT_IP", "")
    dst_port = int(cfg.get("CONNECT_PORT", 443))
    if not dst_ip:
        print("[FAIL] CONNECT_IP is not set in config.json")
        return 2

    local_ip = default_route_ip(dst_ip)
    expect_dev = route_device(dst_ip)
    fwmark = int(str(cfg.get("FWMARK", 0) or 0), 0)
    print(f"Target      : {dst_ip}:{dst_port}")
    print(f"Local IPv4  : {local_ip or '(none — no route to the target!)'}")
    print(f"Egress dev  : {expect_dev or '(unknown)'}")
    print(f"fwmark      : {hex(fwmark) if fwmark else 'off'}")
    if not local_ip:
        print("\n[FAIL] The router has no source address for this destination.")
        print("       Fix routing/WAN first; nothing else can work.")
        return 1

    try:
        cap = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    except AttributeError:
        print("[FAIL] AF_PACKET is unavailable — this must run on Linux.")
        return 2
    except PermissionError:
        print("[FAIL] Permission denied opening AF_PACKET. Run as root.")
        return 2

    cap.settimeout(0.5)
    dst_packed = socket.inet_aton(dst_ip)
    local_packed = socket.inet_aton(local_ip)

    seen = {"out": 0, "in": 0, "out_syn": 0, "ifaces": set(), "dupes": 0}
    sigs = {}
    stop = threading.Event()

    def sniff():
        deadline = time.time() + CAPTURE_SECONDS
        while time.time() < deadline and not stop.is_set():
            try:
                data, addr = cap.recvfrom(65565)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 40 or data[9] != 6:
                continue
            src_p, dst_p = data[12:16], data[16:20]
            if dst_p == dst_packed and src_p == local_packed:
                seen["out"] += 1
                seen["ifaces"].add(addr[0])
                ihl = (data[0] & 0x0F) * 4
                flags = data[ihl + 13]
                if flags & 0x02 and not flags & 0x10:
                    seen["out_syn"] += 1
                sig = (data[ihl:ihl + 4], data[ihl + 4:ihl + 8], flags)
                sigs[sig] = sigs.get(sig, 0) + 1
                if sigs[sig] > 1:
                    seen["dupes"] += 1
            elif src_p == dst_packed and dst_p == local_packed:
                seen["in"] += 1

    t = threading.Thread(target=sniff, daemon=True)
    t.start()
    time.sleep(0.4)  # let the capture socket settle before generating traffic

    print(f"\nOpening a TCP connection to {dst_ip}:{dst_port} while watching the wire...")
    connected = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        if fwmark:
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), fwmark)
        s.bind((local_ip, 0))
        s.connect((dst_ip, dst_port))
        connected = True
    except OSError as e:
        print(f"  connect() failed: {e}")
    finally:
        s.close()

    t.join(CAPTURE_SECONDS + 1)
    stop.set()
    cap.close()

    print(f"  TCP connect     : {'succeeded' if connected else 'FAILED'}")
    print(f"  Outbound packets: {seen['out']} (SYNs: {seen['out_syn']})")
    print(f"  Inbound packets : {seen['in']}")
    print(f"  Seen on devices : {', '.join(sorted(seen['ifaces'])) or '(none)'}")
    print(f"  Duplicate copies: {seen['dupes']}")
    print()

    devs = seen["ifaces"]
    real_devs = devs - {"lo"}

    rc = 0
    if seen["out_syn"] == 0:
        rc = 1
        print("[FAIL] No outbound SYN with this destination was seen at all.")
        print("       Something rewrote the destination before egress, so the")
        print("       injector can never observe this flow.")
        print(f"       Set a bypass fwmark:  uci set sni-spoof.main.fwmark=0xff")
    elif expect_dev and expect_dev not in devs and not real_devs:
        # The give-away for TPROXY-style interception: the packets keep their
        # original destination (so the naive "did we see a SYN" check passes)
        # but are policy-routed to loopback and handed to a local proxy. They
        # never touch the WAN, so the real server never sees them.
        rc = 1
        print(f"[FAIL] The connection never left via {expect_dev} — it was diverted to "
              f"{', '.join(sorted(devs))}.")
        print("       A transparent proxy on this router (Passwall2/TPROXY) is")
        print("       policy-routing the relay's own connection into itself. The")
        print("       real server never sees it, so the desync cannot work.")
        print()
        print("       Passwall2 exempts anything marked 0xff, so mark our sockets:")
        print()
        print("         uci set sni-spoof.main.fwmark='0xff'")
        print("         uci commit sni-spoof && /etc/init.d/sni-spoof restart")
        print()
        print("       (That needs no Passwall2 change and keeps working whatever")
        print("        server IP you use. Alternatively add the IP to Passwall2's")
        print(f"        direct list: uci add_list passwall2.@global[0].direct_ip={dst_ip})")
    elif not connected:
        rc = 1
        print("[FAIL] Packets left the box but the connection did not complete.")
        print("       The server is unreachable or filtered upstream. Not a desync")
        print("       problem — check the server IP/port and the WAN link.")
    else:
        print(f"[ OK ] The relay's own flow egresses via {', '.join(sorted(real_devs))} "
              f"and is visible to the injector.")
        print("       The desync has everything it needs.")

    if seen["dupes"]:
        print()
        print(f"[NOTE] {seen['dupes']} duplicate copies across "
              f"{len(devs)} device(s): {', '.join(sorted(devs))}.")
        print("       Normal for a stacked egress path (DSA port over conduit,")
        print("       PPPoE/VLAN, or loopback). The engine collapses duplicates.")

    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
