import asyncio
import os
import socket
import sys
import traceback
import threading
import json
import time

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from utils.platform_utils import (
    is_admin,
    elevate_or_exit,
    list_interfaces,
    ifname_for_ip,
    ip_for_ifname,
    default_route_ip,
)
from engines import create_engine, detect_backend
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    """Returns the directory where the executable (or this script) lives."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_version() -> str:
    """The installed release tag, from the VERSION file next to this script."""
    try:
        with open(os.path.join(get_exe_dir(), "VERSION")) as f:
            return f.read().strip() or "unknown"
    except OSError:
        return "unknown"


DEFAULT_CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "188.114.99.0",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "chatgpt.com",
    # "auto" selects the engine from the OS (windivert / raw / scapy). Override
    # only for testing on an unusual platform.
    "BACKEND": "auto",
    # When true (or when stdin is not a TTY, e.g. under an init system), skip the
    # interactive interface menu and use the default-route interface. Handy for
    # headless boxes and OpenWRT.
    "AUTO_SELECT_INTERFACE": False,
    # Pin the outbound interface by *kernel device* name (e.g. "pppoe-wan",
    # "eth0.2") or by IPv4. Note this is not the OpenWRT/UCI logical name: "wan"
    # is a logical interface, and on DSA targets it is also a switch port with no
    # IPv4 of its own — pinning it would leave the injector with nothing to bind.
    # Empty or "default" = follow the default route automatically (recommended).
    "INTERFACE": "",
    # Bind the capture socket to the outbound interface instead of listening on
    # all of them. Off by default: binding by name has proved unreliable on some
    # virtualised NICs. Duplicate frames from a stacked WAN are handled without
    # it, so turn this on only to shave CPU on a very busy router.
    "BIND_INTERFACE": False,
    # Linux fwmark (SO_MARK) to stamp on our own outbound sockets, or 0 to
    # disable. This is what keeps a transparent proxy on the same box from
    # swallowing the relay's own connection to the server.
    #
    # On OpenWRT with Passwall2 the correct value is 0xff: Passwall2's own
    # output chain begins with `meta mark 0x000000ff ... return`, so a marked
    # packet skips its TPROXY interception and routes normally out the WAN.
    # Without it, Passwall2 policy-routes our connection to loopback and into
    # its proxy, the real server never sees it, and the desync cannot work.
    "FWMARK": 0,
}


# Load or create the config
config_path = os.path.join(get_exe_dir(), "config.json")
if not os.path.exists(config_path):
    try:
        with open(config_path, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[Info] Created default config.json at {config_path}")
        config = dict(DEFAULT_CONFIG)
    except Exception as e:
        print(f"[Warning] Could not write default config.json: {e}")
        config = dict(DEFAULT_CONFIG)
else:
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        print(f"[Error] Failed to read config.json: {e}. Using defaults.")
        config = dict(DEFAULT_CONFIG)

LISTEN_HOST = config.get("LISTEN_HOST", DEFAULT_CONFIG["LISTEN_HOST"])
LISTEN_PORT = config.get("LISTEN_PORT", DEFAULT_CONFIG["LISTEN_PORT"])
FAKE_SNI = config.get("FAKE_SNI", DEFAULT_CONFIG["FAKE_SNI"]).encode()
CONNECT_IP = config.get("CONNECT_IP", DEFAULT_CONFIG["CONNECT_IP"])
CONNECT_PORT = config.get("CONNECT_PORT", DEFAULT_CONFIG["CONNECT_PORT"])
BACKEND = config.get("BACKEND", "auto")
if not BACKEND or BACKEND == "auto":
    BACKEND = detect_backend()
AUTO_SELECT_INTERFACE = bool(config.get("AUTO_SELECT_INTERFACE", False))
CONFIG_INTERFACE = str(config.get("INTERFACE", "") or "").strip()
BIND_INTERFACE = bool(config.get("BIND_INTERFACE", False))
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)


def _parse_mark(value) -> int:
    """Accept 255, "255" or "0xff" — UCI and JSON both end up here."""
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip() or "0", 0)
    except ValueError:
        print(f"[Warning] Invalid FWMARK {value!r}; ignoring.")
        return 0


FWMARK = _parse_mark(config.get("FWMARK", 0))
# SNI_TRACE=1 logs every packet the state machine acts on. Very noisy; meant for
# working out why a particular connection failed, not for normal running.
TRACE = os.environ.get("SNI_TRACE") == "1"


def _looks_like_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except OSError:
        return False


DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections: "dict[tuple, FakeInjectiveConnection]" = {}


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    break
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                await loop.sock_sendall(sock_2, data)
            except (ConnectionResetError, OSError, asyncio.CancelledError):
                break
    except Exception:
        traceback.print_exc()
        sys.exit("relay main loop error!")
    finally:
        if peer_task and not peer_task.done():
            for sock in (sock_1, sock_2):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        sock_1.close()
        sock_2.close()


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    conn_id = f"{incoming_remote_addr[0]}:{incoming_remote_addr[1]}"
    print(f"[+] Client connected: {conn_id}")
    try:
        loop = asyncio.get_running_loop()
        if not INTERFACE_IPV4:
            # Binding to 0.0.0.0 would make the connection's source address
            # unknowable, so the injector could never match it and the client
            # would just stall for 2s. Fail fast and say why instead.
            report_no_bind_ip(conn_id)
            incoming_sock.close()
            return
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            sys.exit("impossible mode!")
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        # Mark before bind/connect so the very first SYN already carries it.
        set_fwmark(outgoing_sock, "outbound socket")
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        _set_keepalive(outgoing_sock)
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        try:
            try:
                await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
            except Exception as e:
                print(f"[Error] {conn_id}: could not connect to "
                      f"{CONNECT_IP}:{CONNECT_PORT} from {INTERFACE_IPV4}:{src_port} "
                      f"({type(e).__name__}: {e})", flush=True)
                outgoing_sock.close()
                incoming_sock.close()
                return

            if BYPASS_METHOD == "wrong_seq":
                try:
                    await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                except asyncio.TimeoutError:
                    report_desync_timeout(fake_injective_conn, conn_id)
                    outgoing_sock.close()
                    incoming_sock.close()
                    return
                except Exception as e:
                    print(f"[Error] {conn_id}: desync wait failed "
                          f"({type(e).__name__}: {e})", flush=True)
                    outgoing_sock.close()
                    incoming_sock.close()
                    return
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    print(f"[Error] {conn_id}: desync aborted (unexpected packet) on "
                          f"{INTERFACE_IPV4}:{src_port} -> {CONNECT_IP}:{CONNECT_PORT}",
                          flush=True)
                    outgoing_sock.close()
                    incoming_sock.close()
                    return
                if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    sys.exit("impossible t2a msg!")
                if TRACE:
                    print(f"[Trace] {conn_id}: desync OK on {INTERFACE_IPV4}:{src_port}",
                          flush=True)
            else:
                sys.exit("unknown bypass method!")
        finally:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception:
        traceback.print_exc()
        sys.exit("handle should not raise exception")
    finally:
        print(f"[-] Client disconnected: {conn_id}")


_last_timeout_report = 0.0
_last_nobind_report = 0.0


def report_no_bind_ip(conn_id: str):
    """Explain that there is no outbound address to work with. Rate-limited."""
    global _last_nobind_report
    now = time.monotonic()
    if now - _last_nobind_report < 10:
        return
    _last_nobind_report = now
    print(f"[Error] {conn_id}: refused — no outbound IPv4 address is available.")
    print(f"        Configured INTERFACE={CONFIG_INTERFACE or 'default'}. Either the WAN is "
          f"down, or INTERFACE names a device that has no IPv4.")
    print(f"        It must be a kernel device name ('pppoe-wan', 'eth0.2', ...), an IPv4, "
          f"or 'default'. On OpenWRT run: /etc/init.d/sni-spoof check")


def report_desync_timeout(conn, conn_id: str):
    """Explain a desync timeout instead of dropping the client in silence.

    The relay gives the injector 2 s to confirm the fake ClientHello was
    acknowledged; if it never is, the client connection is closed and — before
    this — nothing said why. Each milestone that was *not* reached points at a
    different cause, so report the first one missing. Rate-limited, because a
    broken setup fails on every single connection and this goes to syslog.
    """
    global _last_timeout_report
    now = time.monotonic()
    if now - _last_timeout_report < 10:
        return
    _last_timeout_report = now

    print(f"[Error] {conn_id}: desync timed out after 2s; dropping the connection.")
    if fake_tcp_injector is None:
        print(f"        The packet injector is NOT running — nothing is watching the wire.")
        print(f"        Usually the outbound interface has no IPv4 yet. Configured "
              f"INTERFACE={CONFIG_INTERFACE or 'default'}; current bind IP="
              f"{INTERFACE_IPV4 or '(none)'}.")
        return

    if conn.syn_seq == -1:
        print(f"        No outbound SYN to {CONNECT_IP}:{CONNECT_PORT} was ever seen on the wire.")
        print(f"        The connection left the box without dst={CONNECT_IP}, so something "
              f"redirected it before egress.")
        print(f"        On OpenWRT with Passwall2 this is the usual cause: Passwall2's nat/mangle "
              f"OUTPUT rules re-proxy the router's own traffic.")
        print(f"        Fix: add {CONNECT_IP} to Passwall2's direct/bypass list so the relay's "
              f"own outbound connection is left alone.")
        print(f"        Check with: /etc/init.d/sni-spoof check")
    elif conn.syn_ack_seq == -1:
        print(f"        SYN was sent but {CONNECT_IP}:{CONNECT_PORT} never answered with SYN-ACK.")
        print(f"        The server is unreachable or filtered — this is not a desync problem.")
    elif not conn.fake_sent:
        print(f"        Handshake completed but the fake ClientHello was never injected.")
        print(f"        Raw-socket injection is failing; check that the service runs as root.")
    else:
        print(f"        Fake ClientHello was injected but never acknowledged by the server.")
        print(f"        It was likely dropped in transit — by conntrack marking it INVALID, or "
              f"by the DPI itself.")
        print(f"        Try SNI_NO_BPF=1 (UCI option 'no_bpf 1') to rule out the kernel filter.")


def set_fwmark(sock: socket.socket, what: str = "socket"):
    """Stamp SO_MARK on ``sock`` so an on-box transparent proxy leaves it alone.

    Both of our outbound sockets need this — the TCP connection to the server
    *and* the raw socket that injects the fake ClientHello. If only one carried
    the mark the two halves of the same flow would take different paths.
    """
    if not FWMARK:
        return
    so_mark = getattr(socket, "SO_MARK", 36)  # linux/asm-generic/socket.h
    try:
        sock.setsockopt(socket.SOL_SOCKET, so_mark, FWMARK)
    except OSError as e:
        print(f"[Warning] Could not set fwmark {FWMARK:#x} on the {what} ({e}). "
              f"Needs root/CAP_NET_ADMIN on Linux.")


def _set_keepalive(sock: socket.socket):
    """Enable TCP keepalive tuning where the platform supports the options."""
    for opt, val in (("TCP_KEEPIDLE", 11), ("TCP_KEEPINTVL", 2), ("TCP_KEEPCNT", 3)):
        num = getattr(socket, opt, None)
        if num is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, num, val)
            except OSError:
                pass


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    _set_keepalive(mother_sock)
    mother_sock.listen()
    print(f"[Info] Listening on {LISTEN_HOST}:{LISTEN_PORT} -> {CONNECT_IP}:{CONNECT_PORT} "
          f"(fake SNI: {FAKE_SNI.decode(errors='replace')})")
    loop = asyncio.get_running_loop()
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        _set_keepalive(incoming_sock)
        asyncio.create_task(handle(incoming_sock, addr))


def resolve_bind_ip() -> str:
    """The IPv4 the relay should bind and inject on *right now*, or '' if none.

    Re-resolved on every poll rather than latched at startup. That matters under
    procd: START=95 can easily run before DHCP finishes or PPPoE dials, and the
    previous behaviour latched a placeholder name that no device would ever
    match, leaving the injector permanently unstarted after a reboot.

    Honours the pinned INTERFACE setting: an IPv4 literal is used verbatim, a
    device name is looked up fresh each call (so an interface appearing late,
    like pppoe-wan, self-heals), and empty/"default" follows the default route.
    """
    if CONFIG_INTERFACE and CONFIG_INTERFACE.lower() != "default":
        if _looks_like_ipv4(CONFIG_INTERFACE):
            return CONFIG_INTERFACE
        ip = ip_for_ifname(CONFIG_INTERFACE)
    else:
        ip = get_default_interface_ipv4(CONNECT_IP) or default_route_ip(CONNECT_IP)
    # A link-local address means DHCP failed; binding to it cannot reach anything.
    return "" if not ip or ip.startswith("169.254") else ip


def select_network_interface() -> "tuple[str, str]":
    """Return (label, ipv4). Portable across Windows / Linux / macOS.

    The label is for display only — the *binding* IP is always re-derived by
    ``resolve_bind_ip()``, so a stale or unresolvable name can no longer wedge
    the injector.

    Non-interactive (AUTO_SELECT_INTERFACE, or no TTY) follows the default route
    so the tool works headless and under init systems / OpenWRT procd.
    """
    global CONFIG_INTERFACE
    default_ip = get_default_interface_ipv4(CONNECT_IP) or default_route_ip(CONNECT_IP)
    interfaces = list_interfaces()

    def name_for(ip: str) -> str:
        for i in interfaces:
            if i.get("ip") == ip:
                return i.get("name", "")
        return ifname_for_ip(ip)

    # A pinned interface (from config / the LuCI selector) wins on every platform.
    # Empty or "default" means auto default-route.
    if CONFIG_INTERFACE and CONFIG_INTERFACE.lower() != "default":
        ip = resolve_bind_ip()
        if _looks_like_ipv4(CONFIG_INTERFACE):
            print(f"[Info] Using configured interface IP {CONFIG_INTERFACE} "
                  f"({name_for(CONFIG_INTERFACE) or 'not owned by any local device'})")
            return f"IP {CONFIG_INTERFACE}", ip
        if ip:
            print(f"[Info] Using configured interface {CONFIG_INTERFACE} ({ip})")
        else:
            have = ", ".join(f"{i.get('name')}={i.get('ip')}" for i in interfaces) or "none"
            print(f"[Warning] Configured interface {CONFIG_INTERFACE!r} has no IPv4. "
                  f"Waiting for it to come up.")
            print(f"[Warning] INTERFACE must be a kernel device name, not an OpenWRT logical "
                  f"name: use 'pppoe-wan' / 'eth0.2' / ... , an IPv4, or 'default'.")
            print(f"[Warning] Devices that do have an IPv4: {have}")
        return CONFIG_INTERFACE, ip

    non_interactive = AUTO_SELECT_INTERFACE or not sys.stdin or not sys.stdin.isatty()
    if non_interactive or not interfaces:
        name = name_for(default_ip) or "default route"
        print(f"[Info] Following the default route: {name} ({default_ip or 'no IPv4 yet'})")
        return name, default_ip

    print("\n==================================================")
    print("Available Network Interfaces:")
    for idx, i in enumerate(interfaces, 1):
        mark = "  (Default)" if i.get("ip") == default_ip else ""
        print(f" {idx}. {i.get('name', '?'):<24} -> {i.get('ip', ''):<16}{mark}")
    print("==================================================\n")

    default_hint = f" [Default: {default_ip}]" if default_ip else ""
    while True:
        try:
            choice = input(f"Select interface (1-{len(interfaces)}){default_hint}: ").strip()
        except EOFError:
            choice = ""
        if not choice:
            name = name_for(default_ip) or "default route"
            print(f"Using interface: {name} ({default_ip})")
            return name, default_ip
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            sel = interfaces[int(choice) - 1]
            print(f"Using interface: {sel.get('name')} ({sel.get('ip')})")
            # Pin the choice so resolve_bind_ip() keeps tracking this device.
            CONFIG_INTERFACE = sel.get("name", "")
            return sel.get("name", ""), sel.get("ip", "")
        print("Invalid selection.")


fake_tcp_injector = None
injector_thread = None


def injector_running() -> bool:
    """True when the capture/inject thread is alive and watching the wire."""
    return fake_tcp_injector is not None and injector_thread is not None \
        and injector_thread.is_alive()


def run_injector_safe(local_ip: str):
    global fake_tcp_injector
    try:
        engine = create_engine(local_ip, CONNECT_IP, CONNECT_PORT, backend=BACKEND,
                               bind_interface=BIND_INTERFACE, fwmark=FWMARK)
        fake_tcp_injector = FakeTcpInjector(engine, fake_injective_connections)
        fake_tcp_injector.run()
    except Exception as e:
        print(f"\n[Error] Injector stopped: {e}")
        traceback.print_exc()
    finally:
        fake_tcp_injector = None


def stop_injector():
    global fake_tcp_injector
    if fake_tcp_injector:
        try:
            fake_tcp_injector.w.close()
        except Exception:
            pass
        fake_tcp_injector = None


def start_injector(local_ip: str):
    global injector_thread
    print(f"[Info] Starting fake-TCP injector ({BACKEND} backend) on {local_ip} "
          f"-> {CONNECT_IP}:{CONNECT_PORT}")
    injector_thread = threading.Thread(target=run_injector_safe, args=(local_ip,), daemon=True)
    injector_thread.start()


def monitor_adapter_loop(label: str, initial_ip: str):
    """Keep the injector bound to the current outbound IPv4.

    ``label`` is only for log messages; the address is re-derived every tick by
    ``resolve_bind_ip()`` so a WAN that comes up late, changes address, or drops
    and returns is all handled by the same path.
    """
    global INTERFACE_IPV4
    last_ip = initial_ip
    last_warn = 0.0
    last_restart = 0.0

    if last_ip:
        INTERFACE_IPV4 = last_ip
        start_injector(last_ip)
    else:
        print(f"[Warning] {label} has no IPv4 yet — waiting for it before starting the injector.")

    while True:
        time.sleep(2)
        try:
            current_ip = resolve_bind_ip()
        except Exception:
            current_ip = ""

        if last_ip and not current_ip:
            print(f"[Warning] {label} lost its IPv4. Pausing the injector...")
            stop_injector()
            last_ip = ""
            INTERFACE_IPV4 = ""
        elif current_ip and current_ip != last_ip:
            if not last_ip:
                print(f"[Info] {label} is up (IPv4: {current_ip}). Resuming...")
            else:
                print(f"[Info] {label} IPv4 changed {last_ip} -> {current_ip}. Rebinding...")
                stop_injector()
            INTERFACE_IPV4 = current_ip
            last_ip = current_ip
            start_injector(current_ip)
        elif not current_ip:
            # Nag periodically: without an IPv4 nothing can work, and a silent
            # wait here is exactly what made this state so hard to diagnose.
            now = time.monotonic()
            if now - last_warn > 30:
                last_warn = now
                try:
                    have = ", ".join(f"{i.get('name')}={i.get('ip')}"
                                     for i in list_interfaces()) or "none"
                except Exception:
                    have = "unknown"
                print(f"[Warning] Still no IPv4 for {label}; the desync cannot run. "
                      f"Devices with an IPv4: {have}")
        elif not injector_running():
            # The capture thread died (e.g. the socket was closed underneath it)
            # but the address is still fine — bring it back. Backed off, because
            # a permanent failure (not root, no AF_PACKET) would otherwise spin.
            now = time.monotonic()
            if now - last_restart > 10:
                last_restart = now
                print(f"[Warning] Injector is not running; restarting it on {current_ip}.")
                stop_injector()
                start_injector(current_ip)


if __name__ == "__main__":
    if not is_admin():
        print("This program requires root/administrator privileges. Attempting to elevate...")
        elevate_or_exit()

    print(f"[Info] SNI-Spoofing {get_version()} — platform backend: {BACKEND}")

    INTERFACE_NAME, INTERFACE_IPV4 = select_network_interface()

    threading.Thread(
        target=monitor_adapter_loop,
        args=(INTERFACE_NAME, INTERFACE_IPV4),
        daemon=True,
    ).start()

    print("\nProject to help provide free and open internet access.")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424")
    print("@patterniha\n")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Info] KeyboardInterrupt received. Stopping...")
        stop_injector()
        print("[Info] Goodbye!")
        sys.exit(0)
