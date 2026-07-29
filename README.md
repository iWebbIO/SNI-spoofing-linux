# SNI-Spoofing (cross-platform)

Bypass DPI (Deep Packet Inspection) with IP/TCP header manipulation.

This is a **cross-platform rewrite** of the original Windows-only
[patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing). The original
depended on **WinDivert** and ran only on Windows. This version keeps the exact
same desync technique but abstracts packet capture/injection behind a small
engine interface, so it runs on:

| Platform            | Engine                     | Extra dependencies |
|---------------------|----------------------------|--------------------|
| **Windows**         | WinDivert (`pydivert`)     | `pip install pydivert` |
| **Linux / OpenWRT** | raw `AF_PACKET` + raw send | **none** (pure stdlib) |
| **macOS / *BSD**    | scapy (fallback)           | `pip install scapy` (needs libpcap) |

The backend is auto-detected; nothing to configure.

---

## How it works

It is a local TCP proxy that performs a **fake-ClientHello TCP desync** (the
"wrong sequence number" method):

1. You point a client at the local listener (`LISTEN_PORT`, default `40443`).
2. For each connection the tool opens a real TCP connection to `CONNECT_IP:443`.
3. Right after the TCP handshake, it injects **one fake TLS ClientHello** carrying
   an innocuous `FAKE_SNI` (e.g. `chatgpt.com`) but with a **deliberately wrong
   TCP sequence number** (just *before* the real data).
4. The on-path DPI box sees the "allowed" SNI and lets the flow through. The
   destination server, however, treats the wrong-seq segment as already-seen
   data and **discards it** — so it never reaches the application.
5. The real client data (with the real SNI) then flows normally over the now
   desynchronised path.

The packet-fiddling logic (`fake_tcp.py`) is identical across platforms; only the
capture/injection **engine** differs.

```
main.py ── asyncio proxy ──┐
                           ├─ FakeTcpInjector (state machine, platform-agnostic)
engines/ ── PacketEngine ──┘        │
   ├─ windivert_engine (Windows)    │ uses a uniform packet facade:
   ├─ raw_socket_engine (Linux)     │   pkt.ip / pkt.ipv4 / pkt.tcp
   └─ scapy_engine (macOS/BSD)      │   pkt.is_inbound / is_outbound
utils/rawpacket.py ── pure-Python IPv4/TCP parse+build (pydivert-compatible)
```

---

## Configuration — `config.json`

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.99.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "chatgpt.com",
  "INTERFACE": "",
  "BACKEND": "auto",
  "AUTO_SELECT_INTERFACE": false,
  "BIND_INTERFACE": false
}
```

- `CONNECT_IP` — the real IP you want to reach (e.g. a Cloudflare edge IP).
- `FAKE_SNI` — the decoy hostname shown to the DPI.
- `INTERFACE` — pin the outbound interface by **kernel device name** or by IPv4.
  Empty or `"default"` = follow the default route automatically (recommended).
  On desktop this is offered as an interactive menu; on OpenWRT it is the LuCI
  dropdown. **On OpenWRT this is a device name, not a UCI logical name**: use
  `pppoe-wan` / `eth0.2` / `eth1`, not `wan`. On DSA targets a device called
  `wan` does exist but is a switch port with no address of its own, so pinning
  it leaves the relay with nothing to bind to.
- `BACKEND` — `auto` (recommended), or force `windivert` / `raw` / `scapy`.
- `AUTO_SELECT_INTERFACE` — `true` to skip the interactive interface menu (also
  auto-skipped whenever stdin is not a TTY, e.g. under systemd/procd).
- `BIND_INTERFACE` — Linux only; bind packet capture to the outbound device
  instead of listening on all of them. Off by default (binding by name is
  unreliable on some virtual NICs) and rarely needed.

It is created with defaults on first run.

---

## Requirements

- **Python 3.8+** and **root/administrator** privileges (raw packets need it).
- Linux/OpenWRT need **no third-party Python packages**.
- Windows: `pip install -r requirements.txt` (installs `pydivert`).

---

## Running

### Linux (desktop/server)

```bash
sudo python3 main.py
```

(The program will try to re-exec itself with `sudo` if not run as root; set
`SNI_NO_SUDO=1` to disable that.)

### Windows

```powershell
pip install -r requirements.txt
python main.py     # will prompt for UAC elevation
```

### macOS / *BSD

```bash
pip install scapy         # needs libpcap (brew install libpcap on macOS)
sudo python3 main.py
```

Then send traffic through the listener, e.g.:

```bash
curl --resolve real-host:443:127.0.0.1 https://real-host/ --connect-to ::127.0.0.1:40443
```

(or configure your client/router to use `THIS_HOST:40443`).

---

## OpenWRT

OpenWRT is fully supported by the pure-stdlib Linux engine — no third-party
Python packages, only the Python runtime. Verified end-to-end on **OpenWrt
25.12.5, kernel 6.12, ipq40xx (ARMv7)** with `fw4`/nftables active (see below).

> **Space note:** Python needs a few MB of free space. On small routers use
> [extroot](https://openwrt.org/docs/guide-user/additional-software/extroot_configuration)
> or a USB stick.

### Install

```sh
# copy this repo to the router, then, as root:
sh openwrt/install.sh
```

The installer:
- installs the Python runtime (`apk` on OpenWrt 24.10+, `opkg` on older builds),
  one package at a time, then **verifies every module the program imports** —
  a missing `python3-*` package would otherwise leave the service crash-looping
  with nothing listening;
- copies the program to `/opt/sni-spoof`;
- installs a UCI config at `/etc/config/sni-spoof` and a procd service, and
  **starts it** so procd registers the reload trigger — without that, toggling
  *Enabled* in LuCI would commit the config and then do nothing until a reboot;
- installs a minimal **LuCI** page under **Services → SNI Spoofing** (if LuCI is
  present), including status, diagnostics and a GitHub update button.

### Configure

Use **LuCI → Services → SNI Spoofing**, or edit `/etc/config/sni-spoof`:

```
config sni-spoof 'main'
	option enabled      '1'
	option listen_host  '127.0.0.1'   # loopback: only this router can dial it
	option listen_port  '40443'
	option connect_ip   '<your server IP>'
	option connect_port '443'
	option fake_sni     'chatgpt.com'
	option interface    'default'      # recommended; see below before pinning
	option no_bpf       '0'
```

The LuCI page shows **Network interface** as a dropdown — **Default (default
route)** plus every device on the router. Leave it on **Default** unless you have
a specific reason not to.

> **Do not pin `wan`.** That is a UCI *logical* interface name, and this setting
> takes a *kernel device* name. On DSA targets `wan` is also a real device — a
> switch port with no IPv4 of its own — so pinning it leaves the relay with no
> address to bind and the injector never starts. If you must pin, use the device
> that actually holds the WAN address (`pppoe-wan`, `eth0.2`, `eth1`, …) or the
> IPv4 itself. `ip route get <your server IP>` names the right one.

`Save & Apply` (or `uci commit sni-spoof`) regenerates `config.json` and restarts
the relay via the procd reload trigger. CLI equivalents:

```sh
/etc/init.d/sni-spoof enable      # start on boot
/etc/init.d/sni-spoof start
/etc/init.d/sni-spoof check       # diagnose — run this first if it misbehaves
logread -e sni-spoof              # watch output
```

Under procd there is no TTY, so the interface menu is skipped and the
default-route interface is used automatically.

### Using it with Passwall2

The relay is just a **local endpoint** — it does not touch routing or the
firewall. To route a Passwall2 node through it:

1. Set the relay's `connect_ip`/`connect_port` to your **real proxy server**, and
   `fake_sni` to an allowed hostname (e.g. `chatgpt.com`). Keep `listen_host` on
   `127.0.0.1`.
2. In Passwall2, edit your node and set its **address/port to `127.0.0.1` : `40443`**
   (the relay's listen address). Passwall speaks its normal protocol *through* the
   relay; the relay injects the fake SNI on the wire.
3. **Add `connect_ip` to Passwall2's direct/bypass list.** This step is not
   optional and is the single most common reason the OpenWRT setup appears not
   to work at all.

```sh
uci add_list passwall2.@global[0].direct_ip='<your server IP>'
uci commit passwall2 && /etc/init.d/passwall2 restart
```

(Option names differ between Passwall2 versions; the goal is simply that this one
IP is always routed **direct**, never through a node.)

#### Why step 3 is mandatory

Passwall2 installs `nat OUTPUT` / `mangle OUTPUT` rules that capture the
*router's own* outgoing connections. The relay's connection to your server is
router-originated, so it gets captured too.

The relay observes that connection with an `AF_PACKET` socket, and `AF_PACKET`
taps the egress path **after** NAT. So once Passwall2 redirects the connection,
the packets that actually reach the wire no longer carry your server's address.
The injector sees nothing, the fake ClientHello is never sent, and after two
seconds the relay gives up and closes the connection. From Passwall2's side this
looks like "the node just doesn't connect", with nothing in any log to explain it.

This is also the one failure mode Windows cannot reproduce: WinDivert hooks the
network layer *before* NAT, and there is no Passwall2 in the picture.

To confirm which side of this you are on:

```sh
/etc/init.d/sni-spoof check
```

It makes one real connection to your server while watching the wire and tells you
whether the packets got out — plus it checks the Python runtime, the service, the
route, and whether `connect_ip` appears anywhere in your Passwall2 config.

### Updating

The LuCI page has a **Status & Maintenance** panel with **Check for updates** and
**Update now**, which pull the latest GitHub release, reinstall, and restart the
service. The previous install is backed up first and restored automatically if
anything fails. The same thing from the shell:

```sh
/opt/sni-spoof/update.sh check     # installed vs latest release
/opt/sni-spoof/update.sh apply     # download, install, restart
```

The source repository is read from UCI (`sni-spoof.update.repo`), never from the
web request, so the download URL cannot be steered from the browser.

### Why it is non-invasive on a router (fw4 / conntrack)

The wrong-seq fake ClientHello is placed just *behind* the connection's first
real byte, so Linux conntrack treats it as a valid **retransmission**, not
`invalid`. This was verified on real hardware against `fw4`'s exact
`oifname "wan" ct state invalid drop` rule with strict conntrack
(`nf_conntrack_tcp_be_liberal = 0`): the desync completes and the drop counter
stays at **0**. The relay needs **no firewall rules** and cannot be dropped by
fw4. (Reproduce with `sudo python3 tests/net_e2e_fw4.py`.)

### Performance / lightweightness

- The Linux engine attaches an **in-kernel BPF** filter (offsets relative to
  `SKF_NET_OFF`, so it works on Ethernet, PPPoE and tun alike). Only packets of
  the one flow being manipulated are ever copied to userspace — CPU stays near
  zero even on a busy WAN link.
- No packets are dropped or rewritten in the kernel path; the tool only *sniffs*
  and injects one extra packet, so it adds no forwarding latency.
- If a particular kernel's BPF ever misbehaves, set `SNI_NO_BPF=1` (or
  `option no_bpf '1'` in UCI, which the LuCI page also exposes) to skip the
  kernel filter and rely on the pure-Python filter alone — guaranteed correct,
  just higher CPU. (Verified: the end-to-end desync passes with BPF on *and* off.)

### Capture parity with the Windows engine

The desync state machine is shared across platforms and was written against
WinDivert's capture filter, which delivers only *control* packets of one
specific flow:

```
tcp and ((SrcAddr == local_ip and DstAddr == server and DstPort == port) or
         (SrcAddr == server and DstAddr == local_ip and SrcPort == port))
    and (tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength == 0)
```

The Linux engine reproduces every clause — the in-kernel BPF pins the address
pair, and `recv()` applies the port and payload clauses. This matters: the state
machine has no branch for a payload-bearing packet, so one reaching it is treated
as a protocol violation and the connection is torn down.

Two things WinDivert provides for free that a sniffer must emulate, and now does:

- WinDivert *removes* a packet from the stack, so it is seen exactly once. An
  `AF_PACKET` socket sees one copy **per netdev in the egress stack** — and on a
  router the WAN path is routinely stacked (`pppoe-wan` over `eth0.2` over
  `eth0`, or a DSA user port over its conduit). Exact duplicates are collapsed.
- A WinDivert-injected packet never comes back; a raw-injected one is tapped on
  egress like any other, once per netdev. Every echo is absorbed, not just the
  first.

---

## Notes & limitations

- **WSL2 is not a valid runtime** for actual operation: its virtualised NIC does
  not deliver locally-generated (outbound) packets to `AF_PACKET`, which the
  desync needs. Use native Linux / a router / a VM. (WSL2 is fine for editing and
  for the non-capture unit tests.)
- IPv4 only (matching the original). The target flow is the IPv4 connection to
  `CONNECT_IP`.
- This is a research / censorship-circumvention tool; use it responsibly and
  legally.

---

## Tests

```bash
# packet parse/build + checksums + imports (any OS):
python3 tests/test_rawpacket.py

# Linux engine logic, no root needed:
python3 tests/test_raw_engine_logic.py

# real AF_PACKET + BPF + injection on a live interface (root):
sudo python3 tests/test_linux_integration.py

# FULL end-to-end desync in a veth/netns sandbox (root, no internet needed):
sudo python3 tests/net_e2e.py

# end-to-end desync THROUGH an fw4-style conntrack INVALID-drop rule (root):
sudo python3 tests/net_e2e_fw4.py
```

On a router, the most useful check is not a test but the built-in diagnostic —
it inspects the live installation and makes one real connection while watching
the wire:

```sh
/etc/init.d/sni-spoof check
```

The end-to-end test proves the real behaviour: the peer receives the genuine
payload while the fake SNI packet is discarded as old data.

---

## Credits

Original technique and Windows implementation: **@patterniha**. Licensed under
GPL-3.0 (see `LICENSE`).

Support free & open internet access (@patterniha):
USDT (BEP20): `0x76a768B53Ca77B43086946315f0BDF21156bF424`
