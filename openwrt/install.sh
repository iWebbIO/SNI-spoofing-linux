#!/bin/sh
# Installer for SNI-Spoofing on OpenWrt (with optional LuCI UI).
#
# Installs the Python runtime, copies the project to /opt/sni-spoof, registers a
# procd service driven by UCI (/etc/config/sni-spoof), and installs a minimal
# LuCI page under Services -> SNI Spoofing.
#
# The raw-socket engine needs NO third-party Python packages. Run as root.
set -e

PROG_DIR=/opt/sni-spoof
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" = "0" ] || { echo "[!] Run this as root." >&2; exit 1; }

# ---- 1. Python runtime (apk on new OpenWrt, opkg on older) -------------------
# Installed one package at a time and NEVER fatally: feeds differ between
# releases and a single unknown package name used to abort the whole install
# (under `set -e`) before a single file had been copied. What actually matters
# is the import check below, so that is what we treat as authoritative.
PKGS="python3-light python3-asyncio python3-ctypes python3-logging"
echo "[*] Installing Python runtime: $PKGS"
if command -v apk >/dev/null 2>&1; then
	apk update || true
	for p in $PKGS; do
		apk add "$p" 2>/dev/null || echo "[=] skipped $p (not in this feed)"
	done
elif command -v opkg >/dev/null 2>&1; then
	opkg update || true
	for p in $PKGS; do
		opkg install "$p" 2>/dev/null || echo "[=] skipped $p (not in this feed)"
	done
	# Some older feeds have no python3-light at all; fall back to the full build.
	command -v python3 >/dev/null 2>&1 || opkg install python3 || true
else
	echo "[!] Neither apk nor opkg found — install python3 manually." >&2
	exit 1
fi

# ---- 2. Verify the runtime can actually run this program ---------------------
# An ImportError here means the service would crash-loop under procd and nothing
# would ever listen on the port — a failure that looks exactly like "the OpenWrt
# version doesn't work". Catch it now, while there is a human watching.
echo "[*] Verifying the Python runtime"
if ! command -v python3 >/dev/null 2>&1; then
	echo "[!] python3 is still not installed. Cannot continue." >&2
	exit 1
fi
MISSING=""
for m in asyncio concurrent.futures socket struct fcntl ctypes json threading; do
	python3 -c "import $m" >/dev/null 2>&1 || MISSING="$MISSING $m"
done
if [ -n "$MISSING" ]; then
	echo "[!] These Python modules are missing:$MISSING" >&2
	echo "    Install the matching python3-* packages and re-run this script." >&2
	echo "    (concurrent.futures usually ships in python3-asyncio or" >&2
	echo "     python3-multiprocessing depending on the OpenWrt release.)" >&2
	exit 1
fi
echo "[+] Python runtime OK ($(python3 -V 2>&1))"

# ---- 3. Program files --------------------------------------------------------
echo "[*] Installing project to $PROG_DIR"
mkdir -p "$PROG_DIR"
cp -a "$SRC_DIR"/main.py "$SRC_DIR"/fake_tcp.py "$SRC_DIR"/injecter.py \
      "$SRC_DIR"/monitor_connection.py "$SRC_DIR"/utils "$SRC_DIR"/engines "$PROG_DIR"/
# Install these two via temp+mv rather than cp-in-place: an update run invokes
# this installer *from* update.sh, and overwriting a running shell script's
# inode makes the shell resume reading the new file at its old byte offset.
# mv swaps the directory entry instead, so the running copy keeps its own inode.
for f in selftest.py update.sh; do
	cp -a "$SRC_DIR/openwrt/$f" "$PROG_DIR/.$f.new"
	chmod +x "$PROG_DIR/.$f.new"
	mv -f "$PROG_DIR/.$f.new" "$PROG_DIR/$f"
done
# Version marker: what the LuCI "Check for updates" button compares against.
if [ -f "$SRC_DIR/VERSION" ]; then
	cp -a "$SRC_DIR/VERSION" "$PROG_DIR/VERSION"
else
	echo "unknown" > "$PROG_DIR/VERSION"
fi

# ---- 4. UCI config (do not clobber an existing one) --------------------------
if [ ! -f /etc/config/sni-spoof ]; then
	echo "[*] Installing default UCI config to /etc/config/sni-spoof"
	cp "$SRC_DIR/openwrt/config/sni-spoof" /etc/config/sni-spoof
else
	echo "[=] Keeping existing /etc/config/sni-spoof"
	# Backfill options added by newer versions, so an upgrade does not leave the
	# service reading defaults for settings the UI now exposes.
	for opt in no_bpf bind_interface; do
		uci -q get "sni-spoof.main.$opt" >/dev/null 2>&1 || \
			uci -q set "sni-spoof.main.$opt=0"
	done
	uci -q get sni-spoof.update >/dev/null 2>&1 || {
		uci -q set sni-spoof.update=update
		uci -q set sni-spoof.update.repo='iWebbIO/SNI-spoofing-anywhere'
		uci -q set sni-spoof.update.channel='release'
	}
	uci -q commit sni-spoof
fi

# ---- 5. procd service --------------------------------------------------------
echo "[*] Installing procd service"
cp "$SRC_DIR/openwrt/sni-spoof.init" /etc/init.d/sni-spoof
chmod +x /etc/init.d/sni-spoof
/etc/init.d/sni-spoof enable   # autostart on boot (the UCI 'enabled' flag gates running)

# ---- 6. LuCI UI (optional but installed if LuCI is present) ------------------
if [ -d /www/luci-static/resources ]; then
	echo "[*] Installing LuCI app (Services -> SNI Spoofing)"
	LUCI_SRC="$SRC_DIR/openwrt/luci-app-sni-spoof"
	cp -a "$LUCI_SRC/htdocs/." /www/
	cp -a "$LUCI_SRC/root/." /
	chmod +x /usr/libexec/rpcd/luci.sni-spoof 2>/dev/null || true
	# refresh ACLs + LuCI menu cache
	rm -f /tmp/luci-indexcache* 2>/dev/null || true
	/etc/init.d/rpcd reload 2>/dev/null || /etc/init.d/rpcd restart 2>/dev/null || true
else
	echo "[=] LuCI not detected — skipping web UI (CLI + UCI still work)."
fi

# ---- 7. Register with procd --------------------------------------------------
# `enable` alone only creates the boot symlink. procd does not learn about the
# service or its reload trigger until start_service has run once, so until a
# reboot a LuCI "Save & Apply" would commit the config and then do nothing at
# all. Starting here registers it immediately; if 'enabled' is 0 this is a
# no-op beyond that registration.
echo "[*] Registering the service with procd"
/etc/init.d/sni-spoof start || true

echo
echo "[+] Done  ($(cat "$PROG_DIR/VERSION"))"
echo "    Configure:  LuCI -> Services -> SNI Spoofing   (or edit /etc/config/sni-spoof)"
echo "    Then:       /etc/init.d/sni-spoof start   (Save & Apply in LuCI does this for you)"
echo "    Diagnose:   /etc/init.d/sni-spoof check   <-- run this first if it does not work"
echo "    Watch:      logread -e sni-spoof"
echo
echo "    Passwall2:  set a node's address/port to the listen address/port above,"
echo "                AND add connect_ip to Passwall2's direct/bypass list — without"
echo "                that, Passwall2 re-proxies the relay's own outbound connection"
echo "                and the desync can never fire. 'check' verifies this for you."
