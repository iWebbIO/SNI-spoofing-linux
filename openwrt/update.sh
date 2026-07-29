#!/bin/sh
# Update SNI-Spoofing from a GitHub release.
#
#   update.sh check          print JSON: installed vs latest release
#   update.sh apply [tag]    download, install, restart (defaults to latest)
#
# Backs the current install up first and rolls back if anything goes wrong, so a
# failed update over a flaky WAN cannot leave a router with a half-copied tree.
#
# The repository is read from UCI, never from an argument passed by the web UI,
# so the download URL cannot be steered by an HTTP request.

PROG_DIR=/opt/sni-spoof
BACKUP_DIR=/opt/sni-spoof.bak
LOG=/tmp/sni-spoof-update.log

REPO="$(uci -q get sni-spoof.update.repo || echo 'iWebbIO/SNI-spoofing-anywhere')"
API="https://api.github.com/repos/$REPO/releases/latest"

# A repo is "owner/name" — reject anything else outright rather than pasting it
# into a URL.
case "$REPO" in
	*/*) : ;;
	*) echo "invalid repo in UCI: $REPO" >&2; exit 2 ;;
esac
case "$REPO" in
	*[!A-Za-z0-9._/-]*) echo "invalid repo in UCI: $REPO" >&2; exit 2 ;;
esac

log() { echo "$*"; }

installed_version() {
	cat "$PROG_DIR/VERSION" 2>/dev/null || echo unknown
}

# Fetch a URL to stdout. OpenWrt images vary a lot in what they ship, so try the
# usual suspects in order of likelihood.
fetch() {
	url="$1"
	if command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O - "$url" 2>/dev/null && return 0
	fi
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" 2>/dev/null && return 0
	fi
	if command -v wget >/dev/null 2>&1; then
		wget -q -O - "$url" 2>/dev/null && return 0
	fi
	return 1
}

fetch_to_file() {
	url="$1"; out="$2"
	if command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O "$out" "$url" 2>/dev/null && [ -s "$out" ] && return 0
	fi
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$out" "$url" 2>/dev/null && [ -s "$out" ] && return 0
	fi
	if command -v wget >/dev/null 2>&1; then
		wget -q -O "$out" "$url" 2>/dev/null && [ -s "$out" ] && return 0
	fi
	return 1
}

# HTTPS on a minimal image needs both a TLS backend and a CA store. Say so
# plainly instead of failing with an opaque error, and never fall back to an
# unverified transfer — this downloads code that then runs as root.
tls_hint() {
	if [ ! -f /etc/ssl/certs/ca-certificates.crt ] && [ ! -d /etc/ssl/certs ]; then
		echo "HTTPS is unavailable: no CA certificates installed."
		echo "Fix with:  opkg update && opkg install ca-bundle libustream-mbedtls"
		echo "     (or)  apk update && apk add ca-bundle libustream-mbedtls"
	else
		echo "Could not reach GitHub. Check the router's DNS and internet access."
	fi
}

# Pull "tag_name": "vX.Y.Z" out of a release JSON body without needing jsonfilter.
tag_from_json() {
	printf '%s' "$1" \
		| tr ',' '\n' \
		| sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
		| head -1
}

latest_tag() {
	tag_from_json "$(fetch "$API" 2>/dev/null)"
}

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

cmd_check() {
	local_v="$(installed_version)"
	body="$(fetch "$API" 2>/dev/null)"

	# An empty body means the request itself failed; a body without a tag_name
	# means the repo simply has no published releases yet. Those need different
	# advice, so do not collapse them into one "update check failed".
	if [ -z "$body" ]; then
		printf '{"installed":"%s","latest":"","update_available":false,"error":"%s"}\n' \
			"$(json_escape "$local_v")" "$(json_escape "$(tls_hint | head -1)")"
		return 1
	fi

	remote_v="$(tag_from_json "$body")"
	if [ -z "$remote_v" ]; then
		printf '{"installed":"%s","latest":"","update_available":false,"error":"%s"}\n' \
			"$(json_escape "$local_v")" \
			"$(json_escape "$REPO has no published releases yet, so there is nothing to update to. Create a release on GitHub (tag it, e.g. v1.1.0) and this button will find it.")"
		return 1
	fi

	if [ "$local_v" = "$remote_v" ]; then
		avail=false
	else
		avail=true
	fi
	printf '{"installed":"%s","latest":"%s","update_available":%s,"repo":"%s"}\n' \
		"$(json_escape "$local_v")" "$(json_escape "$remote_v")" "$avail" \
		"$(json_escape "$REPO")"
}

rollback() {
	log "[!] Update failed — rolling back to the previous install."
	if [ -d "$BACKUP_DIR" ]; then
		rm -rf "$PROG_DIR"
		mv "$BACKUP_DIR" "$PROG_DIR"
		log "[+] Restored $PROG_DIR from backup."
	else
		log "[!] No backup present; $PROG_DIR left as-is."
	fi
	/etc/init.d/sni-spoof restart >/dev/null 2>&1 || true
}

cmd_apply() {
	tag="$1"
	[ -n "$tag" ] || tag="$(latest_tag)"
	if [ -z "$tag" ]; then
		log "[!] No release tag available for $REPO."
		log "    Either the router cannot reach GitHub, or the repository has no"
		log "    published releases yet. Tag one (e.g. v1.1.0) and publish it."
		tls_hint
		return 1
	fi
	# The tag reaches a URL, so keep it to what a git tag may sanely contain.
	case "$tag" in
		*[!A-Za-z0-9._-]*) log "[!] Refusing suspicious release tag: $tag"; return 2 ;;
	esac

	local_v="$(installed_version)"
	log "[*] Updating $REPO: $local_v -> $tag"

	tmp="$(mktemp -d /tmp/sni-spoof-update.XXXXXX)" || return 1
	# shellcheck disable=SC2064
	trap "rm -rf '$tmp'" EXIT INT TERM

	url="https://codeload.github.com/$REPO/tar.gz/refs/tags/$tag"
	log "[*] Downloading $url"
	if ! fetch_to_file "$url" "$tmp/src.tar.gz"; then
		log "[!] Download failed."
		tls_hint
		return 1
	fi
	log "[*] Downloaded $(wc -c < "$tmp/src.tar.gz") bytes"

	mkdir -p "$tmp/x"
	if ! tar -xzf "$tmp/src.tar.gz" -C "$tmp/x" 2>/dev/null; then
		log "[!] Archive is corrupt or not a gzip tarball."
		return 1
	fi

	# GitHub wraps everything in a single <repo>-<sha> directory.
	src="$(find "$tmp/x" -maxdepth 1 -mindepth 1 -type d | head -1)"
	if [ -z "$src" ] || [ ! -f "$src/main.py" ] || [ ! -f "$src/openwrt/install.sh" ]; then
		log "[!] Downloaded archive does not look like this project — aborting."
		log "    (expected main.py and openwrt/install.sh at its root)"
		return 1
	fi
	log "[*] Extracted to $src"

	# Back up before touching anything installed.
	rm -rf "$BACKUP_DIR"
	if [ -d "$PROG_DIR" ]; then
		cp -a "$PROG_DIR" "$BACKUP_DIR" || { log "[!] Backup failed — aborting."; return 1; }
		log "[*] Backed up current install to $BACKUP_DIR"
	fi

	# The release carries its own installer; use it so an update applies exactly
	# the same steps as a fresh install.
	echo "$tag" > "$src/VERSION"
	if ! sh "$src/openwrt/install.sh"; then
		rollback
		return 1
	fi

	# The installer verifies the runtime, but not that this build actually runs.
	if ! python3 -c "import sys; sys.path.insert(0, '$PROG_DIR'); import fake_tcp, injecter, engines" \
		>/dev/null 2>&1; then
		log "[!] The new version failed its import check."
		rollback
		return 1
	fi

	rm -rf "$BACKUP_DIR"
	log "[*] Restarting the service"
	/etc/init.d/sni-spoof restart >/dev/null 2>&1 || true
	rm -f /tmp/luci-indexcache* 2>/dev/null
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true

	log "[+] Updated to $(installed_version)"
	return 0
}

case "$1" in
	check)
		cmd_check
		;;
	apply)
		# Tee to a log the LuCI page can show after the request completes.
		{ cmd_apply "$2"; echo "EXIT:$?"; } 2>&1 | tee "$LOG"
		grep -q '^EXIT:0$' "$LOG"
		;;
	version)
		installed_version
		;;
	*)
		echo "usage: $0 {check|apply [tag]|version}" >&2
		exit 2
		;;
esac
