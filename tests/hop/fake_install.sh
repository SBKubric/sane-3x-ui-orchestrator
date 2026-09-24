#!/usr/bin/env bash
# Stand-in for install.sh in proxy mode (tests of role hop only). Served by mock_panel.py as /install.sh.
# Records what the real installer would get (tag, PROXY_* environment, whether a token came), installs a
# fake x-ui into $FAKE_BOX_DIR and joins with the token through the mock panel, like `x-ui chain rejoin`.
set -euo pipefail
tag="$1"
box="${FAKE_BOX_DIR:?FAKE_BOX_DIR is not set}"
[[ "${XUI_PROXY_MODE:-}" == "1" ]] || { echo "XUI_PROXY_MODE is not 1" >&2; exit 1; }
[[ -n "${PROXY_NEXT_HOP:-}" ]] || { echo "PROXY_NEXT_HOP is required" >&2; exit 1; }
[[ -t 0 ]] && { echo "stdin must not be a TTY" >&2; exit 1; }
mkdir -p "$box"
echo "$tag" >>"$box/installs"
{
    for var in XUI_REPO PROXY_NEXT_HOP PROXY_NEXT_HOP_SUB_PORT PROXY_NEXT_HOP_SCHEME PROXY_SUB_PORT PROXY_DOMAIN \
        PROXY_TLS PROXY_CERT PROXY_KEY; do
        echo "${var}=${!var:-}"
    done
    echo "TOKEN_GIVEN=$([[ -n "${PROXY_JOIN_TOKEN:-}" ]] && echo yes || echo no)"
} >"$box/install.env"
echo "${tag#v}" >"$box/version"
cat >"$box/x-ui" <<'XUI'
#!/usr/bin/env bash
dir="$(dirname "$0")"
case "${1:-}" in
-v) cat "$dir/version" ;;
chain)
    [[ "${2:-}" == status ]] || exit 2
    [[ -s "$dir/joined" ]] || { echo "this box has not joined the chain yet"; exit 1; }
    read -r name role <"$dir/joined"
    # Same lines as proxy.PrintStatus; a "stale" file in the box makes the hop lose its next hop.
    reachable=true stale=""
    [[ -e "$dir/stale" ]] && reachable=false stale=" (stale — still relaying)"
    echo "name:      $name ($role)"
    echo "next hop:  $(sed -n "s/^PROXY_NEXT_HOP=//p" "$dir/install.env"):2096 (reachable: $reachable)"
    echo "revision:  1$stale"
    echo "relay:     running=true ports=[443]"
    echo "last wave: 2026-09-24T10:00:00Z"
    ;;
*) exit 2 ;;
esac
XUI
chmod 700 "$box/x-ui"
rm -f "$box/joined"
if [[ -n "${PROXY_JOIN_TOKEN:-}" ]]; then
    python3 - "$FAKE_PANEL/test/join" "$PROXY_JOIN_TOKEN" >"$box/joined" <<'PY'
import json, sys, urllib.request
req = urllib.request.Request(sys.argv[1], data=json.dumps({"token": sys.argv[2]}).encode(), method="POST")
obj = json.load(urllib.request.urlopen(req))["obj"]
print(obj["name"], obj["role"])
PY
    echo "Joined the chain as $(cat "$box/joined")"
fi
echo "x-ui $tag installed as a CHAIN HOP"
