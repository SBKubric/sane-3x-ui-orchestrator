# 3ax-ui-orchestrator

Ansible that deploys a whole 3ax-ui installation from an inventory: the panel
([SBKubric/sane-3x-ui](https://github.com/SBKubric/sane-3x-ui)), its proxy chain hops, and
monitoring ([SBKubric/3ax-ui-monitoring](https://github.com/SBKubric/3ax-ui-monitoring): mon-server and
mon-client). Design: [SBKubric/3ax-ui-monitoring#55](https://github.com/SBKubric/3ax-ui-monitoring/issues/55).

> Status: roles `common`, `panel`, `hop`, `monserver` and `monclient`, `wipe.yml` and `verify.yml` are real;
> the first full stand run (`wipe.yml` + `site.yml` of `stand-full` to a green `verify.yml`) is #5. The default
> profile is [«only 443»](#front-only-443) (#21).

## Layout

```
ansible.cfg            roles path, root over ssh, no default inventory
requirements.txt       ansible-core + ansible-lint (pinned)
requirements.yml       collections (pinned)
site.yml               converge: common -> panel -> hops -> panel inbounds again -> monserver -> monclient -> verify.yml
wipe.yml               destroy state for a fresh start; refuses without -e wipe_confirm=yes
                       (steps: roles/<role>/tasks/wipe.yml)
verify.yml             non-destructive checks; also imported last by site.yml (tag verify)
                       (steps: roles/<role>/tasks/verify.yml)
group_vars/all/        vault.yml (git-ignored, yours) and vault.yml.example (template)
inventories/
  stand-chain/         panel + hops; monserver/monclient empty
  stand-full/          panel + hops + monserver + monclient
roles/
  common/              supported OS check, base packages, time sync; tasks/verify_front.yml + files/portscan.py:
                       verify.yml's «only 443» check from the controller
  panel/               install by tag, self-signed TLS, vault account, Telegram, monitoring token, geosite
                       ru-inside dropped (tasks/ru_inside.yml + files/ru_inside.py, the daily refresh), inbounds
                       from panel_inbounds, the «only 443» front (tasks/front.yml); tasks/api_login.yml is the
                       panel API login helper for other roles
  hop/                 chain registry converged with group hops through the panel API; install + join;
                       neighbour target of every edge (files/neighbour.py: scan + Reality handshake check)
  monserver/           release binary, bootstrap config, unit, admin account, Settings via the admin API;
                       tasks/api_login.yml is the mon-server admin API login helper for other roles
  monclient/           release binaries (mon-client, xray), unit, LE staging roots, pairing auto-approval
tests/hop/             role hop and the chain part of verify.yml against a mock of the panel API, and
                       neighbour.py against a fake scanner, fake xray and local sites (CI)
tests/panel/           role panel's inbounds, its «only 443» front, geosite ru-inside (with a local source of the
                       list) and the targets part of verify.yml against the same mock and local fakes (CI)
tests/monserver/       role monserver's Settings against a mock of mon-server's admin API, verify's probe links (CI)
tests/common/          verify.yml's «only 443» check (port scan, cover page, API login) on local listeners (CI)
tests/wipe/            wipe.yml on local stand-in boxes (CI)
```

## Profiles

A profile is an inventory. Every profile has the groups `panel` (one host), `hops`, `monserver`
(zero or one host) and `monclient`; `site.yml` has one play per group, and an empty group is simply
skipped. So the chain-only profile is the full one with empty monitoring groups.

| Profile | Groups filled | Use |
|---|---|---|
| `inventories/stand-chain` | panel, hops | panel + proxy chain only |
| `inventories/stand-full` | panel, hops, monserver, monclient | panel + chain + monitoring |

Inventory hostnames are ssh aliases (`real`, `bridge`, `proxy`, `monserver`, `monclient`); put them into
`~/.ssh/config` with `HostName`, `User root` and the key. No addresses or secrets are committed; public
addresses come from facts (default IPv4) unless overridden in `host_vars`.

### Variables

Profile-wide (`inventories/<profile>/group_vars/all/main.yml`):

| Variable | Meaning |
|---|---|
| `xui_version` | release tag of sane-3x-ui for the panel and every hop (`install.sh <xui_version>`) |
| `mon_version` | release tag of 3ax-ui-monitoring for mon-server and mon-client |
| `acme_production` | `false` = Let's Encrypt staging for mon-server (default); hops always use production LE |
| `mon_auto_approve` | approve mon-client pairing requests through the mon-server admin API |
| `front_mode` | `only443` (default) or `off`: the profile «only 443» on the panel and every hop, see [Front: only 443](#front-only-443) |

Per hop (`inventories/<profile>/host_vars/<hop>.yml`); the inventory is the source of truth for the
panel's chain registry:

| Variable | Meaning |
|---|---|
| `hop_role` | `inner` or `edge` |
| `hop_position` | order of inner hops, 1 = next to the panel |
| `hop_active` | `true` on exactly one edge hop |
| `hop_name` | name in the chain registry (default: inventory hostname) |
| `hop_next` | next hop inward; empty = derived (edge -> outermost inner, inner N -> N-1, inner 1 -> panel) |
| `hop_tls` | `PROXY_TLS` for install.sh: `letsencrypt-ip` (default), `none`, `manual` |
| `hop_reality_target` | edge only, optional: its neighbour target as `host:port` instead of the scan, see [Neighbour target](#neighbour-target) |
| `hop_reality_server_name` | server name for `hop_reality_target` (required when its host is an address; default: the host) |

Panel inbounds (`inventories/<profile>/group_vars/panel.yml`), see [Inbounds](#inbounds):

| Variable | Meaning |
|---|---|
| `panel_inbounds` | inbounds of the panel, matched by `remark`; missing ones are added, declared fields that differ are updated, others are left alone |

Per mon-client (`host_vars`, optional): `mon_name`, `mon_region`, `mon_paths`, `mon_gomemlimit`; group
`monclient`: `mon_xray_version`. Role-internal knobs live in each role's `defaults/main.yml`.

## Role panel

Runs on the single host of group `panel` (decision #55, items 2, 5, 7). Every step converges and is
skipped when the host already matches, so a second run reports `changed=0`.

1. **TLS.** `community.crypto` makes an ECDSA P-256 key, a CSR and a self-signed certificate
   (10 years, `CA:TRUE`, SANs `IP:<panel_public_ip>` and `IP:127.0.0.1`) in `/etc/x-ui/tls/`. They are
   created once; a new public IP (the SAN changes) re-issues the certificate and restarts the panel.
   `x-ui setting -getCert` must point at these files, otherwise `x-ui cert -webCert -webCertKey` fixes it.
2. **Install / update.** `x-ui -v` equal to `xui_version` (without the `v`) → nothing to do. Otherwise
   `install.sh <xui_version>` (taken from the same tag of `SBKubric/sane-3x-ui`, `XUI_REPO` set) runs with
   its answers on stdin: debug mode `N`, custom port `n`, SSL option `3`, empty domain, certificate path,
   key path. On an existing panel install.sh (no TTY + explicit tag) reinstalls that tag and keeps the
   database; the certificate is written into the settings first, so it asks nothing but the debug
   question. The installed version is checked afterwards.
3. **Account.** `x-ui setting -show` (port, web base path, `hasDefaultCredential`) differs from the vault
   → `x-ui setting -username -password -port -webBasePath` and a restart. Then the role logs in with the
   vault account; a failed login (user or password changed by hand) resets them with `x-ui setting`.
4. **Telegram** (when `tg_bot_token`/`tg_chat_id` are set). Current values are read through the API
   (`POST <base>panel/setting/all`, read-only); on a difference `x-ui setting -tgbottoken -tgbotchatid
   -enabletgbot` and a restart. `panel/setting/update` is never used: it zeroes the fields it is not given.
   Empty vault values leave the panel's Telegram settings alone.
5. **Monitoring** (only when group `monserver` is not empty). `x-ui setting -showMonToken`; `-monEnable true`
   if it is off, `-resetMonToken` only when it says `(not issued)`, so a running mon-server keeps its token.
   The token is read back every run and never stored in the vault.
6. **geosite ru-inside** (`panel_ru_inside_enabled`, on by default): the list of sites reachable only from inside
   Russia, kept fresh on the box by a daily timer, and a routing rule in the panel's Xray template that drops the
   clients' traffic to them, see [Blocking ru-inside](#blocking-ru-inside).
7. **Inbounds** from `panel_inbounds` through the panel API, see [Inbounds](#inbounds). This runs before the
   hops play, so hops that join in the same run find the relayed ports in the chain document.
8. **Front «only 443»** (`front_mode: only443`, the default), after the inbounds: the Let's Encrypt IP certificate,
   fail2ban, `webListen` 127.0.0.1 and `chainPanelHost`, then the panel's nginx front with its firewall, see
   [Front: only 443](#front-only-443).

Secrets never reach the output: the tasks that carry the password, the Telegram token, the monitoring
token or the session cookie are `no_log`. install.sh prints random credentials of its own; they are
replaced right after the install.

Facts left on the panel host for later plays (`hostvars[groups['panel'][0]]`):

| Fact | Value | Used by |
|---|---|---|
| `panel_url` | `https://<panel_public_ip><panel_base_path>` (443) behind the front, else `https://<panel_public_ip>:<panel_port><panel_base_path>` | hop, monserver (`panelUrl`), verify |
| `panel_ca_pem` | empty behind the front (the IP certificate is publicly trusted), else the PEM of the self-signed certificate | monserver (`panelCa`) |
| `panel_mon_token` | monitoring bearer token (only with a `monserver` host) | monserver (`monToken`) |

The facts exist only in a run that includes the panel play (`--tags panel` or a full run).

### Inbounds

`panel_inbounds` lists the inbounds the panel must have; nothing else about the panel's inbounds is
assumed. Each entry:

| Field | Meaning |
|---|---|
| `remark` | name of the inbound, unique; the match key between the inventory and the panel (required) |
| `protocol` | xray protocol (`vless`, `vmess`, `trojan`, `shadowsocks`, ...) or `amneziawg` (required; `nativewg` and `mtproto` are not managed) |
| `port` | listen port (required for xray). For `amneziawg`: the AWG server's UDP port; default: the random port the panel picked |
| `enable` | default `true`; for `amneziawg` it switches the inbound and the AWG server |
| `followChain` | `true`: the inbound follows the chain (Reality only). The panel sets its Reality `target`, `serverNames` and `settings.serverName` to the active edge's neighbour target on every switch; while an edge is active the role therefore leaves those three to the panel and converges the declared ones only while no edge is active. With an active edge that has no neighbour target yet the panel refuses the flag: the role converges the rest, warns, and flags it in the second pass of `site.yml` after role hop wrote the target |
| `listen`, `total`, `expiryTime`, `trafficReset` | as in the panel (xray only); not declared = left as the panel has it (on add: `""`, `0`, `0`, `never`) |
| `settings`, `streamSettings`, `sniffing` | mappings (xray only) merged key by key into the panel's JSON of the same name; keys the entry does not name stay as the panel has them, lists are replaced. `settings.clients` is refused: users are added in the panel, the monitoring probe client by the panel itself. A declared `streamSettings.network` drops the panel's settings of every other transport (`tcpSettings` when moving to `xhttp`), and on a VLESS inbound whose network is not `tcp` the clients' `flow` is cleared (Vision is TCP only); their ids, emails and subIds stay. `sniffing` not declared on add = the UI default |

The converge, on the panel host (`POST <base>login`, then `panel/api/...`):

1. `GET inbounds/list`. Refused before anything is written: two panel inbounds with one declared remark,
   a declared remark whose panel inbound has another `protocol` (delete it in the panel first), an
   `amneziawg` entry while the panel's AWG inbound has another remark (one per panel). Malformed entries
   (missing fields, unknown fields, wrong types) are refused before the login.
2. **AmneziaWG server** (with an `amneziawg` entry). The panel keeps one server and makes it with its keys,
   obfuscation and a random port (install.sh already reads it). `GET awg/server`; when `enable` or the port
   differs, or the AWG inbound record lags behind the server's port, `POST awg/server` with the server as
   read plus `enable`/`listenPort` — the keys are sent back unchanged, never regenerated. The save
   brings the interface up, moves the AWG inbound record to the port and bumps the chain revision.
3. **Per entry**, matched by `remark`:
   - missing, xray: `POST inbounds/add` with `settings` (`clients: []` added), `streamSettings`, `sniffing` as
     JSON strings. With `streamSettings.security: reality` and no `realitySettings.privateKey`, the keys come
     from the panel's generator (`GET server/getNewX25519Cert`: `realitySettings.privateKey` and
     `realitySettings.settings.publicKey`); without `realitySettings.shortIds` one random 16-hex-digit shortId
     is made. This happens only on add.
   - missing, `amneziawg`: `POST inbounds/add`, a bare record on the server's port (peers live in the AWG
     tables; the panel adds the monitoring probe peer itself).
   - present, xray: the declared top-level fields replace the panel's, the declared mappings are merged into
     the parsed JSON; only when that changes something, `POST inbounds/update/<id>` sends the whole inbound
     as the panel has it with the merge applied. The JSON is compared parsed, never as text: the panel
     re-serializes it (indentation, client timestamps, the probe client monitoring adds), and all of that,
     the Reality keys and shortIds included, survives the update.
   - present, `amneziawg`: `POST inbounds/setEnable/<id>` when `enable` differs.

A second run reports `changed=0`. Nothing generated is stored in the inventory or the vault; the keys live
in the panel and are only read back. Check mode (`--check`) reads the panel and prints the plan
(`inbound vless-reality (vless): add`, `AmneziaWG server: save`) without writing. Every API call is
`no_log` (private keys, the session cookie).

The chain: adding, updating or switching an inbound (and saving the AWG server) makes the panel recompute
the relayed ports (`x-ui chain ports`: enabled xray inbounds as TCP, the enabled AWG server as UDP) and bump
the chain revision when the registry has hops. Hops that join afterwards get the ports with their first
document; joined hops pick them up on their next poll (`chainPollSeconds`, 30 s ±20 %, one poll per hop
from the panel outward) and restart the relay. verify.yml waits up to 2 minutes for that.

Port 443 is not available for an inbound while the panel's nginx front is on (`nginxMode` other than `off`;
install.sh sets `shared`): nginx owns the public port and the panel refuses the add with "Port already
exists: 443". The stand inventories therefore put VLESS-Reality on 8443; behind the only443 front the panel moves it to
`127.0.0.1:8443` (it keeps the port number, `listen` and `publicPort` are the panel's) and publishes it on 443, which is
the port its links carry. The role never declares `listen`, so it does not fight that move.

**VLESS + XHTTP + Reality.** The stand's inbound is XHTTP, not TCP + Vision (ADR 0005): `xhttpSettings` `path: /`,
`host: ""`, `mode: auto`. `auto` lets the server take every XHTTP mode and each client pick its own (an xray-core
client picks `stream-one` with Reality); the path is not a secret, Reality authenticates first. Clients built on
xray-core with XHTTP (v2rayNG, v2rayN, Hiddify's xray core; the panel and mon-client run xray 26.3.27) connect; check a
sing-box-based client for XHTTP support before relying on it (upstream sing-box did not have the transport when this
was written). The migration from the TCP + Vision inbound happens in place on the first run (matched
by remark): same keys, same clients, their Vision flow cleared, a new link for each client (`type=xhttp`, port 443,
the active edge's server name) that they get by refreshing the subscription.
The Reality `target` must be a site Xray's Reality can borrow a handshake from: with Xray 26.3.27 and the
`chrome` fingerprint, `www.microsoft.com` fails every handshake ("REALITY: processed invalid connection ...
handshake did not complete successfully") while `dl.google.com`, `github.com` and `www.samsung.com` work; the
stand uses `dl.google.com`.

Example (`inventories/stand-full/group_vars/panel.yml`):

```yaml
panel_inbounds:
  - remark: vless-reality
    protocol: vless
    port: 8443                    # behind the front: 127.0.0.1:8443, published on 443
    followChain: true             # target/serverNames follow the active edge's neighbour
    settings:
      decryption: none
      fallbacks: []
    streamSettings:
      network: xhttp
      security: reality
      realitySettings:            # privateKey, settings.publicKey and shortIds are made on add
        show: false
        xver: 0
        target: dl.google.com:443 # until an edge is active
        serverNames: [dl.google.com]
        settings:
          fingerprint: chrome
          serverName: ""
          spiderX: /
      xhttpSettings:
        path: /
        host: ""
        mode: auto
    sniffing:
      enabled: true
      destOverride: [http, tls, quic]
      metadataOnly: false
      routeOnly: false
  - remark: awg
    protocol: amneziawg
    port: 51820
```

Monitoring: mon-server's periodic `probe/ensure` gives every enabled xray inbound a probe client and the
AWG server a probe peer as soon as an `amneziawg` inbound exists, so both become targets on every
mon-client path (`xray:<id>` and `awg:0`).

Knobs in `roles/panel/defaults/main.yml`: `panel_public_ip` (default IPv4 from facts; set it in
`host_vars` behind NAT), `panel_cert_sans`, `panel_cert_valid_days`, `panel_tls_dir`,
`panel_install_ref`/`panel_install_url`, `panel_install_timeout`.

### Blocking ru-inside

Clients of the panel get no answer from the sites of `geosite:ru-inside`
([golukon/russia-only-geosite](https://github.com/golukon/russia-only-geosite): sites reachable only from inside
Russia; one `geosite.dat` of about 13 KB, released daily at about 03:30 UTC): a routing rule of the panel's Xray
template sends them to the `blocked` blackhole outbound, a silent drop. Only the panel: the hops relay TCP/UDP and never
see a domain. The rule matches the domain a client asks for, or the one xray sniffs (the stand's inbound sniffs
http/tls/quic); a client that resolves the name itself and sends only an IP to an inbound without sniffing passes.

On the panel host (`tasks/ru_inside.yml`):

- **The list.** `/usr/local/sbin/3ax-ru-inside refresh` (`files/ru_inside.py`, settings in `/etc/3ax-ru-inside.json`)
  downloads `geosite.dat.sha256sum` and `geosite.dat`, checks the sha256, the size (`panel_ru_inside_min_bytes` ..
  `panel_ru_inside_max_bytes`) and that the file has the category `ru-inside`, and replaces
  `/var/lib/3ax-ru-inside/ru-inside.dat` atomically when the content differs (a current list only gets its mtime
  touched: the file's age is the time since the last good check). `/usr/local/x-ui/bin/ru-inside.dat`, in xray's
  asset folder, is a link to it: install.sh deletes `/usr/local/x-ui` with that folder on every (re)install, so the
  list lives outside it and a drop-in of `x-ui.service` (`ExecStartPre=-3ax-ru-inside ensure`) puts the link back
  before the panel starts xray. The name is neither one of the panel's geo files nor `geosite_<alias>.dat`/
  `geoip_<alias>.dat` of its custom geo resources.
- **The timer.** `3ax-ru-inside.timer` runs the same refresh daily (`panel_ru_inside_on_calendar`, 05:00 UTC, with
  `panel_ru_inside_randomized_delay` 1h; `Persistent=true`), and restarts xray (`systemctl reload x-ui`, what
  `x-ui restart-xray` does) only when the list changed. A failed download or check keeps the old list; the reason is
  in `journalctl -u 3ax-ru-inside` and the service is `failed` (exit 3) until the next good run.
- **Every run** of `site.yml` refreshes the list the same way. A box that cannot fetch it (no GitHub), or gets a list
  that fails a check, gets it from the controller: `get_url` downloads it there against the same sum file, and the
  script on the box checks it again and installs it. With neither, the old list stays with a `WARNING`; with no list
  at all there is no rule (xray does not start on an `ext:` rule whose file is missing), and a rule left from before
  is taken out.
- **The rule.** `{"type": "field", "ruleTag": "3ax-ru-inside", "domain": ["ext:ru-inside.dat:ru-inside"],
  "outboundTag": "blocked"}`, right after the panel's `api` rule (the panel keeps that one first), read and saved
  through `POST <base>panel/xray/` and `panel/xray/update` with the rest of the form as it was. Other rules and
  outbounds stay; the rule is found by its `ruleTag`, or by its domain entry when the panel's routing editor dropped
  the tag, and there is exactly one. A missing `blocked` outbound is added as a blackhole; one with another protocol
  stops the run. After a save xray is restarted through the panel (`panel/api/server/restartXrayService`); if it
  does not come up, the previous template goes back and the run fails. A new list under an unchanged rule only
  restarts xray.

`panel_ru_inside_enabled: false` takes the rule out and stops the timer (the files stay until `wipe.yml`). The URLs,
file name, schedule and limits are `panel_ru_inside_*` in `roles/panel/defaults/main.yml`. `verify.yml` checks the
rule, the list and the timer, and warns when the list's last good check is older than `panel_ru_inside_max_age_days`
(3).

### Panel API from other roles

`roles/panel/tasks/api_login.yml` logs in (`POST <base>login`, form `username`/`password`) and keeps the
session cookie. The API is reached on the panel host itself (`https://127.0.0.1:<port><base>`, verified
against the self-signed certificate), so calls are delegated there:

```yaml
- name: Log in to the panel
  ansible.builtin.include_role:
    name: panel
    tasks_from: api_login

- name: List chain hops
  ansible.builtin.uri:
    url: "{{ panel_api_url }}panel/api/chain/list"
    headers:
      Cookie: "{{ panel_api_cookie }}"
    ca_path: "{{ panel_api_ca_path }}"
    return_content: true
  delegate_to: "{{ panel_api_host }}"
```

It sets `panel_api_cookie`, `panel_api_url`, `panel_api_host`, `panel_api_ca_path` and
`panel_api_logged_in` on the calling host and fails on a wrong login unless `panel_api_login_required:
false` is passed. Wrong credentials are HTTP 200 with `success: false`; API paths answer 404 without a
session.

## Role hop

Runs on the hosts of group `hops` (decision #55, items 3 and 5). The inventory is the source of truth for
the panel's chain registry. Each hop host checks its variables and reads its box in parallel (`x-ui -v`,
`x-ui chain status`); then the first host of the play converges the registry for the whole chain, one hop
after another from the panel outward (inner hops by `hop_position`, then the edges), because an outer hop
joins through its inner neighbour. Registry calls go through role panel's `api_login` helper (on the panel
host); box operations run on each hop host.

Per hop, against `GET panel/api/chain/list`:

| Registry / box | Action |
|---|---|
| no hop of that name | `add {name, host, role, subPort, subScheme, position}` → install with the join token |
| `joined`, same host / sub port / scheme (behind the front: 443/https, see below), `x-ui chain status` answers with this name, `x-ui -v` = `xui_version` (a leading `v` on either side is ignored), the front in `proxy.json` = `front_mode` | nothing |
| anything else (pending, broken box, other version, new host, other front) | `update` of what changed → `reissueToken` → install |

The plan line names why a hop re-joins, e.g. `proxy=rejoin (subScheme http -> https)`.

Install = `install.sh <xui_version>` from the same tag with `XUI_PROXY_MODE=1`, `PROXY_NEXT_HOP`,
`PROXY_NEXT_HOP_SUB_PORT`/`_SCHEME`, `PROXY_SUB_PORT`, `PROXY_TLS`, `PROXY_FRONT` (`front_mode`),
`PROXY_JOIN_TOKEN`; without a TTY and with an explicit tag install.sh reinstalls that tag and joins before the
service starts. The role then waits for the registry to report the hop `joined` and checks the installed version.

**Behind the front** (`front_mode: only443`, needs `hop_tls: letsencrypt-ip`): install.sh writes `"front": {"mode":
"only443"}` to `proxy.json` and installs fail2ban; the box's front comes up with the IP certificate, and its polls
report it (`X-Chain-Front`), so the panel moves the hop to **443/https** in the registry. The role therefore never
pushes `hop_sub_port`/`hop_sub_scheme` to the registry of a hop behind its front (they stay the box's own sub server,
behind nginx) and waits, after each install, up to `hop_front_retries` x `hop_front_delay` (3 minutes) for that report
before it converges the next hop outward; a hop that does not report stops the run there. A box whose `proxy.json`
names another front than `front_mode`, or whose registry entry is not 443/https, re-joins (`front off -> only443`,
`front not reported`).

The next hop of the box is `hop_next` when set, otherwise derived: the inward neighbour's host, sub port
and scheme as registered, or the panel for the innermost hop (`hop_panel_host`, else the host of
`panel_url`, else `panel_public_ip` from the panel's `host_vars`, else its default IPv4; sub port
`hop_panel_sub_port`: 443 behind the panel's front, else 2096).

After the loop: the [neighbour target](#neighbour-target) of every edge, then `setActive` on the edge with `hop_active: true` (exactly one edge must carry it, asserted
before anything is written), then `del` of every registry hop the inventory does not list — the imported
`legacy` edge included. Edges go first, inner hops from the outside in; an inner that still has live outer
neighbours is left `draining` by the panel. The active edge is only deleted when the inventory has no edge
at all, and then with `force` (the panel publishes the real server address again). `hop_prune: false`
only reports the extra hops.

What the role refuses instead of guessing (fix it in the panel, then rerun): a hop whose role differs
from the registry, a hop that is `draining`, inner hops registered in another order than `hop_position`
(role and position cannot change through `update`). With `--limit` only the hosts in the limit are
converged; hops outside it are never deleted. Check mode (`--check`) logs in, reads the registry and the
boxes and prints the plan (`hops: bridge=add, proxy=skip; active edge: proxy; delete: legacy`) without
writing anything.

Secrets: the join token and the session cookie never reach the output (`no_log` on every API call). The
token goes to the box as a root-only file that the install wrapper reads and deletes before install.sh
starts, so it is neither in the task arguments nor in the environment ansible sends; the install output is
shown with the token masked.

**Let's Encrypt on hops.** `hop_tls: letsencrypt-ip` (default) gets a production LE certificate for the
box IP (short-lived, renewed by acme.sh from cron; port 80 must stay free). A converged hop is skipped, so
the certificate is issued once per box; a reinstall of a box that still holds a valid certificate for its
`hop_host` hands it to install.sh as `PROXY_TLS=manual` instead of issuing a new one (`hop_tls_reuse`), and
`wipe.yml` keeps that certificate unless `hop_wipe_le_cert=true`. A new box, a new address or a wipe with
`hop_wipe_le_cert=true` costs a new certificate: **issuing for one hop more than 4 times a week is not
supported** (LE limits on duplicate certificates). `hop_tls: none` (plain HTTP sub port) and `manual`
(`hop_cert`/`hop_key` on the box) avoid LE.

Variables beyond the per-hop table above (`roles/hop/defaults/main.yml`): `hop_host` (registered address,
default IPv4 from facts), `hop_sub_port`/`hop_sub_scheme` (2096, `https` or `http` with `hop_tls: none`),
`hop_domain` (`PROXY_DOMAIN`), `hop_next_sub_port`/`hop_next_sub_scheme` (for an explicit `hop_next`),
`hop_panel_host`/`hop_panel_sub_port`/`hop_panel_sub_scheme`, `hop_install_environment` (extra install.sh
environment, e.g. `PROXY_TLS_IPV6`), `hop_install_timeout`, `hop_join_retries`/`hop_join_delay`,
`hop_prune`, `hop_tls_reuse`, `hop_front_mode` (default `front_mode`), `hop_front_retries`/`hop_front_delay`.

### Neighbour target

Every edge carries a **neighbour target** in the chain registry (`realityTarget`, `realityServerName`;
SBKubric/sane-3x-ui [ADR 0005](https://github.com/SBKubric/sane-3x-ui/blob/main/docs/adr/0005-only-443-on-every-hop.md),
panel `v1.9.0-chain.8`+): a real site in the same /24 as the edge's address. While the edge is active, the
Reality inbounds that follow the chain imitate that site, and an unknown SNI on the edge is passed to it, so
a prober sees the neighbour's site. The role picks it after converging the hops and before `setActive`
(the panel refuses to activate an edge without one while inbounds follow the chain), per managed edge:

| Situation | What happens |
|---|---|
| `hop_reality_target` set in the edge's `host_vars` | no scan; written as given (server name `hop_reality_server_name`, else the host); a failed handshake check prints a `WARNING` but does not stop the run |
| the registry already holds a target in the edge's /24 and it passes the handshake check | nothing: no scan, no write (`changed=0`) |
| otherwise (no target, the check fails, the fallback, a former override, the edge moved) | scan, write the best candidate that passes the handshake check |
| the scan finds nothing that passes | `hop_reality_fallback_target` (`dl.google.com:443`, passed the xray 26.3.27 handshake in SBKubric/sane-3x-ui#129) and a `WARNING`; the next run scans again |

How the scan works (`roles/hop/files/neighbour.py find`, all **on the controller**, `delegate_to: localhost`,
never on a box: a VPS scanning its neighbours gets flagged):

1. [XTLS RealiTLScanner](https://github.com/XTLS/RealiTLScanner) probes the addresses of the edge's /24
   nearest to it first (the edge, `.0` and `.255` left out): at most `hop_neighbour_scan_limit` (254),
   `hop_neighbour_scan_threads` (8) at a time, `hop_neighbour_scan_timeout` (4) seconds each, on
   `hop_neighbour_port` (443). It keeps sites that answer **TLS 1.3 with ALPN h2 and X25519** (or the hybrid
   X25519MLKEM768).
2. The certificate name becomes the server name (a wildcard `*.example.com` stands for `www.example.com`; an
   address or a bare `*` is dropped). The site must answer **TLS 1.3 + h2 again with that name as SNI**, and
   `GET /` for that name must **not redirect to another host**.
3. **Not a CDN**, two ways: the HTTP answer carries no CDN headers (Cloudflare `cf-ray`/`server: cloudflare`,
   CloudFront `x-amz-cf-*`/`via: ... cloudfront`, Fastly `x-fastly-request-id`/`x-served-by: cache-...`,
   Akamai `server: AkamaiGHost`/`x-akamai-*`), and the site's AS, looked up in
   [Team Cymru's](https://www.team-cymru.com/ip-asn-mapping) bulk whois (`hop_neighbour_asn_whois`,
   `whois.cymru.com:43`, TCP 43 outbound), is not in `hop_neighbour_cdn_asns` (Cloudflare, Fastly, Akamai; the
   whole AWS AS is not listed, so CloudFront is caught by its headers). When the whois does not answer, the run
   notes it and filters by headers only.
4. Ranking: a 2xx answer first, then the nearest address. The best `hop_neighbour_confirm` (3) get the
   **Reality handshake check**, the first that passes wins.

The handshake check (`neighbour.py check`, also used on a stored target and on `hop_reality_target`) runs a
pair of xray processes on the controller's loopback, as in SBKubric/sane-3x-ui#129: a VLESS + Vision + Reality
server whose target is the candidate and whose `serverNames` is its name, and a client through it; it passes
when all `hop_neighbour_check_tries` (3) fetches of `hop_neighbour_probe_url`
(`https://www.cloudflare.com/cdn-cgi/trace`) through the tunnel succeed. xray is the panel's version,
`hop_neighbour_xray_version` (`v26.3.27`).

The run prints one line per edge, e.g. `neighbour target of proxy (170.168.112.0/24): 170.168.112.32:443
(ru.zian.ru.net) from scan; scanned 253 addresses, 16 candidates, handshakes: 170.168.112.32:443 3/3 through
the tunnel`. `verify.yml` shows each edge's target and warns (without failing) about an edge on the fallback
or without a target. `hop_neighbour_enabled: false` leaves the registry fields alone.

**Controller requirements.** Linux on x86_64 or aarch64 (the operator's `o1-ansible` container, root with
`--network host`, works as is), the controller's Python (standard library only), and outbound access to
GitHub (first run only), TCP 443 of the edge's /24, TCP 43 of `whois.cymru.com` and the probe URL. No Docker,
curl or unzip is needed: RealiTLScanner (`hop_neighbour_scanner_version`, `v0.2.3`) and xray are release
binaries downloaded once into `hop_neighbour_cache` (`<playbook dir>/.cache/neighbour`, git-ignored, so the
download survives a throwaway container that mounts the repo) and checked against the sha256 pinned in
`hop_neighbour_downloads`. A new version means a new pin there. `hop_neighbour_scanner_bin` /
`hop_neighbour_xray_bin` point at binaries of your own instead. A full /24 takes about a minute (73 s with 4
threads around the stand's `proxy`).

**Override** (e.g. the scan picks something you do not like, or the controller cannot scan):

```yaml
# inventories/<profile>/host_vars/proxy.yml
hop_reality_target: 203.0.113.20:443
hop_reality_server_name: www.example.com   # required with an address; default: the host of the target
```

Removing the override makes the next run scan again (a target outside the edge's /24 is never kept).

## Role monserver

Runs on the single host of group `monserver` (decision #55, items 6–7; inputs from
SBKubric/3ax-ui-monitoring#52/#56/#65). A second run reports `changed=0`.

1. **Binary.** `mon-server-linux-amd64.tar.gz` of release `mon_version` from
   `SBKubric/3ax-ui-monitoring`, checked against the published `.sha256`, cached in
   `/var/cache/3ax-ui-orchestrator/mon-server/<version>/`; `/usr/local/bin/mon-server` is replaced (and
   the service restarted) only when it differs. `mon-server version` must print `mon_version`.
2. **Config and unit.** System user `mon-server`; `/etc/mon-server/config.json` (`root:mon-server
   0640`, no secrets): `listen :443`, `publicIp` (default IPv4 from facts, `monserver_public_ip` behind
   NAT), `dataDir /var/lib/mon-server`, `tls.mode acme-ip`. Unit `mon-server.service` as in the
   mon-server README: `User=mon-server`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
   `StateDirectory=mon-server`, `StateDirectoryMode=0700`, `UMask=0077`, and
   `MON_TLS_ACME_CA=staging|production` from `acme_production`.
3. **Admin account.** `mon-server admin set -config <path> <mon_admin_user>` with `MON_ADMIN_PASSWORD`,
   run as the service user (`runuser`, umask 077), before the very first start. Later runs log in with
   the vault account (`POST /admin/login`) and set it again only when that fails. Five failed logins
   from one address lock it out for 15 minutes.
4. **Settings** through the admin API (`GET/POST /admin/api/settings`; POST replaces the whole form, so
   the current settings are read and only these fields change): `panelUrl`, `monToken`, `panelCa` from
   the panel play's facts (`panel_url`, `panel_mon_token`, `panel_ca_pem`), `tgToken`/`tgChatId` from
   the vault (empty vault values leave Telegram alone). Then `POST /admin/api/settings/check` must answer
   "Panel reachable"; `monserver_require_panel_reachable: false` turns that into a warning. In a run
   without the panel play (`--tags monserver`) the panel fields are left alone with a warning. Behind the panel's
   only443 front `panelUrl` is `https://<panel IP>/<base>/` on 443 (the front publishes `<base>mon/v1/` with the
   publicly trusted IP certificate) and `panelCa` is emptied: mon-server trusts the system roots.

Admin API calls run on the mon-server host against `https://127.0.0.1/admin/` without certificate
verification (the certificate is for `publicIp`, on staging from an untrusted root); mutating calls
carry `X-Requested-With: XMLHttpRequest`. Tasks that carry the password, tokens or the session cookie
are `no_log`.

Fact for later plays: `monserver_url` = `https://<monserver_public_ip>:443` on
`hostvars[groups['monserver'][0]]` (role monclient: `MON_SERVER_URL`).

Knobs in `roles/monserver/defaults/main.yml`: `monserver_public_ip`, `monserver_port`,
`monserver_tls_mode` (`acme-ip`, or `files` with `monserver_tls_cert`/`monserver_tls_key` for a test
environment without ACME), `monserver_start_timeout`, `monserver_require_panel_reachable`,
`monserver_release_url`.

`mon_version` and `xui_version` must speak the same monitoring contract (mon-server refuses any other,
older or newer): contract 3 (per-hop, SBKubric/sane-3x-ui-monitoring#61) is `v0.1.0-stand.5` with
`v1.9.0-chain.8` or later; bump both tags in one change. mon-server's Settings -> Check (verify.yml) names
the side to update.

`mon_version` needs `v0.1.0-stand.3` or later: it is the first release with `panelCa`/`tls.acmeCa`
(SBKubric/3ax-ui-monitoring#65), needed to trust the panel's self-signed certificate and to use LE
staging. With `v0.1.0-stand.2` the role stops at "no panelCa setting", and mon-server ignores
`MON_TLS_ACME_CA`, i.e. uses production LE.

### mon-server admin API from other roles

`roles/monserver/tasks/api_login.yml` logs in (`POST /admin/login`, JSON) and keeps the session:

```yaml
- name: Log in to mon-server
  ansible.builtin.include_role:
    name: monserver
    tasks_from: api_login

- name: List mon-clients
  ansible.builtin.uri:
    url: "{{ monserver_api_url }}api/clients"
    headers:
      Cookie: "{{ monserver_api_cookie }}"
    validate_certs: false
    return_content: true
  delegate_to: "{{ monserver_api_host }}"
```

It sets `monserver_api_cookie`, `monserver_api_url`, `monserver_api_host` and
`monserver_api_logged_in` on the calling host and fails on a wrong login unless
`monserver_api_login_required: false` is passed.

## Role monclient

Runs on every host of group `monclient` (decision #55, item 6).

1. **Binaries.** `mon-client-linux-amd64.tar.gz` of `mon_version` (sha256 as above) and xray
   `mon_xray_version` from the official `XTLS/Xray-core` release (`Xray-linux-64.zip`, checked against the
   SHA2-256 line of its `.dgst`) to `/usr/local/bin/mon-client` and `/usr/local/bin/xray` (mon-client's
   default `--xray-bin`); both versions are checked after install.
2. **Unit.** System user `mon-client`; `mon-client.service` runs `mon-client run` with
   `MON_SERVER_URL` = the `monserver_url` fact (or `https://<IPv4 of the monserver host>:443`, facts
   gathered on demand, or `monclient_server_url`), `StateDirectory=mon-client` (`state.json`, the token),
   `StateDirectoryMode=0700`, `UMask=0077`, `Restart=always`, and `GOMEMLIMIT` = `mon_gomemlimit`
   (default `128MiB`, empty = none): a guard against swap on a small box (SBKubric/sane-3x-ui-monitoring#85).
3. **LE staging** (`acme_production: false`). The four Let's Encrypt staging roots (Pretend Pear X1,
   Bogus Broccoli X2, Yearning Yucca YE, Yonder Yam YR) are vendored in
   `roles/monclient/files/le-staging-roots.pem` (from letsencrypt.org/docs/staging-environment, with
   SHA-256 fingerprints), installed as `/etc/mon-client/le-staging-roots.pem` and set as
   `SSL_CERT_FILE` in the unit. Go reads `SSL_CERT_FILE` *instead of* the system bundle file but still
   reads the directory `/etc/ssl/certs` (`crypto/x509/root_unix.go`), so public and locally installed
   CAs keep working; the file therefore holds the staging roots only. With `acme_production: true` the
   file and the variable are removed.
4. **Pairing** (`mon_auto_approve`, default `true`). Nothing to do when a mon-client named `mon_name`
   (default: inventory hostname) is ONLINE, or when the box holds a token (`state.json`) the registry
   still knows. Otherwise the role waits (up to 3 minutes) for `registration request sent, pairing code
   <X>` in the journal of the unit's current run (a code followed by `registered as` no longer counts;
   a box whose token the server does not know re-registers after its first heartbeat), finds the request
   with that `pairingCode` in `GET /admin/api/requests` and approves it:
   - a mon-client with that name exists (`suggestReplacement` names it, or the registry has it, e.g.
     after its token was revoked) → `{"mode": "replace", "existingId": <id>}`: keeps id and history;
   - otherwise → `{"mode": "new", "name": mon_name, "region": mon_region, "paths": mon_paths}`
     (`mon_paths` default `[direct, hops]`: direct plus every probed hop of the chain, hops added later
     included, or the proxy path while there is no chain; one hop by path is `edge:<hop_name>` /
     `inner:<hop_name>`; the old `proxy` is refused, contract 3 calls it `hops`).

   It then waits for the box to collect its token and brings `region`/`paths` of the record back to the
   inventory values (`POST /admin/api/clients/<id>`) when they differ. With `mon_auto_approve: false`
   the role prints the pairing code and the admin URL and stops there.

Knobs in `roles/monclient/defaults/main.yml`: `monclient_server_url`, `monclient_log_level`,
`monclient_pairing_retries`/`monclient_pairing_delay`, `monclient_release_url`.

## Front: only 443

The default profile (`front_mode: only443`; SBKubric/sane-3x-ui [ADR 0005](https://github.com/SBKubric/sane-3x-ui/blob/main/docs/adr/0005-only-443-on-every-hop.md),
panel `v1.9.0-chain.10`+). Every box, the real server and each hop, accepts TCP only on **443** (plus SSH, 80 for the
ACME webroot, and the UDP of AmneziaWG and the relayed UDP ports): nginx reads the SNI and passes a Reality client on
(the next hop, the inbound on the real server), an unknown SNI to the edge's neighbour target or a cover page, and
answers requests by address (no SNI) with the box's Let's Encrypt IP certificate on its HTTP side: subscriptions, the
chain poll (`/chain/v1/`), `/join/` on a hop, and on the panel `<base>mon/v1/`, `<base>login` and `<base>panel/api/`
only. The panel's UI is not reachable from outside: `<base>panel/` gets the cover page. Limits and fail2ban guard the
HTTP side (SBKubric/sane-3x-ui#141).

What the roles do with `only443`:

| Box | Role | What |
|---|---|---|
| real | panel | install.sh with `XUI_WEB_LISTEN=127.0.0.1` and `XUI_FAIL2BAN=1`; the Let's Encrypt IP certificate in `/root/cert/ip` (acme.sh through nginx's webroot on :80, shortlived, renewed every 3 days; a valid one is kept, see LE limits); fail2ban (and the sshd jail on the journal where `auth.log` is missing); `webListen` 127.0.0.1 and `chainPanelHost` = the public IP through the settings form (`panel/setting/all` → `update`, a restart when `webListen` changes); then `panel/api/nginx`: mode `only443`, subscriptions and panel behind 443, firewall on, `80` added to `firewallExtra` (the panel's firewall does not keep the ACME port by itself), the plan's blockers refused, `apply`, and `confirm` before the 2-minute rollback |
| hops | hop | install.sh with `PROXY_FRONT=only443` (a converged box re-joins once to get it), fail2ban with it; the registry follows the box's front report (443/https), the role waits for it hop by hop |
| mon-server | monserver | `panelUrl` = `https://<panel IP>/<base>/`, `panelCa` empty |

The role's own panel API calls keep going to `https://127.0.0.1:<panel_port><base>` on the panel host over ssh
(`delegate_to`): neither `webListen` 127.0.0.1 nor the firewall (it never touches the loopback) takes that away.

**Convergence order** (a fresh stand and an existing one alike; `site.yml` does it in one run):

1. **real**: the inbounds (the XHTTP migration, the front needs a Reality inbound to route), the IP certificate, then
   the front with its firewall, confirmed. The panel's port and the sub port 2096 close; a hop that still polls 2096
   loses the wave until step 2 reinstalls it.
2. **inner hops**, from the panel outward (`hop_position`): reinstall with `PROXY_FRONT=only443`, the innermost one
   polling the panel on 443; the role waits until the registry shows the hop on 443/https (its front report).
3. **edges**: reinstall, dialling their inner neighbour on 443, wait for the report the same way. An inner hop keeps its
   old sub port open until every outer neighbour has polled it on 443, then closes it.
4. the neighbour target of every edge and `setActive`; then the second pass over `panel_inbounds` flags the
   chain-following inbound if the active edge had no neighbour target before (its cover becomes the neighbour's).
5. **mon-server** switches to 443; mon-clients probe `direct` (the real server's 443) and every hop.
6. `verify.yml`.

Clients: the links change (port 443, `type=xhttp`, the active edge's server name); they get them by refreshing the
subscription (the panel asks clients to refresh hourly while inbounds follow the chain).

**Admin access through an SSH tunnel.** The panel's pages listen on 127.0.0.1 only:

```sh
ssh -L 2053:127.0.0.1:2053 real          # the vault's panel_port on both sides
# then open https://127.0.0.1:2053/<panel_base_path>/  (the self-signed certificate names the server's IP)
```

**fail2ban on the front.** Misses (a path under the secret base path that the front does not publish, an unknown
subscription) count: 10 in 10 minutes ban the address for an hour on 80/443 (SSH stays). `verify.yml` costs the
controller one miss per run (it opens `<base>panel/` to see the cover page); should it be banned:
`ssh real fail2ban-client set 3ax-ui-probe unbanip <controller IP>`.

**`front_mode: off`** keeps the behaviour before this profile: hops are (re)installed with `PROXY_FRONT=off`, and the
role leaves the panel's front, `webListen` and `chainPanelHost` as they are (install.sh's default front is `shared`,
without a firewall). It does not undo an `only443` panel: switch its front off on the Nginx page (through the tunnel)
first, then rerun `site.yml` with `front_mode: off`.

## wipe.yml

Stops and deletes what `site.yml` and install.sh put on the boxes, so that the next `site.yml` starts from
scratch (decision #55, item 4). One play per group, outside in: monclient → monserver → hops → panel;
an empty group is skipped, a box with nothing installed reports `ok`, and a second wipe reports
`changed=0`. It refuses to start without `-e wipe_confirm=yes`. Tags `monclient`, `monserver`, `hops`,
`panel` wipe some groups only.

Every unit is stopped, disabled and removed with its drop-ins (`/etc/systemd/system/<unit>.service[.d]`),
then:

| Group | Deleted | Kept |
|---|---|---|
| panel | unit `x-ui` (with the ru-inside drop-in), units `3ax-ru-inside.timer`/`.service`; `/etc/x-ui` (database `x-ui.db`, the self-signed certificate in `tls/`), `/usr/local/x-ui`, `/usr/bin/x-ui`, `/var/log/x-ui`, `/root/3ax-ui-install.sh`, the ru-inside list `/var/lib/3ax-ru-inside`, `/usr/local/sbin/3ax-ru-inside` and `/etc/3ax-ru-inside.json`; tunnel interfaces from `/etc/amnezia/amneziawg/*.conf` and `/etc/wireguard/*.conf` (taken down, configs deleted); the panel's nginx files (`stream-enabled/3ax-ui.conf`, `conf.d/3ax-ui.conf`, `http.d/3ax-ui.conf`) and its marked stream block in `nginx.conf` (nginx reloaded); firewall chain `THREEAX-IN` and its `INPUT` jumps (iptables, ip6tables); the TPROXY wiring of tunnels routed through Xray (mangle `PREROUTING` rules with `--tproxy-mark 0x1`/`0x2`, fwmark policy rules and routing tables 100/101), which a tunnel's PostDown leaves behind once the server is switched to direct routing | packages (AmneziaWG, WireGuard, nginx, sqlite3, fail2ban), the rest of nginx.conf, the front's LE IP certificate `/root/cert/ip` with acme.sh's renewal (the next `site.yml` keeps using it) |
| hops | unit `x-ui`; `/etc/x-ui` (`proxy.json`, `chain/` with the hop secret and chain document, `chain-join.url`), `/usr/local/x-ui`, `/usr/bin/x-ui`, `/var/log/x-ui`, `/root/3ax-ui-install.sh`, the join token file `/root/.3ax-ui-join-token` | the LE IP certificate `/root/cert/ip` and acme.sh with its renewal; `-e hop_wipe_le_cert=true` also deletes `/root/cert/ip` and acme.sh's IP certificate dirs (`/root/.acme.sh/<ip>[_ecc]`); fail2ban and its jails |
| monserver | unit `mon-server`; `/usr/local/bin/mon-server`, `/etc/mon-server`, `/var/cache/3ax-ui-orchestrator/mon-server`, everything in `/var/lib/mon-server` (database: admin account, Settings, mon-client registry) | `/var/lib/mon-server/certs` (certmagic's ACME account and certificates) and the `mon-server` user that owns it; `-e monserver_wipe_certs=true` deletes the whole data dir and the user |
| monclient | unit `mon-client`; `/usr/local/bin/mon-client`, `/usr/local/bin/xray`, `/etc/mon-client`, `/var/lib/mon-client` (`state.json`, the token), `/var/cache/3ax-ui-orchestrator/{mon-client,xray}`; user and group `mon-client` | nothing |

The panel's chain registry is not touched on its own: a wiped panel forgets its hops, and a kept panel
(`--tags hops`) sees the wiped boxes as broken and re-joins them on the next `site.yml`. The paths are
role defaults (`*_wipe_paths` and friends in `roles/<role>/defaults/main.yml`).

## verify.yml

Read-only checks, imported last by `site.yml` (tag `verify`) and runnable on its own (decision #55,
item 8). Plays of empty groups are skipped, so `stand-chain` checks the panel and the chain only. The
plays run for real under `--check` too (nothing in them writes). A failure says what is wrong and where
to look; the first group that fails ends the run.

| Play | Checks |
|---|---|
| panel | `x-ui -v` = `xui_version`; API login with the vault account (`POST <base>login`); `GET <base>panel/api/chain/list`: every hop of group `hops` (by `hop_name`, default the inventory hostname) is `joined` (with `front_mode: only443` on 443/https: its front reported), and `activeEdge` is the hop with `hop_active: true`; registry hops the inventory does not list are reported; geosite ru-inside (with `panel_ru_inside_enabled`): the rule in the Xray template, `/usr/local/x-ui/bin/ru-inside.dat` present, a `WARNING` when its last good check is older than `panel_ru_inside_max_age_days`, `3ax-ru-inside.timer` active |
| hops | `x-ui -v` = `xui_version`; `x-ui chain status -c /etc/x-ui/proxy.json` is fresh: it answers as `hop_name`, the revision is not `stale`, the next hop is `reachable: true`, the relay is `running=true` with at least one port (up to 2 minutes, a new port list takes a poll per hop: `hop_verify_retries` x `hop_verify_delay`); with `hop_sub_scheme: https`, `proxy.json` has a `cert` and `https://<hop_host>:<hop_sub_port>/` answers TLS (certificate not validated), fetched from the next-outer hop, or from the controller for an edge (`hop_verify_tls_url`, `hop_verify_tls_probe_host`); an edge's neighbour target in the registry, with a `WARNING` (no failure) for the shared fallback or none |
| panel + hops (only443) | from the controller (`roles/common/files/portscan.py`, TCP connect, all ports at once): 443 answers, the old ports do not (the sub port 2096, the inbounds' ports of `panel_inbounds`, on the panel its own port), waiting up to 2 minutes for an inner hop to close its old sub port; 80 closed is a `WARNING`; on the panel `GET <base>panel/` on 443 gets the cover page (200, no base path in it, not the panel's redirect to its login) and `POST <base>login` on 443 succeeds (the IP certificate is verified). UDP is left to the monitoring targets. `verify_front_scan: false` skips it |
| monserver | `mon-server version` = `mon_version`; admin login (`POST /admin/login`); `GET /admin/api/settings` has `panelUrl` and `monToken`; `POST /admin/api/settings/check` with the saved `panelUrl`/`monToken`/`panelCa`/`realHost` answers `Panel reachable.` (same monitoring contract, the probe configs are readable too), and its probe links per path (`probeItems`) cover `direct` and every hop of group `hops` as `<hop_role>:<hop_name>`, with no path the inventory does not list |
| monclient | `mon-client version` = `mon_version`; in `GET /admin/api/clients` the record named `mon_name` is enabled, has a live token and is `ONLINE` (up to 3 minutes) |
| panel (with mon-clients) | `GET <base>panel/api/monitoring/targets`: the panel's contact with mon-server is not stale, every enabled inbound (xray and the AmneziaWG one alike) has a target for every mon-client of group `monclient` on each path its `mon_paths` expands to (`hops` → `<hop_role>:<hop_name>` of every host in group `hops`, or `proxy` without hops; a named hop only if it is in group `hops`; an xray inbound with `followChain` is not expected on `edge:<name>` unless `<name>` is the active edge of the registry, so on no edge path while no edge is active), and every target of an enabled inbound is `UP` (targets of disabled inbounds are `PAUSED` by design and ignored); up to 3 minutes (`panel_verify_targets_retries` x `panel_verify_targets_delay`) |

## Prerequisites

- Python 3.12+ on the controller; `pip install -r requirements.txt` and
  `ansible-galaxy collection install -r requirements.yml`.
- For the [neighbour target](#neighbour-target) scan: a Linux x86_64/aarch64 controller with outbound
  access to the edges' /24 on 443, `whois.cymru.com:43` and GitHub.
- Root ssh access to every host of the profile (key-based, via the aliases above).
- Target OS: Debian 12/13 or Ubuntu 22.04/24.04; anything else fails in role `common`.
- The vault password.

## Vault

Secrets live in `group_vars/all/vault.yml` next to the playbooks, shared by every profile, and never in
git (`.gitignore`). Keys: `panel_user`, `panel_password`, `panel_port`, `panel_base_path`,
`mon_admin_user`, `mon_admin_password`, `tg_bot_token`, `tg_chat_id` (see `vault.yml.example`).

```sh
cp group_vars/all/vault.yml.example group_vars/all/vault.yml
$EDITOR group_vars/all/vault.yml
ansible-vault encrypt group_vars/all/vault.yml     # asks for a new vault password
ansible-vault edit group_vars/all/vault.yml        # later changes
ansible-vault view group_vars/all/vault.yml
```

Give the password to each run with `--ask-vault-pass`, or keep it in a file outside the repo
(`chmod 600`) and pass `--vault-password-file ~/.3ax-ui-vault-pass` (or set
`ANSIBLE_VAULT_PASSWORD_FILE`).

## Running

```sh
# Converge (install or update to the tags in group_vars, configure, join, verify):
ansible-playbook -i inventories/stand-full site.yml --ask-vault-pass
ansible-playbook -i inventories/stand-chain site.yml --ask-vault-pass

# Only some groups / only the checks:
ansible-playbook -i inventories/stand-full site.yml --tags panel,hops --ask-vault-pass
ansible-playbook -i inventories/stand-full verify.yml --ask-vault-pass

# From scratch: wipe, then converge (see the runbook below).
ansible-playbook -i inventories/stand-full wipe.yml -e wipe_confirm=yes --ask-vault-pass
ansible-playbook -i inventories/stand-full site.yml --ask-vault-pass
```

Tags in `site.yml`: `common`, `panel`, `hops`, `monserver`, `monclient`, `verify`.
`site.yml` only converges and never deletes state; a fresh start is always the explicit `wipe.yml`.

## Runbook: stand from scratch

1. **Controller.** Python 3.12+, then in the repo:
   ```sh
   pip install -r requirements.txt                          # ansible-core, ansible-lint
   ansible-galaxy collection install -r requirements.yml    # community.crypto, community.general
   ```
2. **ssh.** Root access by key to every host of the profile, through the aliases in the inventory
   (`real`, `bridge`, `proxy`, and for `stand-full` also `monserver`, `monclient`) in `~/.ssh/config`:
   ```
   Host bridge
       HostName 203.0.113.10
       User root
       IdentityFile ~/.ssh/stand
   ```
   Check with `ansible -i inventories/stand-full all -m ansible.builtin.ping`.
3. **Vault.** `group_vars/all/vault.yml` (see [Vault](#vault)) and its password, as
   `--ask-vault-pass` or `--vault-password-file ~/.3ax-ui-vault-pass`. The examples below use
   `--ask-vault-pass`.
4. **Profile.** `inventories/stand-chain` (panel + hops) or `inventories/stand-full` (+ mon-server and
   mon-client); versions and `front_mode` (`only443`, the default) in `inventories/<profile>/group_vars/all/main.yml`.
   With only443 every box needs its address reachable from the internet on 80 (Let's Encrypt IP certificates through
   nginx's webroot) and 443, and must not be behind NAT.
5. **Wipe**, then **converge**; `site.yml` ends with `verify.yml`:
   ```sh
   ansible-playbook -i inventories/stand-full wipe.yml -e wipe_confirm=yes --ask-vault-pass
   ansible-playbook -i inventories/stand-full site.yml --ask-vault-pass
   ```
   A fresh panel gets new inbounds (`panel_inbounds`, with new Reality and AWG keys) and a new chain
   registry, so clients' subscriptions from before the wipe are dead. Keep the output of both runs if the run is the resolution of a ticket.
   The order inside `site.yml` is the [convergence order](#front-only-443): the panel behind its front, then every hop
   from the panel outward, each waiting for its front report, then mon-server on 443.
6. **Verify alone**, any time later (read-only; with only443 it costs the controller one miss in the front's fail2ban
   probe jail, see [Front: only 443](#front-only-443)):
   ```sh
   ansible-playbook -i inventories/stand-full verify.yml --ask-vault-pass
   ```
7. **Admin access** to the panel's pages from then on: through an SSH tunnel, `ssh -L <panel_port>:127.0.0.1:<panel_port>
   real`, then `https://127.0.0.1:<panel_port><panel_base_path>`.

**An existing stand to «only 443»** (no wipe): bump `xui_version` to `v1.9.0-chain.10` (or later) and rerun `site.yml`.
The panel is reinstalled with its database, the VLESS inbound moves to XHTTP in place (its clients keep their ids and
subIds), the panel goes behind its front, every hop re-joins with `PROXY_FRONT=only443` from the panel outward, and
mon-server moves to 443. Between the panel's front coming up and a hop's reinstall that hop's wave is stale (it still
polls 2096): a few minutes without chain updates, while its relay keeps carrying traffic. Clients refresh their
subscription for the new links.
**Version upgrade** (no wipe): bump `xui_version` and/or `mon_version` (and `mon_xray_version` in
`group_vars/monclient.yml`) in the profile, then rerun `site.yml`. The panel is reinstalled on the new tag
with its database kept, every hop re-joins with the new version (keeping its LE certificate), mon-server
and mon-client binaries are replaced, and `verify.yml` checks the versions at the end.

**Let's Encrypt limits.** Production LE issues at most 5 certificates for the same identifier (here: the
IP address) in 7 days.
- Hops always use production LE (staging would break trust in the sub port). `wipe.yml` keeps a hop's
  certificate and `site.yml` reuses it (`hop_tls_reuse`), so a wipe + converge costs nothing while the
  box keeps its address; `-e hop_wipe_le_cert=true`, a new box or a new address issues again. More than 4
  issuances per hop a week are not supported; `hop_tls: none|manual` avoids LE.
- mon-server uses LE staging by default (`acme_production: false`; the mon-client trusts the staging
  roots). With `acme_production: true` it counts against the same 5-per-7-days limit, which is why
  `wipe.yml` keeps mon-server's certificates unless `-e monserver_wipe_certs=true`.
- The panel's own port uses a self-signed certificate: no LE. Behind the only443 front the panel box gets a production
  LE IP certificate too (`/root/cert/ip`, what the front's HTTP side and mon-server use); like a hop's it is issued once
  and kept by `site.yml` and `wipe.yml` while valid for the address.

## Development

CI (`.github/workflows/ci.yml`) runs `ansible-lint` with the `production` profile (`.ansible-lint`),
`ansible-playbook --syntax-check` of every playbook against every inventory,
`tests/hop/test_hop_role.py`: role hop on local stand-in hosts against `tests/hop/mock_panel.py` (the panel
API: login, chain list/add/update/reissueToken/setActive/del with the panel's refusals; inbounds
list/add/update/setEnable, the AWG server and getNewX25519Cert, the monitoring targets) and a fake
install.sh — fresh chain replacing `legacy`, idempotent rerun, new version, new host, broken box, LE
certificate reuse, pruning, check mode, refusals, `--limit`, no token or cookie in `-vvv` output; the
neighbour target with `tests/hop/fake_neighbour.py` in place of the scanner and the handshake check — found
and written before `setActive`, a stored target kept without a scan or rescanned when its check fails, the
fallback with a warning and a rescan on every run, the override, its refusals, check mode; the «only 443» front
(`PROXY_FRONT`, the innermost hop polling the panel on 443, the edge installed after its inner neighbour reported its
front, a converged chain moved behind the front with re-joins only, a front that does not report stopping the run,
`hop_tls` refused without the IP certificate, verify requiring 443/https in the registry); the
panel and hop plays of `verify.yml` on the converged chain and on a registry, a box and a version that are
wrong, and the neighbour target warnings; `tests/hop/test_neighbour_script.py`: `neighbour.py` against a fake
RealiTLScanner, TLS sites on `127.0.0.x`, a fake Team Cymru whois and a fake xray — the address list and
limits, every filter, the ranking, the handshake check and the confirmation of the best candidates, the
pinned download; `tests/panel/test_panel_inbounds.py`: role panel's inbounds with the stand's `panel_inbounds` against
the same mock — a fresh panel (Reality keys from the panel, AWG server switched on, both ports relayed), an
idempotent rerun also after the panel re-serialized the settings and added the probe client, a changed
field updated without re-keying, port and enable, the AWG server switched off by hand, unlisted inbounds
left alone, check mode, refusals, no private key or cookie in `-vvv` output, the TCP + Vision inbound migrated to
XHTTP in place (keys, client ids/emails/subIds kept, Vision flow cleared, `tcpSettings` dropped), `followChain` taking
the active edge's neighbour and not fought afterwards, the flag waiting for a neighbour target; and the targets play of
`verify.yml` on every inbound UP, an inbound without targets, a missing path and a DOWN target;
`tests/panel/test_panel_front.py`: the «only 443» front against the same mock and local fakes — only443 applied
with subscriptions/panel behind 443, the firewall and 80 kept in `firewallExtra`, then confirmed, idempotent, the
relocated inbound left alone by the inbounds converge, the owner's firewall ports kept, blockers refused, a pending
confirmation confirmed, warnings shown, check mode, `front_mode: off`; `webListen`/`chainPanelHost` through the
whole settings form with a restart only for a new listen address; the LE IP certificate through a fake acme.sh and
x-ui (installer, acme-front before the issue, webroot/shortlived flags, reuse while valid for the address, reissue
for another address or an expiring one, check mode); `panel_url`/`panel_ca_pem` behind the front;
`tests/panel/test_ru_inside.py`: geosite ru-inside against the same mock (its Xray template API and an xray restart
that fails on a missing `ext:` file) and a local source of the list — a fresh box (list, link, timer, service,
drop-in, the rule right after the api rule, one restart), idempotent, other rules and the form kept, a rule the UI
stripped of its tag not doubled, the api rule elsewhere, a missing blackhole added and a `blocked` of another protocol
refused, a new list restarting xray, a box without GitHub served by the controller, a bad checksum or a list without
the category keeping the old one with a warning, no list anywhere leaving the template alone and taking a stale rule
out, a failed restart putting the old template back, `panel_ru_inside_enabled: false`; the script as the timer and
`ExecStartPre` run it (restart only on a new list, the check time, the link after a reinstall); the ru-inside check of
`verify.yml` (fresh, old list, no rule, no file);
`tests/monserver/test_settings.py`: mon-server's Settings against a mock admin API — `panelUrl` on 443 without
`panelCa`, idempotent, the panel's own port with `panelCa` for `front_mode: off`;
`tests/common/test_verify_front.py`: `portscan.py` and verify's «only 443» step on local listeners — the front port
open, an old port still answering, a closed front, a closed ACME port (warning), the panel UI answering on the front,
a failing API login;
`tests/wipe/test_wipe.py`: `wipe.yml` on local stand-in boxes — refusal, what goes and what stays,
the certificate flags, a repeated wipe and a bare box with `changed=0`, one group by tag; and checks that
`wipe.yml` refuses without confirmation. The mon-server/mon-client plays of `verify.yml` have no mock and
are exercised on the stand. No Molecule. Locally without an ansible install:

```sh
docker run --rm -v "$PWD":/work -w /work python:3.12-slim sh -c '
  pip install -q -r requirements.txt &&
  ansible-galaxy collection install -r requirements.yml &&
  ansible-lint &&
  for inv in inventories/*/; do for pb in site.yml wipe.yml verify.yml; do
    ansible-playbook -i "$inv" "$pb" --syntax-check; done; done &&
  python3 tests/hop/test_neighbour_script.py &&
  python3 tests/hop/test_hop_role.py && python3 tests/panel/test_panel_inbounds.py &&
  python3 tests/panel/test_panel_front.py && python3 tests/panel/test_ru_inside.py &&
  python3 tests/monserver/test_settings.py &&
  python3 tests/common/test_verify_front.py && python3 tests/wipe/test_wipe.py'
```

## License

GPL-3.0-only, see [LICENSE](LICENSE) (same as upstream 3x-ui).
