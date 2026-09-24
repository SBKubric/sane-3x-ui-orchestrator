# 3ax-ui-orchestrator

Ansible that deploys a whole 3ax-ui installation from an inventory: the panel
([SBKubric/3ax-ui-proxy](https://github.com/SBKubric/3ax-ui-proxy)), its proxy chain hops, and
monitoring ([SBKubric/3ax-ui-monitoring](https://github.com/SBKubric/3ax-ui-monitoring): mon-server and
mon-client). Design: [SBKubric/3ax-ui-monitoring#55](https://github.com/SBKubric/3ax-ui-monitoring/issues/55).

> Status: roles `common`, `panel`, `hop`, `monserver` and `monclient`, `wipe.yml` and `verify.yml` are real;
> the first full stand run (`wipe.yml` + `site.yml` of `stand-full` to a green `verify.yml`) is #5.

## Layout

```
ansible.cfg            roles path, root over ssh, no default inventory
requirements.txt       ansible-core + ansible-lint (pinned)
requirements.yml       collections (pinned)
site.yml               converge: common -> panel -> hops -> monserver -> monclient -> verify.yml
wipe.yml               destroy state for a fresh start; refuses without -e wipe_confirm=yes
                       (steps: roles/<role>/tasks/wipe.yml)
verify.yml             non-destructive checks; also imported last by site.yml (tag verify)
                       (steps: roles/<role>/tasks/verify.yml)
group_vars/all/        vault.yml (git-ignored, yours) and vault.yml.example (template)
inventories/
  stand-chain/         panel + hops; monserver/monclient empty
  stand-full/          panel + hops + monserver + monclient
roles/
  common/              supported OS check, base packages, time sync
  panel/               install by tag, self-signed TLS, vault account, Telegram, monitoring token;
                       tasks/api_login.yml is the panel API login helper for other roles
  hop/                 chain registry converged with group hops through the panel API; install + join
  monserver/           release binary, bootstrap config, unit, admin account, Settings via the admin API;
                       tasks/api_login.yml is the mon-server admin API login helper for other roles
  monclient/           release binaries (mon-client, xray), unit, LE staging roots, pairing auto-approval
tests/hop/             role hop and the chain part of verify.yml against a mock of the panel chain API (CI)
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
| `xui_version` | release tag of 3ax-ui-proxy for the panel and every hop (`install.sh <xui_version>`) |
| `mon_version` | release tag of 3ax-ui-monitoring for mon-server and mon-client |
| `acme_production` | `false` = Let's Encrypt staging for mon-server (default); hops always use production LE |
| `mon_auto_approve` | approve mon-client pairing requests through the mon-server admin API |

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

Per mon-client (`host_vars`, optional): `mon_name`, `mon_region`, `mon_paths`; group `monclient`:
`mon_xray_version`. Role-internal knobs live in each role's `defaults/main.yml`.

## Role panel

Runs on the single host of group `panel` (decision #55, items 2, 5, 7). Every step converges and is
skipped when the host already matches, so a second run reports `changed=0`.

1. **TLS.** `community.crypto` makes an ECDSA P-256 key, a CSR and a self-signed certificate
   (10 years, `CA:TRUE`, SANs `IP:<panel_public_ip>` and `IP:127.0.0.1`) in `/etc/x-ui/tls/`. They are
   created once; a new public IP (the SAN changes) re-issues the certificate and restarts the panel.
   `x-ui setting -getCert` must point at these files, otherwise `x-ui cert -webCert -webCertKey` fixes it.
2. **Install / update.** `x-ui -v` equal to `xui_version` (without the `v`) → nothing to do. Otherwise
   `install.sh <xui_version>` (taken from the same tag of `SBKubric/3ax-ui-proxy`, `XUI_REPO` set) runs with
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

Secrets never reach the output: the tasks that carry the password, the Telegram token, the monitoring
token or the session cookie are `no_log`. install.sh prints random credentials of its own; they are
replaced right after the install.

Facts left on the panel host for later plays (`hostvars[groups['panel'][0]]`):

| Fact | Value | Used by |
|---|---|---|
| `panel_url` | `https://<panel_public_ip>:<panel_port><panel_base_path>` | hop, monserver (`panelUrl`), verify |
| `panel_ca_pem` | PEM of the self-signed certificate | monserver (`panelCa`) |
| `panel_mon_token` | monitoring bearer token (only with a `monserver` host) | monserver (`monToken`) |

The facts exist only in a run that includes the panel play (`--tags panel` or a full run).

Knobs in `roles/panel/defaults/main.yml`: `panel_public_ip` (default IPv4 from facts; set it in
`host_vars` behind NAT), `panel_cert_sans`, `panel_cert_valid_days`, `panel_tls_dir`,
`panel_install_ref`/`panel_install_url`, `panel_install_timeout`.

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
| `joined`, same host / sub port / scheme, `x-ui chain status` answers with this name, `x-ui -v` = `xui_version` | nothing |
| anything else (pending, broken box, other version, new host) | `update` of what changed → `reissueToken` → install |

Install = `install.sh <xui_version>` from the same tag with `XUI_PROXY_MODE=1`, `PROXY_NEXT_HOP`,
`PROXY_NEXT_HOP_SUB_PORT`/`_SCHEME`, `PROXY_SUB_PORT`, `PROXY_TLS`, `PROXY_JOIN_TOKEN`; without a TTY and
with an explicit tag install.sh reinstalls that tag and joins before the service starts. The role then
waits for the registry to report the hop `joined` and checks the installed version.

The next hop of the box is `hop_next` when set, otherwise derived: the inward neighbour's host, sub port
and scheme as registered, or the panel for the innermost hop (`hop_panel_host`, else the host of
`panel_url`, else `panel_public_ip` from the panel's `host_vars`, else its default IPv4; sub port
`hop_panel_sub_port`, default 2096).

After the loop: `setActive` on the edge with `hop_active: true` (exactly one edge must carry it, asserted
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
`hop_prune`, `hop_tls_reuse`.

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
   without the panel play (`--tags monserver`) the panel fields are left alone with a warning.

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
   `StateDirectoryMode=0700`, `UMask=0077`, `Restart=always`.
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
     (`mon_paths` default `[direct, proxy]`).

   It then waits for the box to collect its token and brings `region`/`paths` of the record back to the
   inventory values (`POST /admin/api/clients/<id>`) when they differ. With `mon_auto_approve: false`
   the role prints the pairing code and the admin URL and stops there.

Knobs in `roles/monclient/defaults/main.yml`: `monclient_server_url`, `monclient_log_level`,
`monclient_pairing_retries`/`monclient_pairing_delay`, `monclient_release_url`.

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
| panel | unit `x-ui`; `/etc/x-ui` (database `x-ui.db`, the self-signed certificate in `tls/`), `/usr/local/x-ui`, `/usr/bin/x-ui`, `/var/log/x-ui`, `/root/3ax-ui-install.sh`; tunnel interfaces from `/etc/amnezia/amneziawg/*.conf` and `/etc/wireguard/*.conf` (taken down, configs deleted); the panel's nginx files (`stream-enabled/3ax-ui.conf`, `conf.d/3ax-ui.conf`, `http.d/3ax-ui.conf`) and its marked stream block in `nginx.conf` (nginx reloaded); firewall chain `THREEAX-IN` and its `INPUT` jumps (iptables, ip6tables) | packages (AmneziaWG, WireGuard, nginx, sqlite3), the rest of nginx.conf |
| hops | unit `x-ui`; `/etc/x-ui` (`proxy.json`, `chain/` with the hop secret and chain document, `chain-join.url`), `/usr/local/x-ui`, `/usr/bin/x-ui`, `/var/log/x-ui`, `/root/3ax-ui-install.sh`, the join token file `/root/.3ax-ui-join-token` | the LE IP certificate `/root/cert/ip` and acme.sh with its renewal; `-e hop_wipe_le_cert=true` also deletes `/root/cert/ip` and acme.sh's IP certificate dirs (`/root/.acme.sh/<ip>[_ecc]`) |
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
| panel | `x-ui -v` = `xui_version`; API login with the vault account (`POST <base>login`); `GET <base>panel/api/chain/list`: every hop of group `hops` (by `hop_name`, default the inventory hostname) is `joined`, and `activeEdge` is the hop with `hop_active: true`; registry hops the inventory does not list are reported |
| hops | `x-ui -v` = `xui_version`; `x-ui chain status -c /etc/x-ui/proxy.json` is fresh: it answers as `hop_name`, the revision is not `stale`, the next hop is `reachable: true`, the relay is `running=true` (up to 1 minute: `hop_verify_retries` x `hop_verify_delay`) |
| monserver | `mon-server version` = `mon_version`; admin login (`POST /admin/login`); `GET /admin/api/settings` has `panelUrl` and `monToken`; `POST /admin/api/settings/check` with the saved `panelUrl`/`monToken`/`panelCa`/`realHost` answers `Panel reachable.` (the probe configs are readable too) |
| monclient | `mon-client version` = `mon_version`; in `GET /admin/api/clients` the record named `mon_name` is enabled, has a live token and is `ONLINE` (up to 3 minutes) |
| panel (with mon-clients) | `GET <base>panel/api/monitoring/targets`: the panel's contact with mon-server is not stale, there are targets, every mon-client has targets, and every target of an enabled inbound is `UP` (targets of disabled inbounds are `PAUSED` by design and ignored); up to 3 minutes (`panel_verify_targets_retries` x `panel_verify_targets_delay`) |

## Prerequisites

- Python 3.12+ on the controller; `pip install -r requirements.txt` and
  `ansible-galaxy collection install -r requirements.yml`.
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
   mon-client); versions in `inventories/<profile>/group_vars/all/main.yml`.
5. **Wipe**, then **converge**; `site.yml` ends with `verify.yml`:
   ```sh
   ansible-playbook -i inventories/stand-full wipe.yml -e wipe_confirm=yes --ask-vault-pass
   ansible-playbook -i inventories/stand-full site.yml --ask-vault-pass
   ```
   A fresh panel gets new inbounds and a new chain registry, so clients' subscriptions from before the
   wipe are dead. Keep the output of both runs if the run is the resolution of a ticket.
6. **Verify alone**, any time later (read-only):
   ```sh
   ansible-playbook -i inventories/stand-full verify.yml --ask-vault-pass
   ```

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
- The panel uses its own self-signed certificate: no LE.

## Development

CI (`.github/workflows/ci.yml`) runs `ansible-lint` with the `production` profile (`.ansible-lint`),
`ansible-playbook --syntax-check` of every playbook against every inventory,
`tests/hop/test_hop_role.py`: role hop on local stand-in hosts against `tests/hop/mock_panel.py` (the panel
chain API: login, list/add/update/reissueToken/setActive/del with the panel's refusals) and a fake
install.sh — fresh chain replacing `legacy`, idempotent rerun, new version, new host, broken box, LE
certificate reuse, pruning, check mode, refusals, `--limit`, no token or cookie in `-vvv` output; the
panel and hop plays of `verify.yml` on the converged chain and on a registry, a box and a version that are
wrong; `tests/wipe/test_wipe.py`: `wipe.yml` on local stand-in boxes — refusal, what goes and what stays,
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
  python3 tests/hop/test_hop_role.py && python3 tests/wipe/test_wipe.py'
```

## License

GPL-3.0-only, see [LICENSE](LICENSE) (same as upstream 3x-ui).
