# 3ax-ui-orchestrator

Ansible that deploys a whole 3ax-ui installation from an inventory: the panel
([SBKubric/3ax-ui-proxy](https://github.com/SBKubric/3ax-ui-proxy)), its proxy chain hops, and
monitoring ([SBKubric/3ax-ui-monitoring](https://github.com/SBKubric/3ax-ui-monitoring): mon-server and
mon-client). Design: [SBKubric/3ax-ui-monitoring#55](https://github.com/SBKubric/3ax-ui-monitoring/issues/55).

> Status: roles `common` and `panel` are real; roles `hop`, `monserver`, `monclient`,
> `wipe.yml` and `verify.yml` are no-op stubs, implemented in #3–#5.

## Layout

```
ansible.cfg            roles path, root over ssh, no default inventory
requirements.txt       ansible-core + ansible-lint (pinned)
requirements.yml       collections (pinned)
site.yml               converge: common -> panel -> hops -> monserver -> monclient -> verify.yml
wipe.yml               destroy state for a fresh start; refuses without -e wipe_confirm=yes
verify.yml             non-destructive checks; also imported last by site.yml (tag verify)
group_vars/all/        vault.yml (git-ignored, yours) and vault.yml.example (template)
inventories/
  stand-chain/         panel + hops; monserver/monclient empty
  stand-full/          panel + hops + monserver + monclient
roles/
  common/              supported OS check, base packages, time sync
  panel/               install by tag, self-signed TLS, vault account, Telegram, monitoring token;
                       tasks/api_login.yml is the panel API login helper for other roles
  hop/  monserver/  monclient/   (stubs; variables documented in defaults/main.yml)
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

# From scratch: wipe, then converge.
ansible-playbook -i inventories/stand-full wipe.yml -e wipe_confirm=yes --ask-vault-pass
ansible-playbook -i inventories/stand-full site.yml --ask-vault-pass
```

Tags in `site.yml`: `common`, `panel`, `hops`, `monserver`, `monclient`, `verify`.
`site.yml` only converges and never deletes state; a fresh start is always the explicit `wipe.yml`.

## Development

CI (`.github/workflows/ci.yml`) runs `ansible-lint` with the `production` profile (`.ansible-lint`) and
`ansible-playbook --syntax-check` of every playbook against every inventory. No Molecule. Locally
without an ansible install:

```sh
docker run --rm -v "$PWD":/work -w /work python:3.12-slim sh -c '
  pip install -q -r requirements.txt &&
  ansible-galaxy collection install -r requirements.yml &&
  ansible-lint &&
  for inv in inventories/*/; do for pb in site.yml wipe.yml verify.yml; do
    ansible-playbook -i "$inv" "$pb" --syntax-check; done; done'
```

## License

GPL-3.0-only, see [LICENSE](LICENSE) (same as upstream 3x-ui).
