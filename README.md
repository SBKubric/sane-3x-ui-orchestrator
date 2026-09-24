# 3ax-ui-orchestrator

Ansible that deploys a whole 3ax-ui installation from an inventory: the panel
([SBKubric/3ax-ui-proxy](https://github.com/SBKubric/3ax-ui-proxy)), its proxy chain hops, and
monitoring ([SBKubric/3ax-ui-monitoring](https://github.com/SBKubric/3ax-ui-monitoring): mon-server and
mon-client). Design: [SBKubric/3ax-ui-monitoring#55](https://github.com/SBKubric/3ax-ui-monitoring/issues/55).

> Status: skeleton. Role `common` is real; roles `panel`, `hop`, `monserver`, `monclient`,
> `wipe.yml` and `verify.yml` are no-op stubs, implemented in #2–#5.

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
  panel/  hop/  monserver/  monclient/   (stubs; variables documented in defaults/main.yml)
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
