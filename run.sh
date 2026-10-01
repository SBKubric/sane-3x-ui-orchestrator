#!/usr/bin/env bash
# Runs a playbook against an inventory profile, in the operator's ansible image (or natively).
#
#   ./run.sh <profile> site     [ansible-playbook args...]   converge (ends with verify.yml)
#   ./run.sh <profile> verify   [ansible-playbook args...]   checks only
#   ./run.sh <profile> wipe     [ansible-playbook args...]   destroy everything on the profile's hosts (asks first)
#   ./run.sh <profile> ping     [ansible args...]            reach every host of the profile
#
#   e.g. ./run.sh production site --tags panel,hops
#        ./run.sh stand-full site -e awg_obfuscation_apply=true
#
# Environment:
#   VAULT_PASS_FILE  the vault password file (default ~/.3ax-vault-pass)
#   ANSIBLE_IMAGE    the docker image with ansible (default o1-ansible:latest); "native" runs the local ansible
#   LOG_DIR          where each run's output is kept (default ./logs, git-ignored)
# The profile's vault is inventories/<profile>/group_vars/all/vault.yml (README "Vault"); ssh reaches the hosts with
# the keys in ~/.ssh (the image gets a root-owned copy).
set -euo pipefail
cd "$(dirname "$0")"

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
die() { echo "run.sh: $*" >&2; exit 1; }

[ $# -ge 2 ] || usage
profile=$1 action=$2
shift 2
[ -f "inventories/$profile/hosts.yml" ] || die "no profile inventories/$profile (have: $(find inventories -mindepth 1 -maxdepth 1 -type d -printf '%f ' | sort))"
[ -f "inventories/$profile/group_vars/all/vault.yml" ] || die "no vault inventories/$profile/group_vars/all/vault.yml (template: inventories/vault.yml.example)"
[ ! -e group_vars/all/vault.yml ] || die "group_vars/all/vault.yml is the old vault shared by every profile: move it into inventories/<profile>/group_vars/all/"
pass=${VAULT_PASS_FILE:-$HOME/.3ax-vault-pass}
[ -f "$pass" ] || die "no vault password file $pass (set VAULT_PASS_FILE)"

case $action in
  site | verify) cmd=(ansible-playbook -i "inventories/$profile" "$action.yml") ;;
  wipe)
    echo "wipe.yml destroys the installation on every host of '$profile':"
    sed -n '/^all:/,$p' "inventories/$profile/hosts.yml" | grep -E '^ {8}[a-z0-9-]+:$' | tr -d ' :' | sed 's/^/  /'
    read -r -p "Type the profile name to go on: " answer
    [ "$answer" = "$profile" ] || die "not confirmed"
    cmd=(ansible-playbook -i "inventories/$profile" wipe.yml -e wipe_confirm=yes) ;;
  ping) cmd=(ansible -i "inventories/$profile" all -m ansible.builtin.ping) ;;
  *) usage ;;
esac

log_dir=${LOG_DIR:-logs}
mkdir -p "$log_dir"
log="$log_dir/$profile-$action-$(date +%Y%m%d-%H%M%S).log"
echo "run.sh: $profile $action, log $log"

image=${ANSIBLE_IMAGE:-o1-ansible:latest}
if [ "$image" = native ]; then
  ANSIBLE_VAULT_PASSWORD_FILE="$pass" "${cmd[@]}" "$@" 2>&1 | tee "$log"
  exit "${PIPESTATUS[0]}"
fi

tty=(); [ -t 0 ] && [ -t 1 ] && tty=(-t)
docker run --rm "${tty[@]}" --network host \
  -v "$HOME/.ssh:/src-ssh:ro" -v "$(realpath "$pass"):/vault-pass:ro" \
  -v "$PWD:/w" -v gal-3ax:/root/.ansible -w /w \
  -e ANSIBLE_VAULT_PASSWORD_FILE=/vault-pass -e ANSIBLE_FORCE_COLOR="${ANSIBLE_FORCE_COLOR:-1}" \
  "$image" sh -c 'cp -r /src-ssh /root/.ssh && chown -R root:root /root/.ssh && chmod -R go-rwx /root/.ssh
    git config --global --add safe.directory "*" 2>/dev/null
    ansible-galaxy collection install -r requirements.yml >/dev/null 2>&1 || true
    exec "$@"' _ "${cmd[@]}" "$@" 2>&1 | tee "$log"
exit "${PIPESTATUS[0]}"
