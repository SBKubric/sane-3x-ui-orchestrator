#!/bin/bash

VAULT_LOCATION=$1
echo $VAULT_LOCATION
unset O1; unfunction O1 2>/dev/null                                             
cd /usr/src/app/3ax-ui/3ax-ui-orchestrator
vault() { docker run --rm -i --user $(id -u):$(id -g) -e HOME=/tmp -v $PWD:/o -v $HOME/.3ax-vault-pass:/vp:ro -w /o o1-ansible:latest ansible-vault "$@" --vault-password-file /vp; }
(umask 077; vault decrypt --output - $VAULT_LOCATION > /dev/shm/vault.yml) && ${EDITOR:-nano} /dev/shm/vault.yml && vault encrypt --output $VAULT_LOCATION - < /dev/shm/vault.yml; shred -u /dev/shm/vault.yml
