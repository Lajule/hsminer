#!/usr/bin/env bash

MODULE="/usr/lib/softhsm/libsofthsm2.so"
SLOT="$(softhsm2-util --init-token --slot 0 --label "token 1" --so-pin 1234 --pin 1234 | grep -E -o '[0-9]+')"
pkcs11-tool --module "${MODULE}" --slot "${SLOT}" --login --pin 1234 --keygen --key-type aes:32 --label "key 1"
echo "${SLOT}"
