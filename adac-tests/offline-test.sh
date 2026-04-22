#!/usr/bin/env bash

set -e

if [ -z "$ADAC_CLI" ] ; then \
  echo "Set ADAC_CLI variable with path to 'adac-cli' binary" ; \
  exit 1 ; \
fi

TEST_DIR=$(dirname "$0")
KEYS_DIR=$(realpath "$TEST_DIR")/resources/keys
CFG_FILE=$(realpath "$TEST_DIR")/test-config.toml
TEST_DIR=$(realpath "$TEST_DIR")/offline

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-0.pk8" -pubout -out "${TEST_DIR}/EcdsaP384Key-0.pub" 
openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-1.pk8" -pubout -out "${TEST_DIR}/EcdsaP384Key-1.pub"

# Self-signed Root CA
"${ADAC_CLI}" sign "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-0.pub" \
    -p "${KEYS_DIR}/EcdsaP384Key-0.pk8" -s root -o "${TEST_DIR}/root.crt"

# Create pre-certificate +  TBS file + Hash file
"${ADAC_CLI}" offline-prepare "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-1.pub" -s intermediate \
    -o "${TEST_DIR}/inter-off.pre" -t "${TEST_DIR}/inter-off.tbs" --hash "${TEST_DIR}/inter-off.hash"

# Sign TBS
openssl pkeyutl -sign -in "${TEST_DIR}/inter-off.tbs" -inkey "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
  -out "${TEST_DIR}/inter-off.sig" -digest sha384

# Merge TBS signature
"${ADAC_CLI}" offline-merge "${TEST_DIR}/inter-off.pre" "${TEST_DIR}/inter-off.sig" \
    -i "${TEST_DIR}/root.crt" -o "${TEST_DIR}/inter-off.crt"
"${ADAC_CLI}" verify "${TEST_DIR}/inter-off.crt"

# Sign Hash
openssl pkeyutl -sign -in "${TEST_DIR}/inter-off.hash" -inkey "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
  -out "${TEST_DIR}/inter-off.sig" -pkeyopt digest:sha384

# Merge Hash signature
"${ADAC_CLI}" offline-merge "${TEST_DIR}/inter-off.pre" "${TEST_DIR}/inter-off.sig" \
    -i "${TEST_DIR}/root.crt" -o "${TEST_DIR}/inter-off.crt"
"${ADAC_CLI}" verify "${TEST_DIR}/inter-off.crt"
