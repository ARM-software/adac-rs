#!/usr/bin/env bash

set -euo pipefail

if [ -z "${ADAC_CLI:-}" ] ; then \
  echo "Set ADAC_CLI variable with path to 'adac-cli' binary" ; \
  exit 1 ; \
fi

TEST_DIR=$(dirname "$0")
KEYS_DIR=$(realpath "$TEST_DIR")/resources/keys
CFG_FILE=$(realpath "$TEST_DIR")/test-config.toml
TEST_DIR=${ADAC_TEST_OUTPUT_DIR:-"$(realpath "$TEST_DIR")/offline"}

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-0.pk8" -pubout -out "${TEST_DIR}/EcdsaP384Key-0.pub" 
openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-1.pk8" -pubout -out "${TEST_DIR}/EcdsaP384Key-1.pub"
openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-2.pk8" -pubout -out "${TEST_DIR}/EcdsaP384Key-2.pub"

# Self-signed Root CA
"${ADAC_CLI}" certificate-sign "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-0.pub" \
    -p "${KEYS_DIR}/EcdsaP384Key-0.pk8" -s root -o "${TEST_DIR}/root.crt"

# Create pre-certificate +  TBS file + Hash file
"${ADAC_CLI}" certificate-offline-prepare "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-1.pub" -s intermediate \
    -o "${TEST_DIR}/inter-off.pre" -t "${TEST_DIR}/inter-off.tbs" --hash "${TEST_DIR}/inter-off.hash"

# Sign TBS
openssl pkeyutl -sign -in "${TEST_DIR}/inter-off.tbs" -inkey "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
  -out "${TEST_DIR}/inter-off.sig" -digest sha384

# Merge TBS signature
"${ADAC_CLI}" certificate-offline-merge "${TEST_DIR}/inter-off.pre" "${TEST_DIR}/inter-off.sig" \
    -i "${TEST_DIR}/root.crt" -o "${TEST_DIR}/inter-off.crt"
"${ADAC_CLI}" verify "${TEST_DIR}/inter-off.crt"

# Add a leaf certificate so token validation can exercise a leaf-terminated chain.
"${ADAC_CLI}" certificate-sign "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-2.pub" \
    -i "${TEST_DIR}/inter-off.crt" -p "${KEYS_DIR}/EcdsaP384Key-1.pk8" \
    -s leaf -o "${TEST_DIR}/leaf.crt"

CHALLENGE=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# Create pre-token + TBS file + Hash file
"${ADAC_CLI}" token-offline-prepare "${CHALLENGE}" EcdsaP384Sha384 -c "${CFG_FILE}" \
    -s token -o "${TEST_DIR}/token-off.pre" -t "${TEST_DIR}/token-off.tbs" \
    --hash "${TEST_DIR}/token-off.hash"

# Sign token TBS
openssl pkeyutl -sign -in "${TEST_DIR}/token-off.tbs" -inkey "${KEYS_DIR}/EcdsaP384Key-2.pk8" \
  -out "${TEST_DIR}/token-off.sig" -digest sha384

# Merge token TBS signature
"${ADAC_CLI}" token-offline-merge "${TEST_DIR}/token-off.pre" "${TEST_DIR}/token-off.sig" \
    --chain "${TEST_DIR}/leaf.crt" --challenge "${CHALLENGE}" -o "${TEST_DIR}/token-off.bin"
"${ADAC_CLI}" verify "${TEST_DIR}/leaf.crt" --token "${TEST_DIR}/token-off.bin" \
    --challenge "${CHALLENGE}" --strict

# Sign Hash
openssl pkeyutl -sign -in "${TEST_DIR}/inter-off.hash" -inkey "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
  -out "${TEST_DIR}/inter-off.sig" -pkeyopt digest:sha384

# Merge Hash signature
"${ADAC_CLI}" certificate-offline-merge "${TEST_DIR}/inter-off.pre" "${TEST_DIR}/inter-off.sig" \
    -i "${TEST_DIR}/root.crt" -o "${TEST_DIR}/inter-off.crt"
"${ADAC_CLI}" verify "${TEST_DIR}/inter-off.crt"
