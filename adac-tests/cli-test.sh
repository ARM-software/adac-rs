#!/usr/bin/env bash

set -e

if [ -z "$ADAC_CLI" ] ; then
  echo "Set ADAC_CLI variable with path to 'adac-cli' binary"
  exit 1
fi

BASE_DIR=$(dirname "$0")
KEYS_DIR=$(realpath "$BASE_DIR")/resources/keys
CFG_FILE=$(realpath "$BASE_DIR")/test-config.toml
TEST_DIR=$(realpath "$BASE_DIR")/cli
CHALLENGE=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

for i in 0 1 2 3; do
  openssl pkey -in "${KEYS_DIR}/EcdsaP384Key-${i}.pk8" \
    -pubout -out "${TEST_DIR}/EcdsaP384Key-${i}.pub"
done

sign_chain() {
  local leaf_section=$1
  local output=$2

  "${ADAC_CLI}" certificate-sign "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-0.pub" \
    -p "${KEYS_DIR}/EcdsaP384Key-0.pk8" -s root -o "${TEST_DIR}/${output}-root.crt"

  "${ADAC_CLI}" certificate-sign "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-1.pub" \
    -i "${TEST_DIR}/${output}-root.crt" -p "${KEYS_DIR}/EcdsaP384Key-0.pk8" \
    -s intermediate_effective -o "${TEST_DIR}/${output}-inter1.crt"

  "${ADAC_CLI}" certificate-sign "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-2.pub" \
    -i "${TEST_DIR}/${output}-inter1.crt" -p "${KEYS_DIR}/EcdsaP384Key-1.pk8" \
    -s intermediate_policy -o "${TEST_DIR}/${output}-inter2.crt"

  "${ADAC_CLI}" certificate-sign "${CFG_FILE}" "${TEST_DIR}/EcdsaP384Key-3.pub" \
    -i "${TEST_DIR}/${output}-inter2.crt" -p "${KEYS_DIR}/EcdsaP384Key-2.pk8" \
    -s "${leaf_section}" -o "${TEST_DIR}/${output}.crt"
}

sign_token() {
  local section=$1
  local chain=$2
  local output=$3

  "${ADAC_CLI}" token-sign "${CHALLENGE}" -c "${CFG_FILE}" -s "${section}" \
    -p "${KEYS_DIR}/EcdsaP384Key-3.pk8" --chain "${chain}" -o "${output}"
}

# Shell equivalent of verify_command_reports_effective(), with token signature validation.
sign_chain leaf_soc_id effective
sign_token token "${TEST_DIR}/effective.crt" "${TEST_DIR}/effective-token.bin"
"${ADAC_CLI}" verify "${TEST_DIR}/effective.crt" \
  --token "${TEST_DIR}/effective-token.bin" --challenge "${CHALLENGE}" --strict

# Shell equivalent of verify_command_reports_token_soc_id_extension().
sign_chain leaf token-soc-id
sign_token token_soc_id "${TEST_DIR}/token-soc-id.crt" "${TEST_DIR}/token-soc-id.bin"
"${ADAC_CLI}" verify "${TEST_DIR}/token-soc-id.crt" \
  --token "${TEST_DIR}/token-soc-id.bin" --challenge "${CHALLENGE}" --strict
