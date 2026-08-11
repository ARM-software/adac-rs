#!/usr/bin/env bash

set -euo pipefail

if [ -z "${ADAC_CLI:-}" ]; then
  echo "Set ADAC_CLI variable with path to 'adac-cli' binary"
  exit 1
fi

BASE_DIR=$(realpath "$(dirname "$0")")
KEYS_DIR="${BASE_DIR}/resources/keys"
CFG_FILE="${BASE_DIR}/test-config.toml"
TEST_DIR=${ADAC_TEST_OUTPUT_DIR:-"${BASE_DIR}/offline/mldsa"}
CHALLENGE=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}"

run_parameter_set() {
  local parameter_set=$1
  local key_type=$2
  local algorithm_dir="${TEST_DIR}/${key_type}"

  mkdir -p "${algorithm_dir}"

  for key_index in 0 1 2; do
    openssl pkey \
      -in "${KEYS_DIR}/MlDsa${parameter_set}Key-${key_index}.pk8" \
      -pubout \
      -out "${algorithm_dir}/key-${key_index}.pub"
  done

  # Create a self-signed root certificate entirely through the offline flow.
  "${ADAC_CLI}" certificate-offline-prepare \
    "${CFG_FILE}" "${algorithm_dir}/key-0.pub" \
    --section root \
    --output "${algorithm_dir}/root.pre" \
    --tbs "${algorithm_dir}/root.tbs" \
    --hash "${algorithm_dir}/root.hash"

  openssl pkeyutl -sign \
    -inkey "${KEYS_DIR}/MlDsa${parameter_set}Key-0.pk8" \
    -in "${algorithm_dir}/root.tbs" \
    -out "${algorithm_dir}/root.sig"

  "${ADAC_CLI}" certificate-offline-merge \
    "${algorithm_dir}/root.pre" "${algorithm_dir}/root.sig" \
    --output "${algorithm_dir}/root.crt"

  # Create an intermediate certificate signed by the root key.
  "${ADAC_CLI}" certificate-offline-prepare \
    "${CFG_FILE}" "${algorithm_dir}/key-1.pub" \
    --section intermediate \
    --output "${algorithm_dir}/intermediate.pre" \
    --tbs "${algorithm_dir}/intermediate.tbs" \
    --hash "${algorithm_dir}/intermediate.hash"

  openssl pkeyutl -sign \
    -inkey "${KEYS_DIR}/MlDsa${parameter_set}Key-0.pk8" \
    -in "${algorithm_dir}/intermediate.tbs" \
    -out "${algorithm_dir}/intermediate.sig"

  "${ADAC_CLI}" certificate-offline-merge \
    "${algorithm_dir}/intermediate.pre" "${algorithm_dir}/intermediate.sig" \
    --issuer "${algorithm_dir}/root.crt" \
    --output "${algorithm_dir}/intermediate.crt"

  # Create a leaf certificate signed by the intermediate key.
  "${ADAC_CLI}" certificate-offline-prepare \
    "${CFG_FILE}" "${algorithm_dir}/key-2.pub" \
    --section leaf \
    --output "${algorithm_dir}/leaf.pre" \
    --tbs "${algorithm_dir}/leaf.tbs" \
    --hash "${algorithm_dir}/leaf.hash"

  openssl pkeyutl -sign \
    -inkey "${KEYS_DIR}/MlDsa${parameter_set}Key-1.pk8" \
    -in "${algorithm_dir}/leaf.tbs" \
    -out "${algorithm_dir}/leaf.sig"

  "${ADAC_CLI}" certificate-offline-merge \
    "${algorithm_dir}/leaf.pre" "${algorithm_dir}/leaf.sig" \
    --issuer "${algorithm_dir}/intermediate.crt" \
    --output "${algorithm_dir}/chain.crt"

  "${ADAC_CLI}" verify "${algorithm_dir}/chain.crt" --strict

  # Create an authentication token signed by the leaf key.
  "${ADAC_CLI}" token-offline-prepare \
    "${CHALLENGE}" "${key_type}" \
    --config "${CFG_FILE}" \
    --section token \
    --output "${algorithm_dir}/token.pre" \
    --tbs "${algorithm_dir}/token.tbs" \
    --hash "${algorithm_dir}/token.hash"

  openssl pkeyutl -sign \
    -inkey "${KEYS_DIR}/MlDsa${parameter_set}Key-2.pk8" \
    -in "${algorithm_dir}/token.tbs" \
    -out "${algorithm_dir}/token.sig"

  "${ADAC_CLI}" token-offline-merge \
    "${algorithm_dir}/token.pre" "${algorithm_dir}/token.sig" \
    --chain "${algorithm_dir}/chain.crt" \
    --challenge "${CHALLENGE}" \
    --output "${algorithm_dir}/token.bin"

  "${ADAC_CLI}" verify "${algorithm_dir}/chain.crt" \
    --token "${algorithm_dir}/token.bin" \
    --challenge "${CHALLENGE}" \
    --strict
}

run_parameter_set 44 MlDsa44Sha256
run_parameter_set 65 MlDsa65Sha384
run_parameter_set 87 MlDsa87Sha512
