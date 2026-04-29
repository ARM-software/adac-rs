#!/usr/bin/env bash

set -euo pipefail

# Run Kryoptic-backed PKCS#11 ML-DSA tests.
#
# Prerequisites:
#   cargo build
#   export KRYOPTIC_BIN=$HOME/local/bin/kryoptic_init
#   export KRYOPTIC_LIB=$HOME/local/lib/libkryoptic_pkcs11.dylib
#   export ADAC_CLI=$PWD/target/debug/adac-cli
#
# Optional:
#   export ADAC_PKCS11_TEST=$PWD/target/debug/adac_pkcs11_test
#   export PKCS11_SLOT=test-token
#   export PKCS11_PIN=1234
#   export PKCS11_SOPIN=4321
#
# Then run:
#   ./adac-tests/pkcs11-test-krypoptic.sh
#
# This script initializes a throwaway Kryoptic token database under
# adac-tests/kryoptic and exercises the ML-DSA PKCS#11 path. It is not part of
# the default SoftHSM-backed PKCS#11 test harness or CI.

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ] ; then
    echo "Set ${name} environment variable" >&2
    exit 1
  fi
}

require_env ADAC_CLI
require_env KRYOPTIC_LIB
require_env KRYOPTIC_BIN

if [ ! -r "${KRYOPTIC_LIB}" ] ; then
  echo "KRYOPTIC_LIB does not point to a readable PKCS#11 module: ${KRYOPTIC_LIB}" >&2
  exit 1
fi

if [ ! -x "${KRYOPTIC_BIN}" ] ; then
  echo "KRYOPTIC_BIN does not point to an executable kryoptic_init binary: ${KRYOPTIC_BIN}" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1 ; then
  echo "jq is required to parse adac-cli JSON output" >&2
  exit 1
fi

PKCS11_SLOT="${PKCS11_SLOT:-test-token}"
PKCS11_PIN="${PKCS11_PIN:-1234}"
PKCS11_SOPIN="${PKCS11_SOPIN:-4321}"

TEST_ROOT="$(realpath "$(dirname "$0")")"
TST_FILE="${TEST_ROOT}/test-config.toml"
TEST_DIR="${TEST_ROOT}/kryoptic"
CFG_FILE="${TEST_DIR}/kryoptic.conf"
DB_FILE="${TEST_DIR}/token.sql"
ADAC_PKCS11_TEST="${ADAC_PKCS11_TEST:-${TEST_ROOT}/../target/debug/adac_pkcs11_test}"

if [ ! -x "${ADAC_PKCS11_TEST}" ] ; then
  echo "ADAC_PKCS11_TEST does not point to an executable adac_pkcs11_test binary: ${ADAC_PKCS11_TEST}" >&2
  echo "Build it with: cargo build -p adac-tests --bin adac_pkcs11_test" >&2
  exit 1
fi

rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}"
cat <<EOF > "${CFG_FILE}"
[ec_point_encoding]
encoding = "Bytes"

[[slots]]
slot = 1
description = "ADAC Kryoptic test token"
manufacturer = "Kryoptic"
dbtype = "sqlite"
dbargs = "${DB_FILE}"
EOF
export KRYOPTIC_CONF="${CFG_FILE}"

"${KRYOPTIC_BIN}" \
  --pkcs11-module "${KRYOPTIC_LIB}" \
  --pin "${PKCS11_PIN}" \
  --so-pin "${PKCS11_SOPIN}" \
  --token-label "${PKCS11_SLOT}"

"${ADAC_PKCS11_TEST}" check --module "${KRYOPTIC_LIB}" --pin "${PKCS11_PIN}" --label "${PKCS11_SLOT}"
"${ADAC_PKCS11_TEST}" test --module "${KRYOPTIC_LIB}" --pin "${PKCS11_PIN}" --label "${PKCS11_SLOT}"

pkcs11_args=(--module "${KRYOPTIC_LIB}" --slot "${PKCS11_SLOT}" --pin "${PKCS11_PIN}")

generate_key() {
  local key_type="$1"
  local alg_dir="$2"
  local key_index="$3"

  "${ADAC_CLI}" --output-format json pkcs11-keygen \
    "${key_type}" "${pkcs11_args[@]}" > "${alg_dir}/key${key_index}.json"
  jq -r '.pkcs11_generate.kid' "${alg_dir}/key${key_index}.json" > "${alg_dir}/key${key_index}.kid"
  jq -r '.pkcs11_generate.pem' "${alg_dir}/key${key_index}.json" > "${alg_dir}/key${key_index}.pub"
}

run_key_type() {
  local key_type="$1"
  local alg_dir="${TEST_DIR}/${key_type}"

  echo ""
  echo "### ${key_type}"
  mkdir -p "${alg_dir}"

  generate_key "${key_type}" "${alg_dir}" 0
  generate_key "${key_type}" "${alg_dir}" 1
  generate_key "${key_type}" "${alg_dir}" 2

  local key0_id
  key0_id="$(cat "${alg_dir}/key0.kid")"
  local key1_id
  key1_id="$(cat "${alg_dir}/key1.kid")"

  "${ADAC_CLI}" certificate-sign "${TST_FILE}" "${alg_dir}/key0.pub" "${pkcs11_args[@]}" \
    -k "${key0_id}" -s root -o "${alg_dir}/root.crt"

  "${ADAC_CLI}" certificate-sign "${TST_FILE}" "${alg_dir}/key1.pub" "${pkcs11_args[@]}" \
    -k "${key0_id}" -s intermediate -i "${alg_dir}/root.crt" -o "${alg_dir}/inter.crt"

  "${ADAC_CLI}" certificate-sign "${TST_FILE}" "${alg_dir}/key2.pub" "${pkcs11_args[@]}" \
    -k "${key1_id}" -s crt1 -i "${alg_dir}/inter.crt" -o "${alg_dir}/crt1.crt"
  "${ADAC_CLI}" verify "${alg_dir}/crt1.crt"
}

run_key_type MlDsa44Sha256
run_key_type MlDsa65Sha384
run_key_type MlDsa87Sha512
