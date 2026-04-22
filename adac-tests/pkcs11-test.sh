#!/usr/bin/env bash

set -e

if [ -z "$ADAC_CLI" ] ; then \
  echo "Set ADAC_CLI variable with path to 'adac-cli' binary" ; \
  exit 1 ; \
fi

PKCS11_SLOT=test-token
PKCS11_PIN=1234
PKCS11_SOPIN=4321

TEST_DIR=$(dirname "$0")
TST_FILE="$(realpath "$TEST_DIR")/test-config.toml"
TEST_DIR="$(realpath "$TEST_DIR")/softhsm2"
CFG_FILE="$(realpath "$TEST_DIR")/softhsm2.conf"

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/tokens"
cat <<EOF > "${CFG_FILE}"
directories.tokendir = ${TEST_DIR}/tokens
objectstore.backend = file
objectstore.umask = 0077
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOF
export SOFTHSM2_CONF="${CFG_FILE}"

if [ -z "${PKCS11_MODULE:-}" ] ; then
  OS=$(uname -s)
  ARCH=$(uname -m)

  case "${OS}:${ARCH}" in
    Darwin:arm64) PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so ;;
    Linux:aarch64) PKCS11_MODULE=/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so ;;
    Linux:x86_64) PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so ;;
    *) echo "Unsupported platform for default PKCS11_MODULE: ${OS} ${ARCH}" >&2 ; exit 1 ;;
  esac
fi

softhsm2-util --show-slots
softhsm2-util --init-token --free --label "${PKCS11_SLOT}" --pin "${PKCS11_PIN}" --so-pin "${PKCS11_SOPIN}"

pkcs11_args=(--module "${PKCS11_MODULE}" --slot "${PKCS11_SLOT}" --pin "${PKCS11_PIN}")

# Generate Key 0
"${ADAC_CLI}" --output-format json pkcs11-keygen \
    EcdsaP384Sha384 "${pkcs11_args[@]}" > "${TEST_DIR}/key0.json"
KEY0_ID=$(jq -r '.pkcs11_generate.kid' "${TEST_DIR}/key0.json")
jq -r '.pkcs11_generate.pem' "${TEST_DIR}/key0.json" > "${TEST_DIR}/key0.pub"

# Generate Key 1
"${ADAC_CLI}" --output-format json pkcs11-keygen \
    EcdsaP384Sha384 "${pkcs11_args[@]}" > "${TEST_DIR}/key1.json"
KEY1_ID=$(jq -r '.pkcs11_generate.kid' "${TEST_DIR}/key1.json")
jq -r '.pkcs11_generate.pem' "${TEST_DIR}/key1.json" > "${TEST_DIR}/key1.pub"

# Generate Key 2
"${ADAC_CLI}" --output-format json pkcs11-keygen \
    EcdsaP384Sha384 "${pkcs11_args[@]}" > "${TEST_DIR}/key2.json"
KEY2_ID=$(jq -r '.pkcs11_generate.kid' "${TEST_DIR}/key2.json")
jq -r '.pkcs11_generate.pem' "${TEST_DIR}/key2.json" > "${TEST_DIR}/key2.pub"

"${ADAC_CLI}" sign "${TST_FILE}" "${TEST_DIR}/key0.pub" "${pkcs11_args[@]}" \
    -k "${KEY0_ID}" -s root -o "${TEST_DIR}/root.crt"

"${ADAC_CLI}" sign "${TST_FILE}" "${TEST_DIR}/key1.pub" "${pkcs11_args[@]}" \
    -k "${KEY0_ID}" -s intermediate -i "${TEST_DIR}/root.crt" -o "${TEST_DIR}/inter.crt"

### Sign Test 1 certificate
echo ""
"${ADAC_CLI}" sign "${TST_FILE}" "${TEST_DIR}/key2.pub" "${pkcs11_args[@]}" \
    -k "${KEY1_ID}" -s crt1 -i "${TEST_DIR}/inter.crt" -o "${TEST_DIR}/crt1.crt"
"${ADAC_CLI}" verify "${TEST_DIR}/crt1.crt"

### Sign Test 2 certificate
echo ""
"${ADAC_CLI}" sign "${TST_FILE}" "${TEST_DIR}/key2.pub" "${pkcs11_args[@]}" \
    -k "${KEY1_ID}" -s crt2 -i "${TEST_DIR}/inter.crt" -o "${TEST_DIR}/crt2.crt"
"${ADAC_CLI}" verify "${TEST_DIR}/crt2.crt"

### Sign Test 3 certificate
echo ""
"${ADAC_CLI}" sign "${TST_FILE}" "${TEST_DIR}/key2.pub" "${pkcs11_args[@]}" \
    -k  "${KEY1_ID}" -s crt3 -i "${TEST_DIR}/inter.crt" -o "${TEST_DIR}/crt3.crt"
"${ADAC_CLI}" verify "${TEST_DIR}/crt3.crt"
