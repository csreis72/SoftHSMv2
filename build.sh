#!/bin/bash
set -e

SCRIPT_NAME="$(basename "$0")"
PREFIX="/opt/softhsm2"
BUILD_DIR="/src/build"
SRC_DIR="/src"

log() {
    echo "[${SCRIPT_NAME}] $*"
}

FORCE_RECONFIGURE=false
if [ "$1" == "--reconfigure" ]; then
    FORCE_RECONFIGURE=true
fi

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

if [ ! -f "${SRC_DIR}/configure" ]; then
    log "INFO: configure script not found, running autogen.sh"
    (cd "${SRC_DIR}" && sh autogen.sh)
fi

if [ ! -f ./config.status ] || [ "${FORCE_RECONFIGURE}" = true ]; then
    log "INFO: running configure"
    "${SRC_DIR}/configure" \
        --prefix="${PREFIX}" \
        --with-crypto-backend=openssl \
        --with-openssl=/opt/openssl \
        --with-objectstore-backend-db \
        LDFLAGS="-L/opt/openssl/lib64" \
        CPPFLAGS="-I/opt/openssl/include"
else
    log "INFO: config.status found, skipping configure (use --reconfigure to force)"
fi

log "INFO: building"
make -j"$(nproc)"

log "INFO: running tests"
make check

log "INFO: installing to ${PREFIX}"
make install

log "INFO: build completed successfully"