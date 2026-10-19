#!/bin/bash
# Definições comuns a falcon.sh e xwing.sh: localização dos programas,
# criação de um token de teste isolado e funções que conferem cada etapa.
set -euo pipefail

CROSS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$CROSS_DIR/build"
OUT_DIR="$CROSS_DIR/out"

BC_VERSION="1.86"
BC_SHA256="2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f"
BC_JAR="$BUILD_DIR/bcprov-jdk18on-$BC_VERSION.jar"

# Lidas pelos clientes C (ver c/p11.h). O módulo pode ser sobrescrito
# para usar uma compilação fora do container.
export SOFTHSM_MODULE="${SOFTHSM_MODULE:-/opt/softhsm2/lib/softhsm/libsofthsm2.so}"
export TOKEN_LABEL="validacao-cruzada"
export USER_PIN="1234"
SO_PIN="12345678"

# Interrompe a validação se setup.sh ainda não foi executado.
require_setup() {
    if [ ! -x "$BUILD_DIR/falcon_softhsm" ] || [ ! -x "$BUILD_DIR/xwing_softhsm" ] ||
       [ ! -f "$BC_JAR" ]; then
        echo "Ambiente não preparado: execute ./setup.sh antes." >&2
        exit 2
    fi
}

# Executa um cliente C do SoftHSM ou um programa Java do Bouncy Castle.
softhsm() { "$BUILD_DIR/$1" "${@:2}"; }
bc()      { java -cp "$BC_JAR:$BUILD_DIR/classes" "$@"; }

# Cria, em $1, um diretório de trabalho com um token SoftHSM novo, separado
# dos tokens do ambiente de desenvolvimento.
create_token() {
    local work_dir="$1"

    rm -rf "$work_dir"
    mkdir -p "$work_dir/tokens"
    cat > "$work_dir/softhsm2.conf" <<EOF
directories.tokendir = $work_dir/tokens
objectstore.backend = file
EOF
    export SOFTHSM2_CONF="$work_dir/softhsm2.conf"
    softhsm2-util --module "$SOFTHSM_MODULE" --init-token --free --label "$TOKEN_LABEL" \
        --pin "$USER_PIN" --so-pin "$SO_PIN" > /dev/null
}

pass() { echo "  OK    $1"; }
fail() { echo "  FALHA $1"; exit 1; }

# Executa o comando e exige assinatura válida (código de saída 0).
expect_valid() {
    local description="$1"; shift
    if "$@"; then pass "$description"; else fail "$description"; fi
}

# Executa o comando e exige assinatura rejeitada (código de saída 1).
# Qualquer outro código indica erro e também conta como falha.
expect_invalid() {
    local description="$1"; shift
    local status=0
    "$@" || status=$?
    if [ "$status" -eq 1 ]; then pass "$description"; else fail "$description"; fi
}

expect_same() {
    if cmp -s "$2" "$3"; then pass "$1"; else fail "$1"; fi
}

expect_different() {
    if cmp -s "$2" "$3"; then fail "$1"; else pass "$1"; fi
}
