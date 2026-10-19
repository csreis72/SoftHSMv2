#!/bin/bash
# Validação cruzada do X-Wing entre o SoftHSMv2 e o Bouncy Castle.
# Um lado gera o par de chaves, o outro encapsula um segredo para a chave
# pública e o segredo decapsulado deve ser idêntico ao encapsulado. Um
# texto cifrado alterado deve produzir um segredo diferente.
source "$(dirname "$0")/common.sh"
require_setup

# Copia o texto cifrado $1 para $2 zerando os 16 primeiros bytes (parte ML-KEM).
tamper() {
    { head -c 16 /dev/zero; tail -c +17 "$1"; } > "$2"
}

dir="$OUT_DIR/xwing"
echo "X-Wing"
create_token "$dir"

# Chave no SoftHSM, encapsulamento no Bouncy Castle
softhsm xwing_softhsm keygen "$dir/softhsm.pub"
bc XWingBC encaps "$dir/softhsm.pub" "$dir/bc.ct" "$dir/bc-encaps.ss"
softhsm xwing_softhsm decaps "$dir/bc.ct" "$dir/softhsm-decaps.ss"
expect_same "SoftHSM obtém o segredo encapsulado pelo BC" \
    "$dir/bc-encaps.ss" "$dir/softhsm-decaps.ss"

tamper "$dir/bc.ct" "$dir/bc-altered.ct"
softhsm xwing_softhsm decaps "$dir/bc-altered.ct" "$dir/softhsm-altered.ss"
expect_different "SoftHSM obtém outro segredo para texto cifrado alterado" \
    "$dir/bc-encaps.ss" "$dir/softhsm-altered.ss"

# Chave no Bouncy Castle, encapsulamento no SoftHSM
bc XWingBC keygen "$dir/bc.pub" "$dir/bc.key"
softhsm xwing_softhsm encaps "$dir/bc.pub" "$dir/softhsm.ct" "$dir/softhsm-encaps.ss"
bc XWingBC decaps "$dir/bc.key" "$dir/softhsm.ct" "$dir/bc-decaps.ss"
expect_same "BC obtém o segredo encapsulado pelo SoftHSM" \
    "$dir/softhsm-encaps.ss" "$dir/bc-decaps.ss"

tamper "$dir/softhsm.ct" "$dir/softhsm-altered.ct"
bc XWingBC decaps "$dir/bc.key" "$dir/softhsm-altered.ct" "$dir/bc-altered.ss"
expect_different "BC obtém outro segredo para texto cifrado alterado" \
    "$dir/softhsm-encaps.ss" "$dir/bc-altered.ss"

echo "Validação cruzada do X-Wing concluída com sucesso"
