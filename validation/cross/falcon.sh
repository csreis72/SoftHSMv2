#!/bin/bash
# Validação cruzada do Falcon entre o SoftHSMv2 e o Bouncy Castle.
# Cada lado assina uma mensagem e o outro verifica a assinatura; uma
# mensagem alterada deve ser rejeitada pelos dois lados.
source "$(dirname "$0")/common.sh"
require_setup

validate_falcon() {
    local variant="$1"
    local dir="$OUT_DIR/falcon-$variant"

    echo "Falcon-$variant"
    create_token "$dir"
    printf 'Mensagem da validação cruzada do Falcon-%s' "$variant" > "$dir/message.txt"
    printf 'Mensagem alterada' > "$dir/altered.txt"

    # SoftHSM assina, Bouncy Castle verifica
    softhsm falcon_softhsm sign "$variant" "$dir/message.txt" "$dir/softhsm.pub" "$dir/softhsm.sig"
    expect_valid "BC verifica a assinatura do SoftHSM" \
        bc FalconBC verify "$variant" "$dir/message.txt" "$dir/softhsm.pub" "$dir/softhsm.sig"
    expect_invalid "BC rejeita a assinatura do SoftHSM para mensagem alterada" \
        bc FalconBC verify "$variant" "$dir/altered.txt" "$dir/softhsm.pub" "$dir/softhsm.sig"

    # Bouncy Castle assina, SoftHSM verifica
    bc FalconBC sign "$variant" "$dir/message.txt" "$dir/bc.pub" "$dir/bc.sig"
    expect_valid "SoftHSM verifica a assinatura do BC" \
        softhsm falcon_softhsm verify "$variant" "$dir/message.txt" "$dir/bc.pub" "$dir/bc.sig"
    expect_invalid "SoftHSM rejeita a assinatura do BC para mensagem alterada" \
        softhsm falcon_softhsm verify "$variant" "$dir/altered.txt" "$dir/bc.pub" "$dir/bc.sig"
}

validate_falcon 512
validate_falcon 1024
echo "Validação cruzada do Falcon concluída com sucesso"
