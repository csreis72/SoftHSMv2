#!/bin/bash
# Prepara o ambiente da validação cruzada em build/:
#   1. baixa o Bouncy Castle do Maven Central e confere o SHA-256;
#   2. compila os clientes PKCS#11 em C;
#   3. compila os programas Java.
source "$(dirname "$0")/common.sh"

PKCS11_INCLUDE="$CROSS_DIR/../../src/lib/pkcs11"
BC_URL="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/$BC_VERSION/bcprov-jdk18on-$BC_VERSION.jar"

mkdir -p "$BUILD_DIR/classes"

echo "Bouncy Castle $BC_VERSION"
if [ ! -f "$BC_JAR" ]; then
    wget -q -O "$BC_JAR.download" "$BC_URL"
    echo "$BC_SHA256  $BC_JAR.download" | sha256sum --check --quiet
    mv "$BC_JAR.download" "$BC_JAR"
fi

echo "Clientes PKCS#11 (C)"
for client in falcon_softhsm xwing_softhsm; do
    gcc -std=c99 -Wall -Wextra -I "$PKCS11_INCLUDE" \
        -o "$BUILD_DIR/$client" "$CROSS_DIR/c/$client.c" "$CROSS_DIR/c/p11.c" -ldl
done

echo "Programas Bouncy Castle (Java)"
javac -cp "$BC_JAR" -d "$BUILD_DIR/classes" "$CROSS_DIR"/java/*.java

echo "Ambiente pronto em $BUILD_DIR"
