#!/bin/bash
set -e

mkdir -p /var/lib/softhsm/tokens
chmod 700 /var/lib/softhsm/tokens

if [ -f /src/build.sh ]; then
    chmod +x /src/build.sh
fi

exec "$@"