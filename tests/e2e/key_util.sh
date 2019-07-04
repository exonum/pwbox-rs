#!/usr/bin/env bash

set -e

THIS_DIR=`dirname $0`
BIN="cargo run --example key-util --"
DATA=1234567890feedc0ffee1234567890

echo "Testing simple roundtrip..."
$BIN enc -p 'pass:Sup3rSecr1t!' $DATA > enc.toml
DECRYPTED=`PASSWORD='Sup3rSecr1t!' $BIN dec -p env:PASSWORD enc.toml`
if [[ $DECRYPTED != $DATA ]]; then
  echo "Unexpected decryption: $DECRYPTED"
  exit 1
fi

echo "Testing decryption from stdin..."
DECRYPTED=`cat enc.toml | $BIN dec -p 'pass:Sup3rSecr1t!' -`
if [[ $DECRYPTED != $DATA ]]; then
  echo "Unexpected decryption: $DECRYPTED"
  exit 1
fi

echo "Testing --check flag and TOML traversal..."
DECRYPTED=`$BIN dec --check -p 'pass:Sup3rSecret!' -@ master_key "$THIS_DIR/enc.toml"`
if [[ $DECRYPTED != "OK" ]]; then
  echo "Unexpected decryption: $DECRYPTED"
  exit 1
fi

# Cleanup
rm enc.toml
