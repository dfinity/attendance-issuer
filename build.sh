#!/usr/bin/env bash
set -euo pipefail

# Make sure we always run from the issuer root
EARLY_ADOPTER_ISSUER_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$EARLY_ADOPTER_ISSUER_DIR"


# Build the frontend
cd frontend/
./scripts/create-env-vars.sh
npm ci
npm run build 
cd ../

# Build the canister
cargo build --release --target wasm32-unknown-unknown --manifest-path ./Cargo.toml -j1
ic-wasm "target/wasm32-unknown-unknown/release/early_adopter_issuer.wasm" -o "./early_adopter_issuer.wasm" shrink
ic-wasm early_adopter_issuer.wasm -o early_adopter_issuer.wasm metadata candid:service -f early_adopter_issuer.did -v public
# indicate support for certificate version 1 and 2 in the canister metadata
ic-wasm early_adopter_issuer.wasm -o early_adopter_issuer.wasm metadata supported_certificate_versions -d "1,2" -v public
gzip --no-name --force "early_adopter_issuer.wasm"

