#!/usr/bin/env bash
set -euo pipefail

# Make sure we always run from the issuer root
EARLY_ADOPTER_ISSUER_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$EARLY_ADOPTER_ISSUER_DIR"

# Build the frontend
cd dummy-relying-party/
npm ci
npm run build