#!/usr/bin/env bash

print_help() {
  cat <<-EOF

	This script creates the `.env` file and populates it with the environment variables depending on the environment.

	The scripts requires DFX_NETWORK to be set and ENV_FILE is optional.

  Example: DFX_NETWORK=local ./scripts/create-env-vars.sh
	EOF
}

test -n "$DFX_NETWORK" # Will fail if not defined.
export DFX_NETWORK

ENV_FILE=${ENV_OUTPUT_FILE:-$PWD/.env}

II_CANISTER_ID=$(dfx canister id internet_identity --network "$DFX_NETWORK")
EARLY_CANISTER_ID=$(dfx canister id early_adopter --network "$DFX_NETWORK")

if [ "$DFX_NETWORK" = "local" ]; then
  REPLICA_SERVER_PORT=$(dfx info webserver-port)
  II_URL="http://${II_CANISTER_ID}.localhost:${REPLICA_SERVER_PORT}"
  HOST="http://localhost:${REPLICA_SERVER_PORT}"
  echo "PUBLIC_INTERNET_IDENTITY_URL=${II_URL}" > $ENV_FILE
  echo "PUBLIC_OWN_CANISTER_ID=${EARLY_CANISTER_ID}" >> $ENV_FILE
  echo "PUBLIC_HOST=${HOST}" >> $ENV_FILE
  echo "PUBLIC_FETCH_ROOT_KEY=true" >> $ENV_FILE
fi
if [ "$DFX_NETWORK" = "ic_test" ]; then
  II_URL="https://${II_CANISTER_ID}.ic0.app"
  HOST="https://icp-api.io"
  echo "PUBLIC_INTERNET_IDENTITY_URL=${II_URL}" > $ENV_FILE
  echo "PUBLIC_HOST=${HOST}" >> $ENV_FILE
  echo "PUBLIC_FETCH_ROOT_KEY=false" >> $ENV_FILE
fi
if [ "$DFX_NETWORK" = "mainnet" ]; then
  II_URL="https://identity.ic0.app"
  HOST="https://icp-api.io"
  echo "PUBLIC_INTERNET_IDENTITY_URL=${II_URL}" > $ENV_FILE
  echo "PUBLIC_HOST=${HOST}" >> $ENV_FILE
  echo "PUBLIC_FETCH_ROOT_KEY=false" >> $ENV_FILE
  echo "PUBLIC_JUNO_SATELLITE_ID=j62zl-viaaa-aaaal-ajfcq-cai" >> $ENV_FILE
  echo "PUBLIC_JUNO_ORBITER_ID=sfdba-gaaaa-aaaal-ad5ua-cai" >> $ENV_FILE
fi

