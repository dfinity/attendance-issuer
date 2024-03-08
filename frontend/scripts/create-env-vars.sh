# This script creates the `.env` file and populates it with the environment variables depending on the environment.

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
  echo "PUBLIC_HOST=${HOST}" >> $ENV_FILE
  echo "PUBLIC_FETCH_ROOT_KEY=true" >> $ENV_FILE
fi
if [ "$DFX_NETWORK" = "mainnet" ]; then
  II_URL="https://${II_CANISTER_ID}.ic0.app"
  HOST="https://icp-api.io"
  echo "PUBLIC_INTERNET_IDENTITY_URL=${II_URL}" > $ENV_FILE
  echo "PUBLIC_HOST=${HOST}" >> $ENV_FILE
  echo "PUBLIC_FETCH_ROOT_KEY=false" >> $ENV_FILE
fi

