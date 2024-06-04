# Proof Of Attendace Issuer

An implementation of a Verified Credentials issuer for "EventAttendance" credentials.

## Building

### Set Frontend Environment Variables

Before building the wasm you need to specify the environment variables of the context you are building.

There is a script within the `frontend` directory that reads the canister ids and local replica to create the env vars: `DFX_NETWORK=local ./scripts/create-env-vars.sh`.

The `DFX_NETWORK=local` is needed to get the canister ids from the dfx replica.

The needed env vars are:

* `PUBLIC_INTERNET_IDENTITY_URL`. Ex: `http://bnz7o-iuaaa-aaaaa-qaaaa-cai.localhost:8080`.
* `PUBLIC_HOST`. Ex: `http://localhost:8080`.
* `PUBLIC_OWN_CANISTER_ID`. Used only for local development. Ex: `bw4dl-smaaa-aaaaa-qaacq-cai`
* `PUBLIC_FETCH_ROOT_KEY`. Whether client should fetch root key before making calls. Used for development environments. Ex: `true`.

To set the vars you need to put then in the `.env` file.

**NOTE: Careful with the bash env vars which override the ones in `.env` file.**

### Build

Run `build.sh`-script to build the issuer canister.

```shell
./build.sh
```

## Testing

To run tests via `cargo test` two binaries are needed, namely `ic-test-state-machine` and `internet_identity.wasm.gz`, 
whose location should be set via environment variables `STATE_MACHINE_BINARY` resp. `II_WASM`.

## End-to-end testing

The end-to-end test use [Playwright](https://playwright.dev/).

If this is the first time running it, you need to install the browsers: `npx playwright install` from the `frontend` directory.

Prepare the environment before running them:

* Start local replica: `dfx start`. From the root directory.
* Deploy canisters: `dfx deploy`. From the root directory.
* Populate `frontend/.env` with `DFX_NETWORK=local ./scripts/create-env-vars.sh`. From `/frontend` directory.
* Run frontend server: `npm run dev`. From the `/frontend` directory.
* Run e2e tests: `npm run test:e2e`. From the `/frontend` directory.

**NOTE: Careful with the bash env vars which override the ones in `.env` file.**
