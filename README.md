# early-adopter-issuer
An implementation of a VC issuer for "VerifiedEarlyAdopter" credentials.

## Building

### Set environment variables

Before building the wasm you need to specify the environment variables of the context you are building.

The needed env vars are:

* `PUBLIC_INTERNET_IDENTITY_URL`.
* `PUBLIC_HOST`.
* `PUBLIC_OWN_CANISTER_ID`. Used only for local development.

To set the vars you need to put then in the `.env` file.

### Build

Run `build.sh`-script to build the issuer canister.

```shell
./build.sh
```

## Testing

To run tests via `cargo test` two binaries are needed, namely `ic-test-state-machine` and `internet_identity.wasm.gz`, 
whose location should be set via environment variables `STATE_MACHINE_BINARY` resp. `II_WASM`.
