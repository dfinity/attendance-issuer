# early-adopter-issuer
An implementation of a VC issuer for "VerifiedEarlyAdopter" credentials.

## Building

Run `build.sh`-script to build the issuer canister.

```shell
./build.sh
```

## Testing

To run tests via `cargo test` two binaries are needed, namely `ic-test-state-machine` and `internet_identity.wasm.gz`, 
whose location should be set via environment variables `STATE_MACHINE_BINARY` resp. `II_WASM`.
