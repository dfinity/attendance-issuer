# Dummy Relying Party

This project is used in e2e tests for the Early Adopter campaign to test that a relying party can get the Early Adopter credentials for a user.

## Environment Variables

The project needs to following environment variables before building:

* PUBLIC_INTERNET_IDENTITY_URL. URL of the II in the local replica.
* PUBLIC_ISSUER_ORIGIN. Domain of the Early Adopter campaign. Do not use the URL of the deployed project, instead use the vite server to set the necessary headers.
PUBLIC_ISSUER_CANISTER_ID. Canister id of the Early Adopter campaign in the local replica.

They are set in `.env` in this same directory. For example:

```
PUBLIC_INTERNET_IDENTITY_URL=http://bd3sg-teaaa-aaaaa-qaaba-cai.localhost:8080
PUBLIC_ISSUER_ORIGIN=http://localhost:4321
PUBLIC_ISSUER_CANISTER_ID=bkyz2-fmaaa-aaaaa-qaaaq-cai
```

**TODO: Reuse the create-env-vars script to add the env vars.**

## Build

Instal dependencies and build:

```
npm ci
npm run build
```

## Deploy

Use dfx

```
dfx deploy
```
