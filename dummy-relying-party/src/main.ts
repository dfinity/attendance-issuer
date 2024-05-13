import { AuthClient } from "@dfinity/auth-client";
import { decodeJwt } from "jose";
import { requestVerifiablePresentation, type VerifiablePresentationResponse } from "@dfinity/verifiable-credentials/request-verifiable-presentation";

const II_URL = import.meta.env.VITE_INTERNET_IDENTITY_URL;
const ISSUER_ORIGIN = import.meta.env.VITE_ISSUER_ORIGIN;
const ISSUER_CANISTER_ID = import.meta.env.VITE_ISSUER_CANISTER_ID;
const loginButton = document.getElementById("login");
const vcButton = document.getElementById("start-vc");
const loginStatus = document.getElementById("login-status");
const authClient = await AuthClient.create();
loginButton?.addEventListener("click", async () => {
  await authClient.login({
    identityProvider: II_URL,
    onSuccess: () => {
      loginButton?.classList.add("hidden");
      vcButton?.classList.remove("hidden");
      if (loginStatus) {
        loginStatus.innerText = `Logged in as ${authClient.getIdentity().getPrincipal().toText()}`;
      }
    },
  });
});

vcButton?.addEventListener("click", async () => {
  const identity = authClient.getIdentity();
  const principal = identity.getPrincipal().toText();
  requestVerifiablePresentation({
    onSuccess: async (verifiablePresentation: VerifiablePresentationResponse) => {
      const resultElement = document.getElementById("vc-result");
      if ("Ok" in verifiablePresentation) {
        const ver = decodeJwt(verifiablePresentation.Ok) as any;
        const creds = ver.vp.verifiableCredential;
        const [alias, credential] = creds.map((cred: string) =>
          JSON.stringify(decodeJwt(cred), null, 2)
        );
        if (resultElement) {
          resultElement.innerText = `Alias: ${alias}\nCredential: ${credential}`;
        }
      } else {
        if (resultElement) {
          resultElement.innerText = "Credential not obtained";
        }
      }
    },
    onError() {
      const resultElement = document.getElementById("vc-result");
      if (resultElement) {
        resultElement.innerText = "There was an error obtaining the credential.";
      }
    },
    issuerData: {
      origin: ISSUER_ORIGIN,
      canisterId: ISSUER_CANISTER_ID,
    },
    credentialData: {
      credentialSpec: {
        credentialType: "EarlyAdopter",
        arguments: {
          sinceYear: 2024
        }
      },
      credentialSubject: principal,
    },
    identityProvider: II_URL,
    derivationOrigin: undefined,
  });
});
