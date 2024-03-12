import { AuthClient } from "@dfinity/auth-client";
import { decodeJwt } from "jose";

const II_URL = "http://bd3sg-teaaa-aaaaa-qaaba-cai.localhost:8080";
const ISSUER_ORIGIN = "http://localhost:4321";
const ISSUER_CANISTER_ID = "bkyz2-fmaaa-aaaaa-qaaaq-cai";
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
        loginStatus.innerText = "Logged in";
      }
    },
  });
});

let iiWindow: Window | null = null;
const handleFlowFinished = (evnt: MessageEvent) => {
  try {
    // Make the presentation presentable
    const verifiablePresentation = evnt.data?.result?.verifiablePresentation;
    if (verifiablePresentation === undefined) {
      return console.error("No verifiable presentation found");
    }

    const ver = decodeJwt(verifiablePresentation) as any;
    const creds = ver.vp.verifiableCredential;
    const [alias, credential] = creds.map((cred: string) =>
      JSON.stringify(decodeJwt(cred), null, 2)
    );
    const resultElement = document.getElementById("vc-result");
    if (resultElement) {
      resultElement.innerText = `Alias: ${alias}\nCredential: ${credential}`;
    }

    iiWindow?.close();
  } finally {
    window.removeEventListener("message", handleFlowFinished);
  }
}
const handleFlowReady = (evnt: MessageEvent) => {
  if (evnt.data?.method !== "vc-flow-ready") {
    return;
  }
  const identity = authClient.getIdentity();
  const principal = identity.getPrincipal().toText();
  const req = {
    id:"1",
    jsonrpc: "2.0",
    method: "request_credential",
    params: {
      issuer: {
        origin: ISSUER_ORIGIN,
        canisterId: ISSUER_CANISTER_ID,
      },
      credentialSpec: {
        credentialType: "EarlyAdopter",
        arguments: {
          sinceYear: 2024
        }
      },
      credentialSubject: principal,
    },
  };
  window.addEventListener("message", handleFlowFinished);
  window.removeEventListener("message", handleFlowReady);
  evnt.source?.postMessage(req, { targetOrigin: evnt.origin });
};
vcButton?.addEventListener("click", async () => {
  window.addEventListener("message", handleFlowReady);
  const url = new URL(II_URL);
  url.pathname = "vc-flow/";
  iiWindow = window.open(url, "_blank");
});