import { AuthClient } from "@dfinity/auth-client";

const II_URL = "http://bd3sg-teaaa-aaaaa-qaaba-cai.localhost:8080";
const ISSUER_ORIGIN = "http://bkyz2-fmaaa-aaaaa-qaaaq-cai.localhost:8080";
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

const handleFlowFinished = (evnt: MessageEvent) => {
  console.log('in handleFlowFinished');
  console.log(evnt.data);
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
  window.open(url, "_blank");
});