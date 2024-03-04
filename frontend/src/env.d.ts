/// <reference types="astro/client" />
interface ImportMetaEnv {
  readonly PUBLIC_INTERNET_IDENTITY_URL: string;
  readonly PUBLIC_HOST: string;
  readonly PUBLIC_OWN_CANISTER_ID: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
