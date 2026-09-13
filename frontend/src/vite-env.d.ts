/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Build-time API base. Empty or absent means "same origin". */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface Window {
  /** Written by `/config.js` at container start-up; see `src/api/config.ts`. */
  __AEGIS_CONFIG__?: { apiBase?: string };
}
