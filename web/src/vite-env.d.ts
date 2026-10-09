/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** '1' only in `npm run dev:mock` (see .env.mock). Ignored in production builds. */
  readonly VITE_MOCK?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
