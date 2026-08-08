/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_PENTAI_CORE_URL?: string;
  readonly VITE_PENTAI_LAUNCH_CREDENTIAL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
