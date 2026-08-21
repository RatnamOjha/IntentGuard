// Bindings that may be injected at deploy time but are absent from the local
// configuration in vite.config.ts. Declared optional because that is what they
// are: db/index.ts guards on `env.DB` before using it.
//
// `env` from "cloudflare:workers" is typed as Cloudflare.Env, so the
// augmentation targets that namespace rather than the global Env interface.
declare namespace Cloudflare {
  interface Env {
    DB?: D1Database;
  }
}
