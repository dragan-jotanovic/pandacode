export const MIN_SECRET_CHARS = 32;

/** Which sign-in route a request is for; `false` for every authenticated route. */
export type AuthRoute = false | "github" | "key";

/**
 * True when the Worker has what it needs; the caller answers a generic 500 otherwise and never says which secret.
 * GitHub sign-in needs the OAuth app's ID and secret; key sign-in only needs ACCESS_KEY, so a private relay can leave GitHub unset.
 */
export const configured = (
  env: { SESSION_SECRET?: string; GITHUB_CLIENT_ID?: string; GITHUB_CLIENT_SECRET?: string; ACCESS_KEY?: string },
  auth: AuthRoute,
): boolean =>
  typeof env.SESSION_SECRET === "string" && env.SESSION_SECRET.length >= MIN_SECRET_CHARS &&
  (auth === false ||
    (auth === "github" ? !!env.GITHUB_CLIENT_ID && !!env.GITHUB_CLIENT_SECRET : typeof env.ACCESS_KEY === "string" && env.ACCESS_KEY.length >= MIN_SECRET_CHARS));
