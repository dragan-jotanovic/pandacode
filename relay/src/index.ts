import { KEY_ACCOUNT, keyMatches } from "./access-key.ts";
import { Account } from "./account.ts";
import { readJsonCapped } from "./body.ts";
import { configured } from "./config.ts";
import { type Env, fail, json } from "./env.ts";
import { type GithubUser, githubUser } from "./github.ts";
import { MAX_FRAME_BYTES } from "./limits.ts";
import { isKnownRoute } from "./routes.ts";
import { signToken, verifyToken } from "./token.ts";
import { parseDevice } from "./validate.ts";

export { Account };

const stub = (env: Env, acct: string) => env.ACCOUNT.get(env.ACCOUNT.idFromName(acct));

/** The sign-in steps both methods share: the rate limits, the capped body, the device, then the account's device row and token. */
async function signIn(
  request: Request,
  env: Env,
  field: string,
  identify: (credential: string) => Promise<GithubUser | { status: number; error: string }>,
): Promise<Response> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  if (!(await env.AUTH_LIMITER.limit({ key: ip })).success) return fail(429, "too many sign-in attempts");
  if (!(await env.GLOBAL_AUTH_LIMITER.limit({ key: "all" })).success) return fail(429, "too many sign-in attempts");
  const read = await readJsonCapped(request, MAX_FRAME_BYTES);
  if (read === "too-large") return fail(413, "request too large");
  const body = read === "invalid" ? null : (read.value as Record<string, unknown> | null);
  const credential = body?.[field];
  if (!body || typeof credential !== "string" || !credential || credential.length > 512) {
    return fail(400, `${field} is required`);
  }
  const device = parseDevice(body.device);
  if (typeof device === "string") return fail(400, device);
  const user = await identify(credential);
  if ("status" in user) return fail(user.status, user.error);
  const res = await stub(env, user.id).fetch("https://account/internal/register", { method: "POST", body: JSON.stringify(device) });
  if (!res.ok) return res;
  const { gen } = (await res.json().catch(() => ({}))) as { gen?: unknown };
  const token = await signToken(env.SESSION_SECRET, user.id, device.id, Math.floor(Date.now() / 1000), typeof gen === "number" ? gen : undefined);
  return json({ token, account: user });
}

const authGithub = (request: Request, env: Env) =>
  signIn(request, env, "githubToken", (token) => githubUser(token, env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET));

const authKey = (request: Request, env: Env) =>
  signIn(request, env, "key", async (key) => ((await keyMatches(key, env.ACCESS_KEY ?? "")) ? KEY_ACCOUNT : { status: 401, error: "wrong access key" }));

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const auth = path === "/v1/auth/github" ? "github" : path === "/v1/auth/key" ? "key" : false;
    if (!configured(env, auth)) return fail(500, "server error");
    if (auth) return request.method === "POST" ? (auth === "github" ? authGithub(request, env) : authKey(request, env)) : fail(405, "method not allowed");

    if (!isKnownRoute(path)) return fail(404, "not found");
    const bearer = /^Bearer (\S+)$/.exec(request.headers.get("authorization") ?? "")?.[1];
    const claims = bearer ? await verifyToken(env.SESSION_SECRET, bearer, Math.floor(Date.now() / 1000)) : null;
    if (!claims) return fail(401, "invalid or expired token");

    if (!(await env.ACCOUNT_LIMITER.limit({ key: claims.acct })).success) return fail(429, "too many requests");

    const headers = new Headers(request.headers);
    headers.set("x-device-id", claims.dev);
    headers.set("x-token-iat", String(claims.iat));
    headers.delete("x-token-gen");
    if (claims.gen !== undefined) headers.set("x-token-gen", String(claims.gen));
    headers.delete("authorization");
    const res = await stub(env, claims.acct).fetch(new Request(request, { headers }));
    if (path !== "/v1/token" || !res.ok) return res;
    const { gen } = (await res.json().catch(() => ({}))) as { gen?: unknown };
    return json({ token: await signToken(env.SESSION_SECRET, claims.acct, claims.dev, Math.floor(Date.now() / 1000), typeof gen === "number" ? gen : undefined) });
  },
} satisfies ExportedHandler<Env>;
