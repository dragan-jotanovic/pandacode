import type { GithubUser } from "./github.ts";

/**
 * The relay's second sign-in method, for a relay on a private network with no GitHub at all:
 * one shared key from the Worker's ACCESS_KEY secret, and one account for everyone who has it.
 */
export const KEY_ACCOUNT: GithubUser = { id: "key:private", login: "Private relay", avatarUrl: "" };

const enc = new TextEncoder();

async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}

/** Compares in constant time: both sides are hashed first, so length and content leak nothing. */
export async function keyMatches(given: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([digest(given), digest(expected)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
