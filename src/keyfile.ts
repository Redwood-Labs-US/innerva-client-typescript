/**
 * Durable proof-key storage for Node.js runtimes.
 *
 * The key is stored as a private P-256 JWK JSON file with owner-only
 * permissions. Browser and edge runtimes should persist the JWK themselves
 * and pass it to `createClient` directly.
 */

import { generateProofJwk } from "./signing";

/** Load a durable P-256 proof key or create it with owner-only permissions. */
export async function loadOrCreateProofKey(path: string): Promise<JsonWebKey> {
  if (path === "") {
    throw new Error("proof key path is required");
  }
  const fs = await import("node:fs/promises");
  const nodePath = await import("node:path");
  let stats;
  try {
    stats = await fs.lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
    const directory = nodePath.dirname(path);
    if (directory !== "" && directory !== ".") {
      await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    }
    const jwk = await generateProofJwk();
    const encoded = JSON.stringify(
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d },
      null,
      2,
    );
    await fs.writeFile(path, encoded + "\n", { mode: 0o600, flag: "wx" });
    return jwk;
  }
  if (!stats.isFile() || (stats.mode & 0o077) !== 0) {
    throw new Error("proof key file must be regular and accessible only by its owner");
  }
  const data = await fs.readFile(path, "utf-8");
  const jwk = JSON.parse(data) as JsonWebKey;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y || !jwk.d) {
    throw new Error("proof key file must contain a private P-256 JWK");
  }
  return jwk;
}
