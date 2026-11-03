/**
 * ES256 HTTP message signing for the Innerva v0.1 profile.
 *
 * Reproduces, byte for byte, the signature base and header serialization of
 * the Go reference implementation, using WebCrypto only (Node 18+, browsers,
 * and edge runtimes). Validated against the shared conformance vectors in
 * `sdk/conformance/vectors`.
 */

export const SIGNATURE_ALGORITHM = "ecdsa-p256-sha256";
export const SIGNATURE_LABEL = "sig1";
export const SIGNATURE_LIFETIME_SECONDS = 60;

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

/** Standard base64 of raw bytes. */
export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** Decode standard base64 into raw bytes. */
export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** Base64url without padding, as used for JWK fields and tokens. */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** An opaque, typed value with 256 random bits, matching the Go SDK. */
export function newToken(prefix: string): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return prefix + toBase64Url(bytes);
}

/** The canonical v0.1 Content-Digest field value for a request body. */
export async function contentDigest(body: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await subtle.digest("SHA-256", body as BufferSource));
  return `sha-256=:${toBase64(digest)}:`;
}

/** The RFC 7638 SHA-256 thumbprint of a public P-256 JWK. */
export async function jwkThumbprint(x: string, y: string): Promise<string> {
  const canonical = JSON.stringify({ crv: "P-256", kty: "EC", x, y });
  const digest = new Uint8Array(await subtle.digest("SHA-256", encoder.encode(canonical)));
  return toBase64Url(digest);
}

/** The interaction-finish hash binding a browser result to its request. */
export async function callbackHash(
  clientFinish: string,
  serverFinish: string,
  interactRef: string,
  accessEndpoint: string,
): Promise<string> {
  const joined = [clientFinish, serverFinish, interactRef, accessEndpoint].join("\n");
  const digest = new Uint8Array(await subtle.digest("SHA-256", encoder.encode(joined)));
  return toBase64Url(digest);
}

/** The ordered signature components required by the v0.1 profile. */
export function coveredComponents(
  hasBody: boolean,
  hasAuthorization: boolean,
  hasIdempotencyKey: boolean,
): string[] {
  const components = ["@method", "@target-uri"];
  if (hasBody) {
    components.push("content-digest", "content-type");
  }
  components.push("innerva-nonce");
  if (hasAuthorization) {
    components.push("authorization");
  }
  if (hasIdempotencyKey) {
    components.push("idempotency-key");
  }
  return components;
}

/** The serialized @signature-params value for the fixed v0.1 profile. */
export function signatureParams(
  components: string[],
  created: number,
  expires: number,
  keyId: string,
): string {
  const quoted = components.map((name) => `"${name}"`).join(" ");
  return `(${quoted});created=${created};expires=${expires};keyid="${keyId}";alg="${SIGNATURE_ALGORITHM}"`;
}

/** Inputs describing the request being signed. */
export interface SignatureInputs {
  readonly method: string;
  readonly targetUri: string;
  readonly nonce: string;
  readonly created: number;
  readonly expires: number;
  readonly keyId: string;
  readonly contentType?: string | undefined;
  readonly bodyDigest?: string | undefined;
  readonly authorization?: string | undefined;
  readonly idempotencyKey?: string | undefined;
}

/** Build the RFC 9421 signature base and Signature-Input header value. */
export function signatureBase(inputs: SignatureInputs): {
  base: string;
  signatureInput: string;
} {
  const components = coveredComponents(
    inputs.contentType !== undefined,
    inputs.authorization !== undefined,
    inputs.idempotencyKey !== undefined,
  );
  const values = new Map<string, string>([
    ["@method", inputs.method],
    ["@target-uri", inputs.targetUri],
    ["innerva-nonce", inputs.nonce],
  ]);
  if (inputs.contentType !== undefined) {
    if (inputs.bodyDigest === undefined) {
      throw new Error("a body digest is required when content type is present");
    }
    values.set("content-digest", inputs.bodyDigest);
    values.set("content-type", inputs.contentType);
  }
  if (inputs.authorization !== undefined) {
    values.set("authorization", inputs.authorization);
  }
  if (inputs.idempotencyKey !== undefined) {
    values.set("idempotency-key", inputs.idempotencyKey);
  }
  const parameters = signatureParams(components, inputs.created, inputs.expires, inputs.keyId);
  const lines = components.map((name) => `"${name}": ${values.get(name) ?? ""}`);
  lines.push(`"@signature-params": ${parameters}`);
  return { base: lines.join("\n"), signatureInput: `${SIGNATURE_LABEL}=${parameters}` };
}

/** A loaded proof key ready for signing. */
export interface ProofKey {
  readonly privateKey: CryptoKey;
  readonly publicJwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
  readonly keyId: string;
}

/** Import a private P-256 JWK (fields kty, crv, x, y, d) as a proof key. */
export async function importProofKey(jwk: JsonWebKey): Promise<ProofKey> {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y || !jwk.d) {
    throw new Error("proof key must be a private P-256 EC JWK");
  }
  const privateKey = await subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  return {
    privateKey,
    publicJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
    keyId: await jwkThumbprint(jwk.x, jwk.y),
  };
}

/** Generate a fresh P-256 proof key and return its private JWK. */
export async function generateProofJwk(): Promise<JsonWebKey> {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  return subtle.exportKey("jwk", pair.privateKey);
}

/** Sign a signature base, returning the raw 64-byte r||s form. */
export async function signEs256(privateKey: CryptoKey, base: string): Promise<Uint8Array> {
  const signature = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    encoder.encode(base),
  );
  return new Uint8Array(signature);
}

/** The proof headers to attach to one signed request. */
export interface SignedHeaders {
  readonly innervaNonce: string;
  readonly signatureInput: string;
  readonly signature: string;
}

/** Produce the v0.1 proof headers for one request. */
export async function signRequest(
  key: ProofKey,
  request: {
    method: string;
    targetUri: string;
    created: number;
    contentType?: string | undefined;
    body?: Uint8Array | undefined;
    authorization?: string | undefined;
    idempotencyKey?: string | undefined;
    nonce?: string | undefined;
  },
): Promise<SignedHeaders> {
  const nonce = request.nonce ?? newToken("n1_");
  const bodyDigest =
    request.contentType !== undefined
      ? await contentDigest(request.body ?? new Uint8Array())
      : undefined;
  const { base, signatureInput } = signatureBase({
    method: request.method,
    targetUri: request.targetUri,
    nonce,
    created: request.created,
    expires: request.created + SIGNATURE_LIFETIME_SECONDS,
    keyId: key.keyId,
    contentType: request.contentType,
    bodyDigest,
    authorization: request.authorization,
    idempotencyKey: request.idempotencyKey,
  });
  const raw = await signEs256(key.privateKey, base);
  return {
    innervaNonce: nonce,
    signatureInput,
    signature: `${SIGNATURE_LABEL}=:${toBase64(raw)}:`,
  };
}
