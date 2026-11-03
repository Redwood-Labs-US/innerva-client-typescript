/**
 * The Innerva Grant Protocol v0.1 client.
 *
 * Construct a `Client`, request access, stream a response, read a typed
 * result. Requests are signed with the ES256 HTTP message-signature profile
 * and retried automatically only while retrying is provably safe: the same
 * idempotency key is reused across attempts, and nothing is ever retried
 * after a stream opened, because streamed content is not retained
 * server-side.
 */

import {
  CallbackBindingError,
  ConfigurationError,
  InferenceAlreadyStartedError,
  KeyBindingError,
  ProblemError,
  ResponseFormatError,
  TransportError,
} from "./errors";
import * as signing from "./signing";
import { decodeInferenceStream } from "./sse";
import {
  defaultRetryPolicy,
  type Capability,
  type CreateAccessOptions,
  type InferenceOutcome,
  type InferOptions,
  type PendingAccess,
  type RetryPolicy,
  type StreamEvent,
} from "./types";

export const MAX_RESPONSE_BODY = 1 << 20;
const CAPABILITY_REFRESH_WINDOW_MS = 30_000;
const SPEND_AUTHORIZATION_HEADER = "Innerva-Staging-Spend-Authorization";
const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);

/** Configuration for one developer integration environment. */
export interface ClientConfig {
  readonly baseUrl: string;
  /** A private P-256 JWK (kty, crv, x, y, d). */
  readonly key: JsonWebKey;
  readonly displayName: string;
  readonly displayUri: string;
  readonly callbackUri: string;
  /** Operator-issued staging credential; leave unset against production. */
  readonly spendAuthorization?: string;
  readonly retryPolicy?: RetryPolicy;
  /** Timeout for non-streaming requests, in milliseconds. */
  readonly requestTimeoutMs?: number;
  /** Overridable for tests. */
  readonly fetch?: typeof fetch;
}

/** Create a client, importing and validating the proof key. */
export async function createClient(config: ClientConfig): Promise<Client> {
  const key = await signing.importProofKey(config.key);
  return new Client(config, key);
}

/** Signs protocol requests with one durable integration key. */
export class Client {
  private readonly base: URL;
  private readonly key: signing.ProofKey;
  private readonly displayName: string;
  private readonly displayUri: string;
  private readonly callbackUri: string;
  private readonly spendAuthorization: string;
  private readonly retryPolicy: RetryPolicy;
  private readonly requestTimeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  /** Overridable for tests. */
  sleep: (ms: number) => Promise<void> = (ms) =>
    new Promise((resolve) => setTimeout(resolve, ms));
  /** Overridable for tests. */
  random: () => number = Math.random;
  /** Overridable for tests. */
  now: () => number = Date.now;

  constructor(config: ClientConfig, key: signing.ProofKey) {
    this.base = parseAbsoluteUrl(config.baseUrl, "base URL");
    if ((this.base.pathname !== "/" && this.base.pathname !== "") || this.base.search !== "") {
      throw new ConfigurationError("base URL must be an origin without a path or query");
    }
    if (this.base.protocol !== "https:" && !isLoopbackHost(this.base.hostname)) {
      throw new ConfigurationError("base URL must use HTTPS outside loopback development");
    }
    if (config.displayName.length < 1 || config.displayName.length > 120) {
      throw new ConfigurationError("display name must be 1 to 120 characters");
    }
    parseAbsoluteUrl(config.displayUri, "display URI");
    parseAbsoluteUrl(config.callbackUri, "callback URI");
    this.key = key;
    this.displayName = config.displayName;
    this.displayUri = config.displayUri;
    this.callbackUri = config.callbackUri;
    this.spendAuthorization = config.spendAuthorization ?? "";
    this.retryPolicy = config.retryPolicy ?? defaultRetryPolicy;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 15_000;
    this.fetchImpl = config.fetch ?? fetch;
  }

  /** This integration's proof-key thumbprint. */
  get keyThumbprint(): string {
    return this.key.keyId;
  }

  /**
   * Start a signed access request and return its browser interaction. An
   * idempotency key is generated automatically when not supplied and reused
   * across every retry of this call.
   */
  async createAccess(options: CreateAccessOptions = {}): Promise<PendingAccess> {
    let finishUri = this.callbackUri;
    if (options.callbackUri !== undefined) {
      parseAbsoluteUrl(options.callbackUri, "callback URI");
      finishUri = options.callbackUri;
    }
    const clientFinish = signing.newToken("cf1_");
    const credits: Record<string, unknown> = { unit: "innerva_credit" };
    if (options.suggestedCredits !== undefined) {
      credits["suggested"] = options.suggestedCredits;
    }
    if (options.minimumCredits !== undefined) {
      credits["minimum"] = options.minimumCredits;
    }
    const request: Record<string, unknown> = {
      protocol_version: "0.1",
      client: {
        key: { proof: "httpsig", jwk: this.key.publicJwk },
        display: { name: this.displayName, uri: this.displayUri },
      },
      access_token: {
        access: [
          {
            type: "innerva_inference",
            actions: ["responses.create"],
            models: ["innerva:standard"],
            credits,
            duration: "until_depleted_or_revoked",
          },
        ],
      },
      interact: {
        start: ["redirect"],
        finish: {
          method: "redirect",
          uri: finishUri,
          nonce: clientFinish,
          hash_method: "sha-256",
        },
      },
    };
    if (options.clientReference !== undefined) {
      request["client_reference"] = options.clientReference;
    }
    const endpoint = `${this.origin()}/v1/access-requests`;
    const extraHeaders: Record<string, string> = {};
    if (this.spendAuthorization !== "") {
      extraHeaders[SPEND_AUTHORIZATION_HEADER] = this.spendAuthorization;
    }
    const created = await this.postJson(endpoint, request, {
      idempotencyKey: options.idempotencyKey ?? signing.newToken("ik_"),
      extraHeaders,
    });
    let pending: PendingAccess;
    try {
      const continuation = asRecord(created["continue"]);
      const interact = asRecord(created["interact"]);
      pending = {
        requestId: nonEmptyString(created["request_id"]),
        instanceId: nonEmptyString(created["instance_id"]),
        interactionUri: nonEmptyString(interact["redirect"]),
        continuationUri: nonEmptyString(continuation["uri"]),
        continuationToken: nonEmptyString(asRecord(continuation["access_token"])["value"]),
        clientFinish,
        serverFinish: typeof interact["finish"] === "string" ? interact["finish"] : "",
        accessEndpoint: endpoint,
      };
      if (created["protocol_version"] !== "0.1") {
        throw new Error("unsupported protocol version");
      }
    } catch {
      throw new ResponseFormatError("innerva returned an incomplete access response");
    }
    this.requireSameOrigin(pending.continuationUri, "continuation URI");
    this.requireSameOrigin(pending.interactionUri, "interaction URI");
    return pending;
  }

  /** Verify that a browser result belongs to the pending request. */
  async validateCallback(
    pending: PendingAccess,
    interactRef: string,
    callbackHash: string,
  ): Promise<boolean> {
    const expected = await signing.callbackHash(
      pending.clientFinish,
      pending.serverFinish,
      interactRef,
      pending.accessEndpoint,
    );
    return timingSafeEqual(expected, callbackHash);
  }

  /** Validate the browser binding and exchange it for a capability. */
  async continueAccess(
    pending: PendingAccess,
    interactRef: string,
    callbackHash: string,
  ): Promise<Capability> {
    if (!(await this.validateCallback(pending, interactRef, callbackHash))) {
      throw new CallbackBindingError("interaction callback binding is invalid");
    }
    const response = await this.postJson(
      pending.continuationUri,
      { interact_ref: interactRef },
      {
        token: pending.continuationToken,
        idempotencyKey: await operationIdempotencyKey("continue-", pending.continuationToken),
      },
    );
    return this.acceptCapability(response);
  }

  /** Replace the short-lived inference token using the management credential. */
  async rotate(capability: Capability): Promise<Capability> {
    const endpoint = `${capability.managementUri.replace(/\/+$/, "")}/rotate`;
    this.requireSameOrigin(endpoint, "management URI");
    const response = await this.postJson(endpoint, {}, {
      token: capability.managementToken,
      idempotencyKey: await operationIdempotencyKey("rotate-", capability.value),
    });
    return this.acceptCapability(response);
  }

  /** Immediately revoke the capability and its sandbox grant. */
  async revoke(capability: Capability): Promise<void> {
    this.requireSameOrigin(capability.managementUri, "management URI");
    const { response, body } = await this.sendWithRetry({
      method: "DELETE",
      endpoint: capability.managementUri,
      token: capability.managementToken,
      stream: false,
    });
    if (response.status !== 204) {
      throw problemError(response.status, body ?? new Uint8Array());
    }
  }

  /**
   * Run one inference and collect its output text in memory, returning a
   * typed outcome. The SDK does not persist the input or output and never
   * retries a started stream.
   */
  async infer(capability: Capability, input: string, options: InferOptions): Promise<InferenceOutcome> {
    let outcome: InferenceOutcome | undefined;
    for await (const event of this.inferStream(capability, input, options)) {
      if (event.kind === "completed" || event.kind === "incomplete") {
        outcome = event;
      }
    }
    if (outcome === undefined) {
      throw new ResponseFormatError("inference stream produced no outcome");
    }
    return outcome;
  }

  /**
   * Run one inference, yielding typed stream events as they arrive. The final
   * event is always a terminal outcome; failures throw typed errors. Only
   * failures before the stream opens are retried, under the operation's
   * single idempotency key.
   */
  async *inferStream(
    capability: Capability,
    input: string,
    options: InferOptions,
  ): AsyncGenerator<StreamEvent, void, undefined> {
    const encoded = new TextEncoder().encode(input);
    if (encoded.length < 1 || encoded.length > 32768) {
      throw new ConfigurationError("input must be 1 to 32768 UTF-8 bytes");
    }
    if (
      !Number.isInteger(options.maxOutputTokens) ||
      options.maxOutputTokens < 1 ||
      options.maxOutputTokens > 4096
    ) {
      throw new ConfigurationError("maxOutputTokens must be 1 to 4096");
    }
    let idempotencyKey = options.idempotencyKey;
    if (idempotencyKey === undefined) {
      idempotencyKey = signing.newToken("op_");
    } else if (!validOperationKey(idempotencyKey)) {
      throw new ConfigurationError("idempotency key must be 1 to 128 visible ASCII characters");
    }
    const token = await this.currentCapabilityValue(capability);
    const body = new TextEncoder().encode(
      JSON.stringify({
        model: "innerva:standard",
        input,
        max_output_tokens: options.maxOutputTokens,
        stream: true,
      }),
    );
    const { response } = await this.sendWithRetry({
      method: "POST",
      endpoint: `${this.origin()}/v1/responses`,
      body,
      contentType: "application/json",
      token,
      idempotencyKey,
      stream: true,
    });
    if (response.status !== 200) {
      throw problemError(response.status, await readLimited(response));
    }
    const mediaType = (response.headers.get("content-type") ?? "")
      .split(";")[0]!
      .trim()
      .toLowerCase();
    if (mediaType !== "text/event-stream") {
      await response.body?.cancel().catch(() => undefined);
      throw new ResponseFormatError("innerva returned an invalid inference content type");
    }
    if (response.body === null) {
      throw new ResponseFormatError("innerva returned no inference stream body");
    }
    try {
      yield* decodeInferenceStream(iterateStream(response.body));
    } finally {
      await response.body.cancel().catch(() => undefined);
    }
  }

  private async currentCapabilityValue(capability: Capability): Promise<string> {
    if (capability.expiresAt === undefined) {
      if (capability.value === "") {
        throw new ConfigurationError("capability has no inference token");
      }
      return capability.value;
    }
    if (this.now() + CAPABILITY_REFRESH_WINDOW_MS < capability.expiresAt) {
      return capability.value;
    }
    const refreshed = await this.rotate(capability);
    capability.value = refreshed.value;
    capability.managementToken = refreshed.managementToken;
    capability.managementUri = refreshed.managementUri;
    capability.capabilityId = refreshed.capabilityId;
    capability.grantId = refreshed.grantId;
    capability.grantLimit = refreshed.grantLimit;
    capability.grantRemaining = refreshed.grantRemaining;
    capability.expiresAt = refreshed.expiresAt;
    return capability.value;
  }

  private async postJson(
    endpoint: string,
    payload: Record<string, unknown>,
    options: { token?: string; idempotencyKey?: string; extraHeaders?: Record<string, string> },
  ): Promise<Record<string, unknown>> {
    this.requireSameOrigin(endpoint, "endpoint");
    const body = new TextEncoder().encode(JSON.stringify(payload));
    const request: SendRequest = {
      method: "POST",
      endpoint,
      body,
      contentType: "application/json",
      stream: false,
    };
    if (options.token !== undefined) {
      request.token = options.token;
    }
    if (options.idempotencyKey !== undefined) {
      request.idempotencyKey = options.idempotencyKey;
    }
    if (options.extraHeaders !== undefined) {
      request.extraHeaders = options.extraHeaders;
    }
    const { response, body: responseBody } = await this.sendWithRetry(request);
    const bytes = responseBody ?? new Uint8Array();
    if (response.status < 200 || response.status >= 300) {
      throw problemError(response.status, bytes);
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new ResponseFormatError("innerva returned invalid JSON");
    }
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
      throw new ResponseFormatError("innerva returned a non-object response");
    }
    return decoded as Record<string, unknown>;
  }

  private async sendWithRetry(
    request: SendRequest,
  ): Promise<{ response: Response; body?: Uint8Array }> {
    const policy = this.retryPolicy;
    let lastError: unknown;
    for (let attempt = 1; attempt <= policy.maxAttempts; attempt += 1) {
      let response: Response;
      try {
        response = await this.sendOnce(request);
      } catch (error) {
        lastError = error;
        if (attempt < policy.maxAttempts) {
          await this.sleep(this.backoffDelayMs(attempt, undefined));
        }
        continue;
      }
      if (RETRYABLE_STATUSES.has(response.status) && attempt < policy.maxAttempts) {
        const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
        await response.body?.cancel().catch(() => undefined);
        await this.sleep(this.backoffDelayMs(attempt, retryAfter));
        continue;
      }
      if (request.stream) {
        return { response };
      }
      return { response, body: await readLimited(response) };
    }
    throw new TransportError(
      `innerva request failed after ${policy.maxAttempts} attempts: ${String(lastError)}`,
      policy.maxAttempts,
    );
  }

  private async sendOnce(request: SendRequest): Promise<Response> {
    const headers: Record<string, string> = { "accept-encoding": "identity" };
    const authorization = request.token !== undefined ? `Innerva ${request.token}` : undefined;
    if (request.body !== undefined) {
      headers["content-type"] = request.contentType ?? "application/json";
      headers["content-digest"] = await signing.contentDigest(request.body);
    }
    if (authorization !== undefined) {
      headers["authorization"] = authorization;
    }
    if (request.idempotencyKey !== undefined) {
      headers["idempotency-key"] = request.idempotencyKey;
    }
    for (const [name, value] of Object.entries(request.extraHeaders ?? {})) {
      headers[name.toLowerCase()] = value;
    }
    const signed = await signing.signRequest(this.key, {
      method: request.method,
      targetUri: request.endpoint,
      created: Math.floor(this.now() / 1000),
      contentType: request.body !== undefined ? request.contentType : undefined,
      body: request.body,
      authorization,
      idempotencyKey: request.idempotencyKey,
    });
    headers["innerva-nonce"] = signed.innervaNonce;
    headers["signature-input"] = signed.signatureInput;
    headers["signature"] = signed.signature;
    const init: RequestInit = {
      method: request.method,
      headers,
      redirect: "manual",
    };
    if (request.body !== undefined) {
      init.body = request.body as BodyInit;
    }
    if (!request.stream) {
      init.signal = AbortSignal.timeout(this.requestTimeoutMs);
    }
    return this.fetchImpl(request.endpoint, init);
  }

  private backoffDelayMs(attempt: number, retryAfterSeconds: number | undefined): number {
    const policy = this.retryPolicy;
    const cap = Math.min(policy.maxBackoffMs, policy.initialBackoffMs * 2 ** (attempt - 1));
    let delay = cap * this.random();
    if (retryAfterSeconds !== undefined) {
      delay = Math.min(Math.max(delay, retryAfterSeconds * 1000), policy.maxBackoffMs);
    }
    return delay;
  }

  private acceptCapability(response: Record<string, unknown>): Capability {
    let capability: Capability;
    try {
      const token = asRecord(response["access_token"]);
      const key = asRecord(token["key"]);
      if (key["jkt"] !== this.key.keyId) {
        throw new KeyBindingError("innerva capability is bound to an unexpected proof key");
      }
      const access = token["access"];
      if (!Array.isArray(access) || access.length !== 1) {
        throw new Error("unexpected access list");
      }
      const granted = asRecord(access[0]);
      const manage = asRecord(token["manage"]);
      const credits = asRecord(granted["credits"]);
      const managementUri = nonEmptyString(manage["uri"]);
      const expiresIn = token["expires_in"];
      if (typeof expiresIn !== "number" || expiresIn < 1) {
        throw new Error("invalid expiry");
      }
      capability = {
        value: nonEmptyString(token["value"]),
        managementToken: nonEmptyString(asRecord(manage["access_token"])["value"]),
        managementUri,
        capabilityId: managementUri.replace(/\/+$/, "").split("/").pop() ?? "",
        grantId: nonEmptyString(granted["grant_id"]),
        grantLimit: integerField(credits["grant_limit"]),
        grantRemaining: integerField(credits["grant_remaining"]),
        expiresAt: this.now() + expiresIn * 1000,
      };
    } catch (error) {
      if (error instanceof KeyBindingError) {
        throw error;
      }
      throw new ResponseFormatError("innerva returned an incomplete capability");
    }
    this.requireSameOrigin(capability.managementUri, "management URI");
    return capability;
  }

  private origin(): string {
    return this.base.origin;
  }

  private requireSameOrigin(value: string, label: string): void {
    const parsed = parseAbsoluteUrl(value, label);
    if (parsed.origin !== this.base.origin) {
      throw new ConfigurationError(`${label} origin does not match the configured base URL`);
    }
  }
}

interface SendRequest {
  method: string;
  endpoint: string;
  body?: Uint8Array;
  contentType?: string;
  token?: string;
  idempotencyKey?: string;
  extraHeaders?: Record<string, string>;
  stream: boolean;
}

async function* iterateStream(stream: ReadableStream<Uint8Array>): AsyncGenerator<Uint8Array> {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return;
      }
      yield value;
    }
  } finally {
    reader.releaseLock();
  }
}

async function readLimited(response: Response): Promise<Uint8Array> {
  if (response.body === null) {
    return new Uint8Array();
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of iterateStream(response.body)) {
    total += chunk.length;
    if (total > MAX_RESPONSE_BODY) {
      await response.body.cancel().catch(() => undefined);
      throw new ResponseFormatError("innerva response is too large");
    }
    chunks.push(chunk);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
}

async function operationIdempotencyKey(prefix: string, credential: string): Promise<string> {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(credential)),
  );
  return prefix + Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validOperationKey(value: string): boolean {
  if (value.length < 1 || value.length > 128) {
    return false;
  }
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code < 0x21 || code > 0x7e) {
      return false;
    }
  }
  return true;
}

function parseAbsoluteUrl(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConfigurationError(`${label} must be an absolute HTTP(S) URL`);
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.hostname === "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== ""
  ) {
    throw new ConfigurationError(
      `${label} must be an absolute HTTP(S) URL without credentials or fragment`,
    );
  }
  return parsed;
}

function isLoopbackHost(host: string): boolean {
  const trimmed = host.toLowerCase().replace(/\.$/, "");
  if (trimmed === "localhost" || trimmed === "[::1]") {
    return true;
  }
  return /^127(\.\d{1,3}){3}$/.test(trimmed);
}

function timingSafeEqual(expected: string, actual: string): boolean {
  if (expected.length !== actual.length) {
    return false;
  }
  let mismatch = 0;
  for (let index = 0; index < expected.length; index += 1) {
    mismatch |= expected.charCodeAt(index) ^ actual.charCodeAt(index);
  }
  return mismatch === 0;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("expected an object");
  }
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown): string {
  if (typeof value !== "string" || value === "") {
    throw new Error("expected a non-empty string");
  }
  return value;
}

function integerField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error("expected an integer");
  }
  return value;
}

function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) {
    return undefined;
  }
  const seconds = Number(value.trim());
  if (!Number.isFinite(seconds)) {
    return undefined;
  }
  return Math.max(0, seconds);
}

function problemError(status: number, body: Uint8Array): ProblemError {
  let code = "unknown";
  let title = `HTTP ${status}`;
  let detail: string | undefined;
  try {
    const decoded = JSON.parse(new TextDecoder().decode(body));
    if (typeof decoded === "object" && decoded !== null && typeof decoded.code === "string") {
      code = decoded.code;
      if (typeof decoded.title === "string" && decoded.title !== "") {
        title = decoded.title;
      }
      if (typeof decoded.detail === "string") {
        detail = decoded.detail;
      }
    }
  } catch {
    // Fall through to the generic HTTP error.
  }
  if (code === "inference_already_started") {
    return new InferenceAlreadyStartedError(status, code, title, detail);
  }
  return new ProblemError(status, code, title, detail);
}
