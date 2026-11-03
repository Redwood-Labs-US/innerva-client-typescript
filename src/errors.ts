/**
 * Typed error causes for the Innerva TypeScript SDK.
 *
 * The retry boundary is encoded in the types: `TransportError` and retryable
 * problem statuses are the only causes the SDK retries by itself, and only
 * before a stream opens. Everything after `response.created` is a
 * `StreamError` carrying the operation id and whatever was streamed —
 * retrying one is a new operation and a new charge, so the SDK never does it
 * automatically.
 */

/** Documented protocol problem codes. Servers may add codes over time. */
export type ProblemCode =
  | "unsupported_protocol_version"
  | "invalid_request"
  | "invalid_signature"
  | "invalid_proof"
  | "invalid_credential"
  | "replay_detected"
  | "invalid_continuation"
  | "interaction_required"
  | "interaction_cancelled"
  | "payment_failed"
  | "insufficient_credits"
  | "access_denied"
  | "capability_expired"
  | "capability_revoked"
  | "idempotency_conflict"
  | "idempotency_mismatch"
  | "rate_limited"
  | "inference_already_started"
  | "provider_unavailable"
  | "streaming_unavailable"
  | "invalid_state"
  | "internal_error"
  | (string & {});

/** Error codes the server can emit as a typed event inside a stream. */
export type StreamErrorCode =
  | "incomplete_provider_stream"
  | "provider_stream_failed"
  | "invalid_provider_stream"
  | "accounting_failed";

/** Base class for every error thrown by this SDK. */
export class InnervaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The client or a request was configured with invalid values. */
export class ConfigurationError extends InnervaError {}

/** The browser callback does not bind to the pending access request. */
export class CallbackBindingError extends InnervaError {}

/** The server issued a capability bound to an unexpected proof key. */
export class KeyBindingError extends InnervaError {}

/** A network-level failure with no HTTP response, after retries. */
export class TransportError extends InnervaError {
  readonly attempts: number;

  constructor(message: string, attempts: number) {
    super(message);
    this.attempts = attempts;
  }
}

/** The server returned bytes that violate the strict v0.1 wire profile. */
export class ResponseFormatError extends InnervaError {}

/** The server rejected a request with an application/problem+json body. */
export class ProblemError extends InnervaError {
  readonly status: number;
  readonly code: ProblemCode;
  readonly title: string;
  readonly detail: string | undefined;

  constructor(status: number, code: ProblemCode, title: string, detail?: string) {
    super(`innerva ${code} (${status}): ${title}`);
    this.status = status;
    this.code = code;
    this.title = title;
    this.detail = detail;
  }
}

/**
 * The idempotency key was already used for a started inference (HTTP 409).
 *
 * Streamed content is never retained server-side, so the output cannot be
 * replayed. This is a terminal, typed outcome for the logical operation — the
 * SDK never retries it. Starting over means a new operation with a new
 * idempotency key and a new charge.
 */
export class InferenceAlreadyStartedError extends ProblemError {}

/**
 * A failure after the inference stream opened. Never auto-retried.
 *
 * `operationId` is empty if the failure happened before `response.created`
 * arrived; `partialOutput` is whatever text was streamed before the failure.
 * Any retry is a new operation with a new idempotency key and a new charge,
 * and is the caller's decision.
 */
export class StreamError extends InnervaError {
  readonly operationId: string;
  readonly partialOutput: string;

  constructor(message: string, operationId: string, partialOutput: string) {
    super(message);
    this.operationId = operationId;
    this.partialOutput = partialOutput;
  }
}

/** The server ended the stream with a typed error event. */
export class InferenceStreamError extends StreamError {
  readonly code: StreamErrorCode;
  readonly serverMessage: string;

  constructor(
    code: StreamErrorCode,
    serverMessage: string,
    operationId: string,
    partialOutput: string,
  ) {
    super(`innerva inference ${code}: ${serverMessage}`, operationId, partialOutput);
    this.code = code;
    this.serverMessage = serverMessage;
  }
}

/** The stream ended (or the connection failed) before a terminal event. */
export class StreamInterruptedError extends StreamError {}

/** The stream violated the strict v0.1 event profile. */
export class StreamProtocolError extends StreamError {}
