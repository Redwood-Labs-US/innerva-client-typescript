/**
 * Typed protocol values for the Innerva Grant Protocol v0.1.
 *
 * Terminal outcomes, credit accounting, stream events, and error causes are
 * discriminated unions so callers can branch on results without parsing prose.
 */

/** The unit credits are accounted in. v0.1 defines exactly one. */
export type CreditUnit = "innerva_credit";

/** Provider-reported usage for one inference operation. */
export interface Usage {
  readonly inputUnits: number;
  readonly outputUnits: number;
}

/**
 * The authoritative credit accounting for one inference operation. `charged`
 * is what the grant was actually debited; `capped` means the charge was
 * limited by the remaining grant balance rather than measured usage alone.
 */
export interface Credits {
  readonly charged: number;
  readonly capped: boolean;
  readonly unit: CreditUnit;
}

/** A terminal response whose output text was delivered in full. */
export interface CompletedResponse {
  readonly kind: "completed";
  readonly operationId: string;
  readonly output: string;
  readonly usage: Usage;
  readonly credits: Credits;
}

/**
 * A terminal response that did not deliver complete output text.
 *
 * Covers both a budget-capped response (partial `output`, usually
 * `credits.capped`) and the uncharged no-output case: the provider terminated upstream
 * without producing any visible text, the reservation was released, and
 * `credits.charged` is 0. Branch on `producedNoOutput` for that case —
 * retrying it is a new operation and a new charge, and may again produce no
 * output.
 */
export interface IncompleteResponse {
  readonly kind: "incomplete";
  readonly operationId: string;
  readonly output: string;
  readonly usage: Usage;
  readonly credits: Credits;
  /** True for the uncharged no-output case: no output text and nothing charged. */
  readonly producedNoOutput: boolean;
}

/** A terminal inference outcome: the stream ended with an authoritative result. */
export type InferenceOutcome = CompletedResponse | IncompleteResponse;

/**
 * The server accepted the operation and opened the stream. After this event
 * the operation is charged as it runs; a failure past this point is never
 * auto-retried.
 */
export interface StreamStarted {
  readonly kind: "started";
  readonly operationId: string;
}

/** The next fragment of normalized output text. Innerva does not retain it. */
export interface OutputTextDelta {
  readonly kind: "delta";
  readonly operationId: string;
  readonly delta: string;
}

/** Events yielded by `Client.inferStream`, ending with a terminal outcome. */
export type StreamEvent = StreamStarted | OutputTextDelta | InferenceOutcome;

/** The durable state needed to finish one browser interaction. */
export interface PendingAccess {
  readonly requestId: string;
  readonly instanceId: string;
  readonly interactionUri: string;
  readonly continuationUri: string;
  readonly continuationToken: string;
  readonly clientFinish: string;
  readonly serverFinish: string;
  readonly accessEndpoint: string;
}

/**
 * An opaque inference credential plus its lifecycle authority. Keep it
 * protected and pass the same object to inference calls so the SDK can
 * replace an expiring inference token in place before starting a request.
 */
export interface Capability {
  value: string;
  managementToken: string;
  managementUri: string;
  capabilityId: string;
  grantId: string;
  grantLimit: number;
  grantRemaining: number;
  /** Milliseconds since epoch; undefined disables automatic rotation. */
  expiresAt?: number | undefined;
}

/**
 * Exponential backoff with full jitter for pre-stream failures only: network
 * failures, 5xx before a stream opened, and 429 (honoring `Retry-After` up to
 * `maxBackoffMs`). One idempotency key is generated per logical operation and
 * reused across every attempt.
 */
export interface RetryPolicy {
  readonly maxAttempts: number;
  readonly initialBackoffMs: number;
  readonly maxBackoffMs: number;
}

/** The default retry policy. */
export const defaultRetryPolicy: RetryPolicy = {
  maxAttempts: 4,
  initialBackoffMs: 250,
  maxBackoffMs: 4000,
};

/** Options for one access request. */
export interface CreateAccessOptions {
  readonly suggestedCredits?: number;
  readonly minimumCredits?: number;
  readonly clientReference?: string;
  readonly callbackUri?: string;
  readonly idempotencyKey?: string;
}

/** Options for one inference operation. */
export interface InferOptions {
  readonly maxOutputTokens: number;
  readonly idempotencyKey?: string;
}
