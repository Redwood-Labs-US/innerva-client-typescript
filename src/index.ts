/**
 * TypeScript server SDK for the Innerva Grant Protocol v0.1.
 *
 * ```ts
 * import { createClient, loadOrCreateProofKey } from "@innerva/client";
 *
 * const client = await createClient({
 *   baseUrl: "https://innerva.net",
 *   key: await loadOrCreateProofKey("/var/lib/myapp/innerva-proof-key.json"),
 *   displayName: "My App",
 *   displayUri: "https://myapp.example",
 *   callbackUri: "https://myapp.example/innerva/callback",
 * });
 *
 * const pending = await client.createAccess({ suggestedCredits: 1000 });
 * // Send the customer to pending.interactionUri; on callback:
 * const capability = await client.continueAccess(pending, interactRef, hash);
 * const outcome = await client.infer(capability, "Hello!", { maxOutputTokens: 256 });
 * switch (outcome.kind) {
 *   case "completed":
 *     console.log(outcome.output, outcome.credits.charged);
 *     break;
 *   case "incomplete":
 *     if (outcome.producedNoOutput) {
 *       // Completed upstream with no visible output — charged 0.
 *     }
 *     break;
 * }
 * ```
 */

export { Client, createClient, MAX_RESPONSE_BODY, type ClientConfig } from "./client";
export { loadOrCreateProofKey } from "./keyfile";
export {
  CallbackBindingError,
  ConfigurationError,
  InferenceAlreadyStartedError,
  InferenceStreamError,
  InnervaError,
  KeyBindingError,
  ProblemError,
  ResponseFormatError,
  StreamError,
  StreamInterruptedError,
  StreamProtocolError,
  TransportError,
  type ProblemCode,
  type StreamErrorCode,
} from "./errors";
export {
  defaultRetryPolicy,
  type Capability,
  type CompletedResponse,
  type CreateAccessOptions,
  type CreditUnit,
  type Credits,
  type IncompleteResponse,
  type InferenceOutcome,
  type InferOptions,
  type OutputTextDelta,
  type PendingAccess,
  type RetryPolicy,
  type StreamEvent,
  type StreamStarted,
  type Usage,
} from "./types";
export { decodeInferenceStream } from "./sse";
export { generateProofJwk } from "./signing";
