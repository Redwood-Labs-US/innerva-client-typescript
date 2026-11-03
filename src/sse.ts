/**
 * Strict decoding of the v0.1 inference event stream.
 *
 * Mirrors the Go reference decoder exactly: unknown events, malformed lines,
 * duplicate or out-of-order events, and comment-only blocks are protocol
 * violations, and a stream that ends without a terminal event is a typed
 * interruption. Streamed content is never retained server-side, so no failure
 * here may be retried automatically.
 */

import {
  InferenceStreamError,
  StreamError,
  StreamInterruptedError,
  StreamProtocolError,
  type StreamErrorCode,
} from "./errors";
import type { InferenceOutcome, StreamEvent } from "./types";

export const MAX_SSE_LINE_BYTES = 1 << 20;
export const MAX_OUTPUT_BYTES = 8 << 20;

const MODEL = "innerva:standard";
const STREAM_ERROR_CODES: ReadonlySet<string> = new Set([
  "incomplete_provider_stream",
  "provider_stream_failed",
  "invalid_provider_stream",
  "accounting_failed",
]);

/** Decode a byte stream of SSE data into typed events ending with an outcome. */
export async function* decodeInferenceStream(
  chunks: AsyncIterable<Uint8Array>,
): AsyncGenerator<StreamEvent, void, undefined> {
  const decoder = new Decoder();
  let eventName = "";
  let dataLines: string[] = [];
  for await (const line of lines(chunks, decoder)) {
    if (line === "") {
      const events = decoder.apply(eventName, dataLines.join("\n"));
      yield* events;
      if (decoder.finished) {
        return;
      }
      eventName = "";
      dataLines = [];
      continue;
    }
    if (line.startsWith(":")) {
      continue;
    }
    const separator = line.indexOf(":");
    if (separator < 0) {
      throw decoder.protocolError("malformed inference stream line");
    }
    const field = line.slice(0, separator);
    let value = line.slice(separator + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }
    if (field === "event") {
      if (eventName !== "") {
        throw decoder.protocolError("duplicate event field in one inference event");
      }
      eventName = value;
    } else if (field === "data") {
      dataLines.push(value);
    } else {
      throw decoder.protocolError("unsupported inference event field");
    }
  }
  if (eventName !== "" || dataLines.length > 0) {
    yield* decoder.apply(eventName, dataLines.join("\n"));
    if (decoder.finished) {
      return;
    }
  }
  throw new StreamInterruptedError(
    "inference stream ended before a terminal event",
    decoder.operationId,
    decoder.partialOutput(),
  );
}

async function* lines(chunks: AsyncIterable<Uint8Array>, decoder: Decoder): AsyncGenerator<string> {
  const textDecoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = new Uint8Array(0);
  const iterator = chunks[Symbol.asyncIterator]();
  for (;;) {
    let next: IteratorResult<Uint8Array>;
    try {
      next = await iterator.next();
    } catch (error) {
      if (error instanceof StreamError) {
        throw error;
      }
      throw new StreamInterruptedError(
        `inference stream connection failed: ${String(error)}`,
        decoder.operationId,
        decoder.partialOutput(),
      );
    }
    if (next.done) {
      break;
    }
    const merged = new Uint8Array(buffer.length + next.value.length);
    merged.set(buffer);
    merged.set(next.value, buffer.length);
    buffer = merged;
    let newline = buffer.indexOf(0x0a);
    while (newline >= 0) {
      yield decodeLine(buffer.subarray(0, newline), decoder, textDecoder);
      buffer = buffer.subarray(newline + 1);
      newline = buffer.indexOf(0x0a);
    }
    if (buffer.length > MAX_SSE_LINE_BYTES) {
      throw decoder.protocolError("inference stream line is too long");
    }
  }
  if (buffer.length > 0) {
    yield decodeLine(buffer, decoder, textDecoder);
  }
}

function decodeLine(raw: Uint8Array, decoder: Decoder, textDecoder: TextDecoder): string {
  if (raw.length > MAX_SSE_LINE_BYTES) {
    throw decoder.protocolError("inference stream line is too long");
  }
  try {
    return textDecoder.decode(raw);
  } catch {
    throw decoder.protocolError("inference stream line is not UTF-8");
  }
}

class Decoder {
  operationId = "";
  finished = false;
  private outputParts: string[] = [];
  private outputBytes = 0;

  partialOutput(): string {
    return this.outputParts.join("");
  }

  protocolError(message: string): StreamProtocolError {
    return new StreamProtocolError(
      `innerva returned an invalid inference stream: ${message}`,
      this.operationId,
      this.partialOutput(),
    );
  }

  apply(eventName: string, data: string): StreamEvent[] {
    if (eventName === "" || data === "") {
      throw this.protocolError("incomplete inference event");
    }
    const payload = this.strictJson(eventName, data);
    switch (eventName) {
      case "response.created":
        return [this.applyCreated(payload)];
      case "response.output_text.delta":
        return [this.applyDelta(payload)];
      case "response.completed":
      case "response.incomplete": {
        const outcome = this.applyTerminal(eventName, payload);
        this.finished = true;
        return [outcome];
      }
      case "error":
        throw this.applyError(payload);
      default:
        throw this.protocolError("unsupported inference event");
    }
  }

  private strictJson(eventName: string, data: string): Record<string, unknown> {
    let payload: unknown;
    try {
      payload = JSON.parse(data);
    } catch {
      throw this.protocolError(`invalid JSON for ${eventName}`);
    }
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
      throw this.protocolError(`${eventName} data is not a JSON object`);
    }
    return payload as Record<string, unknown>;
  }

  private applyCreated(payload: Record<string, unknown>): StreamEvent {
    const response = payload["response"];
    if (
      this.operationId !== "" ||
      !hasExactKeys(payload, ["type", "response"]) ||
      payload["type"] !== "response.created" ||
      !isRecord(response) ||
      !hasExactKeys(response, ["id", "model", "status"]) ||
      typeof response["id"] !== "string" ||
      response["id"] === "" ||
      response["model"] !== MODEL ||
      response["status"] !== "in_progress"
    ) {
      throw this.protocolError("invalid response.created event");
    }
    this.operationId = response["id"];
    return { kind: "started", operationId: this.operationId };
  }

  private applyDelta(payload: Record<string, unknown>): StreamEvent {
    const delta = payload["delta"];
    if (
      this.operationId === "" ||
      !hasExactKeys(payload, ["type", "response_id", "delta"]) ||
      payload["type"] !== "response.output_text.delta" ||
      payload["response_id"] !== this.operationId ||
      typeof delta !== "string"
    ) {
      throw this.protocolError("invalid response delta");
    }
    const encodedLength = new TextEncoder().encode(delta).length;
    if (this.outputBytes + encodedLength > MAX_OUTPUT_BYTES) {
      throw this.protocolError("inference output exceeds the maximum size");
    }
    this.outputParts.push(delta);
    this.outputBytes += encodedLength;
    return { kind: "delta", operationId: this.operationId, delta };
  }

  private applyTerminal(eventName: string, payload: Record<string, unknown>): InferenceOutcome {
    const expectedStatus = eventName.slice("response.".length);
    const response = payload["response"];
    if (
      this.operationId === "" ||
      !hasExactKeys(payload, ["type", "response"]) ||
      payload["type"] !== eventName ||
      !isRecord(response) ||
      !hasExactKeys(response, ["id", "model", "status", "usage", "credits"]) ||
      response["id"] !== this.operationId ||
      response["model"] !== MODEL ||
      response["status"] !== expectedStatus
    ) {
      throw this.protocolError(`invalid terminal ${eventName} event`);
    }
    const usage = response["usage"];
    const credits = response["credits"];
    if (
      !isRecord(usage) ||
      !hasExactKeys(usage, ["input_units", "output_units"]) ||
      !isNonNegativeInteger(usage["input_units"]) ||
      !isNonNegativeInteger(usage["output_units"]) ||
      !isRecord(credits) ||
      !hasExactKeys(credits, ["charged", "unit", "capped"]) ||
      !isNonNegativeInteger(credits["charged"]) ||
      credits["unit"] !== "innerva_credit" ||
      typeof credits["capped"] !== "boolean"
    ) {
      throw this.protocolError(`invalid terminal ${eventName} event`);
    }
    const output = this.partialOutput();
    const shared = {
      operationId: this.operationId,
      output,
      usage: {
        inputUnits: usage["input_units"] as number,
        outputUnits: usage["output_units"] as number,
      },
      credits: {
        charged: credits["charged"] as number,
        capped: credits["capped"],
        unit: "innerva_credit" as const,
      },
    };
    if (expectedStatus === "completed") {
      return { kind: "completed", ...shared };
    }
    return {
      kind: "incomplete",
      ...shared,
      producedNoOutput: output === "" && shared.credits.charged === 0,
    };
  }

  private applyError(payload: Record<string, unknown>): StreamError {
    const error = payload["error"];
    if (
      !hasExactKeys(payload, ["type", "error"]) ||
      payload["type"] !== "error" ||
      !isRecord(error) ||
      !hasExactKeys(error, ["code", "message"]) ||
      typeof error["code"] !== "string" ||
      typeof error["message"] !== "string"
    ) {
      throw this.protocolError("invalid inference error event");
    }
    if (!STREAM_ERROR_CODES.has(error["code"])) {
      throw this.protocolError("unknown inference error code");
    }
    return new InferenceStreamError(
      error["code"] as StreamErrorCode,
      error["message"],
      this.operationId,
      this.partialOutput(),
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const present = Object.keys(value);
  return present.length === keys.length && keys.every((key) => present.includes(key));
}

function isNonNegativeInteger(value: unknown): boolean {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}
