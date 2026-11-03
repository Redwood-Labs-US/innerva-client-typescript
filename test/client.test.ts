/** Behavioral tests for the client: retry boundary, idempotency, typed outcomes. */

import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { createClient, type Client } from "../src/client";
import {
  CallbackBindingError,
  ConfigurationError,
  InferenceAlreadyStartedError,
  KeyBindingError,
  ProblemError,
  StreamInterruptedError,
  TransportError,
} from "../src/errors";
import { callbackHash, contentDigest, generateProofJwk } from "../src/signing";
import type { Capability } from "../src/types";

const OPERATION_ID = "resp_test234567abcdefghijklmnop";

function sseCompleted(output = "Hello."): string {
  const delta =
    output === ""
      ? ""
      : `event: response.output_text.delta\ndata: ${JSON.stringify({
          type: "response.output_text.delta",
          response_id: OPERATION_ID,
          delta: output,
        })}\n\n`;
  return (
    `event: response.created\ndata: {"type":"response.created","response":{"id":"${OPERATION_ID}","model":"innerva:standard","status":"in_progress"}}\n\n` +
    delta +
    `event: response.completed\ndata: {"type":"response.completed","response":{"id":"${OPERATION_ID}","model":"innerva:standard","status":"completed","usage":{"input_units":3,"output_units":2},"credits":{"charged":2,"unit":"innerva_credit","capped":false}}}\n\n`
  );
}

function sseEmptyUncharged(): string {
  return (
    `event: response.created\ndata: {"type":"response.created","response":{"id":"${OPERATION_ID}","model":"innerva:standard","status":"in_progress"}}\n\n` +
    `event: response.incomplete\ndata: {"type":"response.incomplete","response":{"id":"${OPERATION_ID}","model":"innerva:standard","status":"incomplete","usage":{"input_units":30,"output_units":512},"credits":{"charged":0,"unit":"innerva_credit","capped":false}}}\n\n`
  );
}

function ssePartialThenEof(): string {
  return (
    `event: response.created\ndata: {"type":"response.created","response":{"id":"${OPERATION_ID}","model":"innerva:standard","status":"in_progress"}}\n\n` +
    `event: response.output_text.delta\ndata: {"type":"response.output_text.delta","response_id":"${OPERATION_ID}","delta":"partial ans"}\n\n`
  );
}

type Scripted =
  | "drop"
  | {
      status: number;
      body: string;
      contentType?: string;
      headers?: Record<string, string>;
    };

interface RecordedRequest {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

interface Stub {
  url: string;
  requests: RecordedRequest[];
  script: Scripted[];
  close(): Promise<void>;
}

function problem(status: number, code: string): Scripted {
  return {
    status,
    body: JSON.stringify({ type: "about:blank", title: code, status, code }),
    contentType: "application/problem+json",
  };
}

async function startStub(): Promise<Stub> {
  const requests: RecordedRequest[] = [];
  const script: Scripted[] = [];
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      requests.push({
        method: request.method ?? "",
        path: request.url ?? "",
        headers: request.headers,
        body: Buffer.concat(chunks),
      });
      const item = script.shift();
      assert.ok(item !== undefined, "no scripted response left");
      if (item === "drop") {
        request.socket.destroy();
        return;
      }
      response.writeHead(item.status, {
        "content-type": item.contentType ?? "application/json",
        ...item.headers,
      });
      response.end(item.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    script,
    close: () =>
      new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

interface Harness {
  stub: Stub;
  client: Client;
  sleeps: number[];
  capability(overrides?: Partial<Capability>): Capability;
  capabilityResponse(): Scripted;
}

async function startHarness(t: { after(fn: () => Promise<void> | void): void }): Promise<Harness> {
  const stub = await startStub();
  t.after(() => stub.close());
  const client = await createClient({
    baseUrl: stub.url,
    key: await generateProofJwk(),
    displayName: "Test App",
    displayUri: "https://client.example",
    callbackUri: "https://client.example/callback",
  });
  const sleeps: number[] = [];
  client.sleep = async (ms) => {
    sleeps.push(ms);
  };
  return {
    stub,
    client,
    sleeps,
    capability: (overrides = {}) => ({
      value: "it1_test_inference_token_value_x",
      managementToken: "mt1_test_management_token_value",
      managementUri: `${stub.url}/v1/capabilities/cap_test34567abcdefghijklmnopq`,
      capabilityId: "cap_test34567abcdefghijklmnopq",
      grantId: "grant_test34567abcdefghijklmno",
      grantLimit: 1000,
      grantRemaining: 900,
      ...overrides,
    }),
    capabilityResponse: () => ({
      status: 200,
      body: JSON.stringify({
        access_token: {
          value: "it1_rotated_inference_token_value",
          access: [
            {
              type: "innerva_inference",
              actions: ["responses.create"],
              models: ["innerva:standard"],
              credits: { grant_limit: 1000, grant_remaining: 800, unit: "innerva_credit" },
              grant_id: "grant_test34567abcdefghijklmno",
            },
          ],
          expires_in: 600,
          key: { jkt: client.keyThumbprint },
          manage: {
            uri: `${stub.url}/v1/capabilities/cap_test34567abcdefghijklmnopq`,
            access_token: { value: "mt1_rotated_management_token_val" },
          },
        },
      }),
    }),
  };
}

test("infer returns a typed completed outcome over a fully signed request", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push({
    status: 200,
    body: sseCompleted(),
    contentType: "text/event-stream",
  });
  const outcome = await harness.client.infer(harness.capability(), "Say hello.", {
    maxOutputTokens: 64,
  });
  assert.equal(outcome.kind, "completed");
  assert.equal(outcome.output, "Hello.");
  assert.equal(outcome.credits.charged, 2);
  assert.equal(outcome.operationId, OPERATION_ID);
  const request = harness.stub.requests[0]!;
  for (const header of [
    "signature",
    "signature-input",
    "innerva-nonce",
    "content-digest",
    "idempotency-key",
  ]) {
    assert.ok(request.headers[header], header);
  }
  assert.ok(String(request.headers["authorization"]).startsWith("Innerva it1_"));
  assert.equal(
    request.headers["content-digest"],
    await contentDigest(new Uint8Array(request.body)),
  );
});

test("uncharged no-output outcome is branchable and uncharged", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push({
    status: 200,
    body: sseEmptyUncharged(),
    contentType: "text/event-stream",
  });
  const outcome = await harness.client.infer(harness.capability(), "Think.", {
    maxOutputTokens: 512,
  });
  assert.equal(outcome.kind, "incomplete");
  assert.ok(outcome.kind === "incomplete" && outcome.producedNoOutput);
  assert.equal(outcome.credits.charged, 0);
  assert.equal(outcome.usage.outputUnits, 512);
});

test("pre-stream 5xx retries with the same idempotency key and a fresh nonce", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push(problem(503, "unavailable"), {
    status: 200,
    body: sseCompleted(),
    contentType: "text/event-stream",
  });
  const outcome = await harness.client.infer(harness.capability(), "Hi", { maxOutputTokens: 16 });
  assert.equal(outcome.kind, "completed");
  assert.equal(harness.stub.requests.length, 2);
  const [first, second] = harness.stub.requests;
  assert.equal(first!.headers["idempotency-key"], second!.headers["idempotency-key"]);
  assert.notEqual(first!.headers["innerva-nonce"], second!.headers["innerva-nonce"]);
  assert.equal(harness.sleeps.length, 1);
});

test("a dropped connection before any response is retried", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push("drop", {
    status: 200,
    body: sseCompleted(),
    contentType: "text/event-stream",
  });
  const outcome = await harness.client.infer(harness.capability(), "Hi", { maxOutputTokens: 16 });
  assert.equal(outcome.kind, "completed");
  assert.equal(harness.stub.requests.length, 2);
});

test("429 honors Retry-After", async (t) => {
  const harness = await startHarness(t);
  const limited = problem(429, "rate_limited") as Exclude<Scripted, "drop">;
  limited.headers = { "retry-after": "2" };
  harness.stub.script.push(limited, {
    status: 200,
    body: sseCompleted(),
    contentType: "text/event-stream",
  });
  const outcome = await harness.client.infer(harness.capability(), "Hi", { maxOutputTokens: 16 });
  assert.equal(outcome.kind, "completed");
  assert.ok(harness.sleeps[0]! >= 2000);
});

test("409 inference_already_started is typed and never retried", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push(problem(409, "inference_already_started"));
  await assert.rejects(
    harness.client.infer(harness.capability(), "Hi", { maxOutputTokens: 16 }),
    (error: unknown) => {
      if (!(error instanceof InferenceAlreadyStartedError)) {
        return false;
      }
      assert.equal(error.code, "inference_already_started");
      return true;
    },
  );
  assert.equal(harness.stub.requests.length, 1);
  assert.equal(harness.sleeps.length, 0);
});

test("an interrupted stream is typed with partial output and never retried", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push({
    status: 200,
    body: ssePartialThenEof(),
    contentType: "text/event-stream",
  });
  await assert.rejects(
    harness.client.infer(harness.capability(), "Hi", { maxOutputTokens: 16 }),
    (error: unknown) => {
      if (!(error instanceof StreamInterruptedError)) {
        return false;
      }
      assert.equal(error.operationId, OPERATION_ID);
      assert.equal(error.partialOutput, "partial ans");
      return true;
    },
  );
  assert.equal(harness.stub.requests.length, 1);
});

test("a non-retryable problem is raised once with its typed code", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push(problem(402, "insufficient_credits"));
  await assert.rejects(
    harness.client.infer(harness.capability(), "Hi", { maxOutputTokens: 16 }),
    (error: unknown) => {
      if (!(error instanceof ProblemError)) {
        return false;
      }
      assert.equal(error.code, "insufficient_credits");
      assert.equal(error.status, 402);
      return true;
    },
  );
  assert.equal(harness.stub.requests.length, 1);
});

test("exhausted retries raise a transport error", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push("drop", "drop", "drop", "drop");
  await assert.rejects(
    harness.client.infer(harness.capability(), "Hi", { maxOutputTokens: 16 }),
    (error: unknown) => error instanceof TransportError,
  );
  assert.equal(harness.stub.requests.length, 4);
});

test("an expiring capability is rotated in place before inference", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push(harness.capabilityResponse(), {
    status: 200,
    body: sseCompleted(),
    contentType: "text/event-stream",
  });
  const capability = harness.capability({ expiresAt: Date.now() });
  const outcome = await harness.client.infer(capability, "Hi", { maxOutputTokens: 16 });
  assert.equal(outcome.kind, "completed");
  assert.equal(capability.value, "it1_rotated_inference_token_value");
  const [rotate, infer] = harness.stub.requests;
  assert.ok(rotate!.path.endsWith("/rotate"));
  assert.ok(String(rotate!.headers["idempotency-key"]).startsWith("rotate-"));
  assert.ok(String(infer!.headers["authorization"]).endsWith("it1_rotated_inference_token_value"));
});

test("a capability bound to a foreign key is rejected", async (t) => {
  const harness = await startHarness(t);
  const response = harness.capabilityResponse() as Exclude<Scripted, "drop">;
  const body = JSON.parse(response.body);
  body.access_token.key.jkt = "someone-elses-thumbprint";
  response.body = JSON.stringify(body);
  harness.stub.script.push(response);
  await assert.rejects(
    harness.client.rotate(harness.capability()),
    (error: unknown) => error instanceof KeyBindingError,
  );
});

test("createAccess and continueAccess round trip", async (t) => {
  const harness = await startHarness(t);
  const created = {
    protocol_version: "0.1",
    request_id: "ar_test234567abcdefghijklmnopq",
    instance_id: "ci_test234567abcdefghijklmnopq",
    continue: {
      uri: `${harness.stub.url}/v1/access-requests/ar_test234567abcdefghijklmnopq/continue`,
      access_token: { value: "ct1_test_continuation_token_valu" },
      wait: 0,
    },
    interact: {
      redirect: `${harness.stub.url}/interact/ix_test234567abcdefghijklmnopq`,
      finish: "sf1_test_server_finish_value",
    },
    expires_in: 600,
  };
  harness.stub.script.push(
    { status: 200, body: JSON.stringify(created) },
    harness.capabilityResponse(),
  );
  const pending = await harness.client.createAccess({ suggestedCredits: 1000 });
  assert.equal(pending.requestId, "ar_test234567abcdefghijklmnopq");
  const requestBody = JSON.parse(harness.stub.requests[0]!.body.toString());
  assert.equal(requestBody.protocol_version, "0.1");
  assert.equal(requestBody.access_token.access[0].credits.suggested, 1000);
  assert.ok(harness.stub.requests[0]!.headers["idempotency-key"]);

  const interactRef = "ref_test_interaction_reference";
  const hash = await callbackHash(
    pending.clientFinish,
    pending.serverFinish,
    interactRef,
    pending.accessEndpoint,
  );
  assert.equal(await harness.client.validateCallback(pending, interactRef, "tampered"), false);
  await assert.rejects(
    harness.client.continueAccess(pending, interactRef, "tampered"),
    (error: unknown) => error instanceof CallbackBindingError,
  );
  const capability = await harness.client.continueAccess(pending, interactRef, hash);
  assert.equal(capability.value, "it1_rotated_inference_token_value");
  const continueRequest = harness.stub.requests[1]!;
  assert.ok(String(continueRequest.headers["idempotency-key"]).startsWith("continue-"));
  assert.deepEqual(JSON.parse(continueRequest.body.toString()), { interact_ref: interactRef });
});

test("revoke sends a signed DELETE without a content digest", async (t) => {
  const harness = await startHarness(t);
  harness.stub.script.push({ status: 204, body: "", contentType: "text/plain" });
  await harness.client.revoke(harness.capability());
  const request = harness.stub.requests[0]!;
  assert.equal(request.method, "DELETE");
  assert.equal(request.headers["content-digest"], undefined);
  assert.ok(request.headers["signature"]);
});

test("cross-origin endpoints are refused before any request is sent", async (t) => {
  const harness = await startHarness(t);
  await assert.rejects(
    harness.client.rotate(
      harness.capability({ managementUri: "https://evil.example/v1/capabilities/cap_x" }),
    ),
    (error: unknown) => error instanceof ConfigurationError,
  );
  assert.equal(harness.stub.requests.length, 0);
});
