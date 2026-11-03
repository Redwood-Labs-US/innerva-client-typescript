/**
 * Shared conformance vectors: signing, hashing, and stream outcomes. The
 * vectors are generated from the Go reference implementation
 * (`go run ./sdk/conformance/gen`) and every client SDK must pass them.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  InferenceStreamError,
  StreamInterruptedError,
  StreamProtocolError,
} from "../src/errors";
import * as signing from "../src/signing";
import { decodeInferenceStream } from "../src/sse";
import type { StreamEvent } from "../src/types";

// The vectors live at sdk/conformance/vectors in the repository and at
// <archive root>/conformance/vectors inside a downloaded SDK tarball.
const vectorsDir = [
  path.join(__dirname, "..", "..", "..", "conformance", "vectors"),
  path.join(__dirname, "..", "..", "conformance", "vectors"),
].find((candidate) => existsSync(candidate))!;

function load(name: string): any {
  return JSON.parse(readFileSync(path.join(vectorsDir, name), "utf-8"));
}

async function importPublic(jwk: { x: string; y: string }): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

async function verifyRaw(key: CryptoKey, base: string, signatureB64: string): Promise<boolean> {
  const raw = signing.fromBase64(signatureB64);
  assert.equal(raw.length, 64, "vector signature must be 64 raw bytes");
  return globalThis.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    raw as BufferSource,
    new TextEncoder().encode(base),
  );
}

test("signing conformance", async (t) => {
  const vectors = load("signing.json");
  const key = await signing.importProofKey(vectors.key.jwk);
  assert.equal(key.keyId, vectors.key.thumbprint);
  const publicKey = await importPublic(vectors.key.jwk);
  for (const signingCase of vectors.cases) {
    await t.test(signingCase.name, async () => {
      const request = signingCase.request;
      const expected = signingCase.expected;
      const body = new TextEncoder().encode(request.body ?? "");
      const digest = request.content_type ? await signing.contentDigest(body) : undefined;
      if (request.content_type) {
        assert.equal(digest, expected.content_digest);
      }
      const { base, signatureInput } = signing.signatureBase({
        method: request.method,
        targetUri: request.target_uri,
        nonce: signingCase.nonce,
        created: signingCase.created,
        expires: signingCase.expires,
        keyId: key.keyId,
        contentType: request.content_type,
        bodyDigest: digest,
        authorization: request.authorization,
        idempotencyKey: request.idempotency_key,
      });
      assert.equal(base, expected.signature_base);
      assert.equal(signatureInput, expected.signature_input);
      assert.ok(await verifyRaw(publicKey, base, expected.signature), "vector signature verifies");
      assert.ok(
        !(await verifyRaw(publicKey, base + "tampered", expected.signature)),
        "tampered base is rejected",
      );
      const own = await signing.signEs256(key.privateKey, base);
      assert.ok(await verifyRaw(publicKey, base, signing.toBase64(own)), "own signature verifies");
    });
  }
});

test("hashing conformance", async (t) => {
  const vectors = load("hashing.json");
  await t.test("thumbprints", async () => {
    for (const thumbprintCase of vectors.thumbprint_cases) {
      assert.equal(
        await signing.jwkThumbprint(thumbprintCase.jwk.x, thumbprintCase.jwk.y),
        thumbprintCase.thumbprint,
        thumbprintCase.name,
      );
    }
  });
  await t.test("content digests", async () => {
    for (const digestCase of vectors.content_digest_cases) {
      const body = signing.fromBase64(digestCase.body_base64);
      assert.equal(await signing.contentDigest(body), digestCase.content_digest, digestCase.name);
    }
  });
  await t.test("callback hashes", async () => {
    for (const callbackCase of vectors.callback_hash_cases) {
      assert.equal(
        await signing.callbackHash(
          callbackCase.client_finish,
          callbackCase.server_finish,
          callbackCase.interact_ref,
          callbackCase.access_endpoint,
        ),
        callbackCase.hash,
        callbackCase.name,
      );
    }
  });
});

async function* singleChunk(sse: string): AsyncGenerator<Uint8Array> {
  if (sse.length > 0) {
    yield new TextEncoder().encode(sse);
  }
}

async function collect(sse: string): Promise<StreamEvent[]> {
  const events: StreamEvent[] = [];
  for await (const event of decodeInferenceStream(singleChunk(sse))) {
    events.push(event);
  }
  return events;
}

test("stream conformance", async (t) => {
  const vectors = load("stream.json");
  for (const streamCase of vectors.cases) {
    await t.test(streamCase.name, async () => {
      const expect = streamCase.expect;
      switch (expect.kind) {
        case "completed":
        case "incomplete": {
          const events = await collect(streamCase.sse);
          const outcome = events[events.length - 1]!;
          assert.equal(outcome.kind, expect.kind);
          if (outcome.kind !== "completed" && outcome.kind !== "incomplete") {
            throw new Error("terminal event expected");
          }
          assert.equal(outcome.operationId, expect.operation_id ?? "");
          assert.equal(outcome.output, expect.output ?? "");
          assert.equal(outcome.usage.inputUnits, expect.input_units ?? 0);
          assert.equal(outcome.usage.outputUnits, expect.output_units ?? 0);
          assert.equal(outcome.credits.charged, expect.credits_charged ?? 0);
          assert.equal(outcome.credits.capped, expect.credits_capped ?? false);
          if (
            outcome.kind === "incomplete" &&
            (expect.credits_charged ?? 0) === 0 &&
            (expect.output ?? "") === ""
          ) {
            assert.ok(outcome.producedNoOutput, "uncharged no-output case must be branchable");
          }
          break;
        }
        case "stream_error": {
          await assert.rejects(collect(streamCase.sse), (error: unknown) => {
            if (!(error instanceof InferenceStreamError)) {
              return false;
            }
            assert.equal(error.code, expect.error_code);
            assert.equal(error.serverMessage, expect.error_message ?? "");
            assert.equal(error.operationId, expect.operation_id ?? "");
            assert.equal(error.partialOutput, expect.partial_output ?? "");
            return true;
          });
          break;
        }
        case "interrupted": {
          await assert.rejects(collect(streamCase.sse), (error: unknown) => {
            if (!(error instanceof StreamInterruptedError)) {
              return false;
            }
            assert.equal(error.operationId, expect.operation_id ?? "");
            assert.equal(error.partialOutput, expect.partial_output ?? "");
            return true;
          });
          break;
        }
        case "invalid": {
          await assert.rejects(
            collect(streamCase.sse),
            (error: unknown) => error instanceof StreamProtocolError,
          );
          break;
        }
        default:
          assert.fail(`unknown vector kind ${expect.kind}`);
      }
    });
  }
});
