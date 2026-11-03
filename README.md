# Innerva TypeScript SDK

TypeScript server SDK for the Innerva Grant Protocol v0.1: ES256 HTTP message
signatures, the browser interaction flow, and streaming inference with typed
outcomes. Zero runtime dependencies — WebCrypto and `fetch` only (Node 18.17+,
modern edge runtimes; key storage helper requires Node).

> **Read-only mirror.** This repository is published automatically from the
> Innerva source repository on each SDK release; pull requests are not merged
> here. Report bugs and ask questions in
> [this repository's issues](https://github.com/Redwood-Labs-US/innerva-client-typescript/issues)
> or at support@innerva.net.

- API reference: <https://innerva.net/docs/api>
- OpenAPI contract: <https://innerva.net/openapi.yaml> (every deployment serves
  its own at `/openapi.yaml`)

## Install

Until the package is on npm, install a release tag from this repository (npm
builds it on install):

```sh
npm install "github:Redwood-Labs-US/innerva-client-typescript#v0.1.0"
```

Or fetch it from a running Innerva server (the served artifact always matches
the deployed protocol version):

```sh
curl -fO https://innerva.net/sdk/typescript.tar.gz
tar -xzf typescript.tar.gz
cd innerva-typescript && npm install && npm run build
```

## Usage

```ts
import { createClient, loadOrCreateProofKey } from "@innerva/client";

const client = await createClient({
  baseUrl: "https://innerva.net",
  key: await loadOrCreateProofKey("/var/lib/myapp/innerva-proof-key.json"),
  displayName: "My App",
  displayUri: "https://myapp.example",
  callbackUri: "https://myapp.example/innerva/callback",
});

// 1. Request access and send the customer to the interaction page.
const pending = await client.createAccess({ suggestedCredits: 1000 });
redirectCustomerTo(pending.interactionUri);

// 2. On the callback, validate the binding and obtain a capability.
const capability = await client.continueAccess(pending, interactRef, callbackHash);

// 3. Run inference and branch on the typed, discriminated outcome.
const outcome = await client.infer(capability, "Hello!", { maxOutputTokens: 256 });
switch (outcome.kind) {
  case "completed":
    console.log(outcome.output, "charged:", outcome.credits.charged);
    break;
  case "incomplete":
    if (outcome.producedNoOutput) {
      // Completed upstream with no visible output — charged 0.
      // Retrying is a new operation and a new charge.
    } else {
      console.log("partial (capped:", outcome.credits.capped, "):", outcome.output);
    }
    break;
}
```

`client.inferStream(...)` is an async generator yielding typed events
(`started`, `delta`, then a terminal outcome) for incremental display.

## Retry semantics

The SDK generates an idempotency key per logical operation and reuses it
across automatic retries (exponential backoff with jitter). Only pre-stream
failures are retried: network errors, 5xx before the stream opened, and 429
(honoring `Retry-After`). Streamed content is never retained server-side, so:

- a replayed operation surfaces as a typed `InferenceAlreadyStartedError`
  (HTTP 409) and is never retried automatically;
- any failure after `response.created` throws a typed `StreamError` subclass
  carrying the operation id and the partial output — retrying is a new
  operation, a new key, and a new charge, and is your decision.

## Tests

```sh
npm install && npm test
```

The signing tests run against the shared conformance vectors in
`conformance/vectors`, generated from the server's reference implementation.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
