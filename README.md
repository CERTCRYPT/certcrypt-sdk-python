# CERTCRYPT SDK for Python

Official Python SDK for integrating with CERTCRYPT infrastructure to produce certification artifacts that can reach `Independent`.

CERTCRYPT is infrastructure that makes certification independently verifiable under public rules. Selected artifacts can reach `Independent` through `Proof of Independence`, a structural result, so later verification no longer depends on the issuer's live systems.

The issuer remains responsible for issuing the base certificate and controlling the original material. CERTCRYPT does not validate semantic truth, does not decide whether document content is true, and does not custody the original material.

> [!NOTE]
> **The SDK API is stable at 1.0.**
>
> The public surface follows semantic versioning from 1.0.0 on, so anything that breaks it requires a major release.

## Install

```sh
pip install certcrypt-sdk
```

Requires Python 3.10 or newer.

**You will need credentials to issue.** The SDK signs client-side, but an issuer's
key-set root has to be authorized before anything it emits can reach `Independent`.
Get yours at **[console.certcrypt.com](https://console.certcrypt.com)**.

## Core idea

Most digital certificates, records, messages, and decisions remain dependent on the systems that issued them.

That dependency is fragile over time. Systems are migrated, providers change, databases are archived, credentials expire, and institutions reorganize.

CERTCRYPT addresses this by allowing selected certification artifacts to reach `Independent`: a state in which later verification can be evaluated under public rules without relying on the issuer as a live system.

## SDK scope

This repository hosts the issuer-side SDK. It helps issuer systems:

- integrate with CERTCRYPT infrastructure
- produce certification artifacts at issuance
- support selected artifacts reaching `Independent`
- preserve separation between issuer emission and later independent verification

The SDK does not replace the issuer's own certificate issuance logic and does not make claims about the truth, legal validity, or factual correctness of the underlying content.

### The signing key stays with the issuer

The issuer signs its own certificates, client-side, with a key derived from a seed it
holds. CERTCRYPT never receives that seed and never signs on an issuer's behalf.

That has a direct consequence for where this SDK runs: it is **server-side only**.
The issuer seed must never reach a client device or a browser — anyone who obtains
it can issue as that issuer.

### The node is a transport

Your issuance goes through a CERTCRYPT node. The SDK activates through it and
hands it your submissions, and asks it for nothing else: no identity proof, no
pinned key, nothing to configure about which node you use.

That is safe because nothing the node relays is taken on its word. The node
cannot forge a certificate — you sign it here, with a key CERTCRYPT never sees —
and what comes back, the `Proof of Independence`, is signed by the CERTCRYPT
System Domain. Whether a node may submit at all is decided by the CERTCRYPT
service, which admits submissions only from nodes whose operator it recognizes.
A node that misbehaves can delay or drop a submission; it cannot alter or invent
what is signed. A dropped submission shows up as an emission that stays pending
past its expected settlement window, which `resolve_emission()` reports as
overdue.

This SDK does not verify the `Proof of Independence` itself. Any verifier checks
it offline with the verifier toolkit, and the proof also records which node
carried the submission.

## Usage

Configuration values come from whoever operates the system domain you issue under.
Keep the keyset seed in a secret manager: it is the issuer's identity, and
everything the SDK signs derives from it.

`rules_version` carries one value the SDK has to know: the commitment TTL, which
is a public rule of the domain rather than an issuer setting — a verifier
requires `expires_at == issued_at + ttl`. The SDK knows the TTL for the published
rules domains and refuses any other at construction, rather than inventing an
expiry that every conformant verifier would reject. A deployment that runs under
its own rules domain registers it with `register_rules_domain("rules/...")`
before constructing `Certcrypt`, and passes `commitment_ttl_seconds` with that
domain's value. Registering asserts that the domain forms artifacts exactly as a
published one does; an unregistered domain is still refused.

```python
import os
from certcrypt import Certcrypt, SubjectInput

certcrypt = Certcrypt(
    node_base_url=os.environ["CERTCRYPT_NODE_BASE_URL"],
    keyset_seed=os.environ["CERTCRYPT_ISSUER_KEYSET_SEED"],
    integration_key=os.environ["CERTCRYPT_ISSUER_INTEGRATION_KEY"],
    rules_version=os.environ["CERTCRYPT_RULES_VERSION"],
    system_id=os.environ["CERTCRYPT_SYSTEM_ID"],
    system_root_fingerprint=os.environ["CERTCRYPT_SYSTEM_ROOT_FINGERPRINT"],
)

# Certify the material itself. The SDK derives the signing key from the seed,
# mints a signed base certificate, and anchors it toward `Independent`.
with open("invoice-2026-0041.pdf", "rb") as fh:
    material = fh.read()

result = certcrypt.issue(
    subjects=[SubjectInput("subject.binary/1", material)],
)

# Persist the handle — it identifies the operation and lets you finish the job later, even
# after a restart, without re-emitting.
save_somewhere(result.handle.to_dict())

# Later: assemble the package a third party can verify offline, without contacting
# you. Settlement is not instantaneous, so this reports where the emission is —
# `pending` means retry later, never that anything is wrong.
resolution = certcrypt.resolve_emission(result.handle)

if resolution.state == "independent":
    save_somewhere(resolution.verification_package)
elif resolution.state == "pending":
    pass  # not settled yet; the handle stays valid
else:
    pass  # "rejected" or "expired" — terminal, and resolution.node_state says why
```

### The authorization your issuer needs

Before an issuer can emit, its **operation-key root must be authorized by a system
domain**. That authorization is a binding the domain signs over your key-set root,
and it is what a verifier ultimately checks: everything you sign derives its
authority from it.

How you obtain it is not fixed by the protocol. The SDK supports both shapes:

- **You already hold a binding** — pass it as `signed_level1`, together with the
  `holder_id` and `pool_id` it was issued against.
- **The domain issues one automatically** — pass an `integration_key` and the SDK
  redeems it on first use.

With an integration key, `keyset_seed` and `integration_key` are two halves of one
boot credential: provision both from config on every start and keep them. To
redeem, the SDK sends the key together with your key-set root, one leaf of that
key set with its inclusion proof, and that leaf's signature over the key and the
root. The node that relays the request cannot swap in a root of its own, because it
cannot sign for it. The key is "one-time" only in that its first use binds it to
that root. Presenting it again with the same root is an idempotent replay
(`already_consumed_same_root`) answered with the same binding, which is what makes
a cold restart work with nothing persisted. Presenting it with a different root is
refused.

The binding's validity starts when the issuance service grants it: the activation
instant, never before the system-domain key that signs it. A replay answers with
the authorization bound at first activation, so a restart reuses it. It ends at
2100-01-01 unless you pass `valid_until` (RFC 3339, whole seconds).

Two refusals carry a code on `CertcryptNodeError.code` and are never worth
retrying: `integration_key_replaced` means a newer key was issued for this
integration, so configure the latest one. `key_set_root_already_bound` means this
seed is already bound to another integration, and each integration needs its own
seed.

The first `issue()` redeems on the way past, so most integrations call nothing
explicitly. `activate()` exists for when the deploy and the first real certificate
are far apart, because the integration key's expiry window only covers the FIRST
activation.

Pass a `binding_store` to cache the binding across restarts. It is a cache:
omitting it, or having it fail, costs one extra request and never correctness —
the key-set root is re-derived from the seed, so re-presenting the same
integration key is an idempotent replay.

### Waiting for settlement

`pending` is the normal state of a fresh emission, not a problem: the operation is
waiting to be settled, and settlement batches many operations into one window.

`resolve_emission()` does a single status check by default — a reconciler wants a
quick "is it ready yet?", not a long block. Pass `max_wait_ms` to wait inline. The
wait is window-aware: when the node reports a settlement window, the client sleeps
until that window rather than polling blindly, and reports progress so a
multi-minute wait is distinguishable from a hang.

The window (`SettlementWindowEstimate`, on `pending.settlement_window` and on each
`WaitProgress.window`) carries `target_close_by`, the instant the window is expected
to close, and `expected_settled_by`, the operator's estimate of when that window's
settlement is anchored and final so that a read can return a terminal state. The
second is never earlier than the first and is present exactly when it is; both are
operational estimates, not deadlines and not a promise of when the operation
becomes Independent. The client checks twice before calling the operation overdue:
once 60 % of the way from `target_close_by` to `expected_settled_by`, where most
settlements have already landed, and once at `expected_settled_by` plus one second
for clock skew; each check is pushed back by a random 0–1 s so that the operations of
one window do not all ask at the same instant. `overdue` is true only once
`expected_settled_by` has passed with the operation still not terminal. When the node
reports only `target_close_by`, the client checks at it plus three seconds and
`overdue` follows it. The package records this
instance's `rules_version` and `system_id`; pass `verification_context` only to
record something else.

The wait options, accepted by `resolve_emission()` and `wait_for_operation()`:

| option | meaning |
| --- | --- |
| `max_wait_ms` | wall-clock bound on the whole wait. Under `"auto"` it defaults to 15 minutes; `"fixed"` waits indefinitely unless you set it |
| `strategy` | `"auto"` (default): use the window estimate, else backoff. `"fixed"`: poll every `interval_ms` |
| `backoff_base_ms` / `backoff_cap_ms` | backoff shape when there is no estimate (defaults 1 s / 30 s) |
| `on_progress` | called before each sleep with a `WaitProgress`: a ready-to-log `message`, plus `attempt`, `node_state`, `next_check_in_ms`, `elapsed_ms`, `overdue`, and — when the node reports them — `window` and `settlement` |
| `interval_ms` / `max_attempts` | fixed-interval polling: a poll every `interval_ms` (default 1 s), at most `max_attempts` polls (default 60) |

Passing `interval_ms` or `max_attempts` selects `"fixed"` unless you also pass
`strategy`. Without `on_progress`, a sleep of ten seconds or more, or an overdue
window, is logged at INFO on the `certcrypt` logger with the same message. An
exception raised by `on_progress` is swallowed: reporting never breaks the wait.

When the wait ends without a terminal state, `wait_for_operation()` raises
`CertcryptNodeError` saying the operation "did not reach a terminal state", with the
last state it saw. `resolve_emission()` does not raise for that: it reports
`pending`, because the handle is still good.

### Timeouts and retries

Every request to the node is bounded at 30 seconds. A submit and every read
(`get_operation`, `get_emission_by_commitment`, `list_unresolved_emissions`,
`list_dead_letters`) are retried under the transport-retry policy: a
connection that fails or times out, and a 408, 425, 429 or 5xx, are retried until
the time budget runs out, and a `Retry-After` on 503 or 429 is waited out without
counting as an attempt. A submit keeps the same `request_id` on every attempt, so a
2xx answer whose body is not JSON is retried safely too. Tune it on `Certcrypt`:

| option | meaning |
| --- | --- |
| `retry_max_elapsed_ms` | total time budget from the first attempt (default 120 s) |
| `retry_max_attempts` | counted attempts, the first included (default: no limit; 1 disables retry) |
| `retry_base_ms` / `retry_cap_ms` | backoff shape: attempt n waits a random draw under `base × 2^(n−1)`, capped at `cap` (defaults 200 ms / 30 s) |

`health()` is one request, never retried, and reports `False` rather than raising
when the node does not answer.

### Certifying a multi-subject certificate

A certificate commits to an ORDERED set of subjects under one signature — an
assertion plus its PDF, say. Order is significant, and `subjects[0]` is the
primary face.

```python
result = certcrypt.issue(
    subjects=[
        SubjectInput("subject.text/1", assertion.encode("utf-8")),
        SubjectInput("subject.binary/1", pdf_bytes),
    ],
)
```

### Handing out one element of a collection

A `subject.collection/1` commits to many elements under one certificate. Declare it
by its ordered leaves and the SDK builds the descriptor, salted with the
certificate's own nonce:

```python
from certcrypt import CollectionLeafInput, SubjectInput

result = certcrypt.issue(
    subjects=[
        SubjectInput(
            "subject.collection/1",
            leaves=[
                CollectionLeafInput("subject.binary/1", first),
                CollectionLeafInput("subject.text/1", second),
            ],
        )
    ],
)

# The same descriptor and leaf hashes travel signed inside the base certificate,
# which CERTCRYPT never receives: keep this or the certificate. Lose both and
# they cannot be recomputed without the complete ordered leaf set and the
# certificate nonce.
save_somewhere(result.collections)
```

## Building from source

```sh
pip install -e ".[dev]"
python -m pytest tests -q
```

The test suite validates against the published conformance vectors, which are not
vendored here: check out
[`certcrypt-conformance`](https://github.com/CERTCRYPT/certcrypt-conformance) as a
sibling of this repository. Tests that need it fail with a message naming what to
check out (see below for the opt-out).

This SDK is not a verifier and returns no `VerifierResult`, so the verdict
fixtures do not apply to it; what it must reproduce is the bytes, identically to
every other implementation. State the version you ran against when you claim
parity — the value in the suite's `VERSION` at that time. The contract is
versioned independently of this package.

The ECDSA P-256 half of every signature is part of those bytes: it is RFC 6979
deterministic (conformance family `ecdsa-p256-deterministic`), so the same key
over the same message always gives the same signature. The ML-DSA-65 half is
hedged, so it differs between runs; both halves verify either way.

Some tests additionally round-trip what this SDK mints through
[`certcrypt-verifier-toolkit-js`](https://github.com/CERTCRYPT/certcrypt-verifier-toolkit-js),
which verifies every signature — the assertion that makes the language bindings siblings rather
than lookalikes. They need Node and a built toolkit sibling, and fail otherwise.

**A missing sibling is a failure, by default.** A skipped test reports no
failure, so if the tests that need a sibling skipped when it was absent, `passed`
could describe a run that never checked parity — including both round-trips
through the verifier. Nothing needs to be switched on: `pytest` without a sibling
fails, naming the path it looked for. Making rigor opt-in gets it backward — whoever forgets the flag is
precisely whoever needed it.

```sh
git clone https://github.com/CERTCRYPT/certcrypt-conformance.git ../certcrypt-conformance
python -m pytest tests -q
```

Two escape hatches, both deliberate and neither a default:

| Variable | Effect |
| --- | --- |
| `CERTCRYPT_ALLOW_MISSING_CONFORMANCE=1` | Go back to skipping. For working on this repo alone, knowing the parity half did not run |
| `CERTCRYPT_ALLOW_CONFORMANCE_VERSION_MISMATCH=1` | Run against a contract version this SDK does not claim, to see what a bump would break |

**The contract VERSION is checked too.** Requiring it to be present is not
enough: two implementations can each build green against a different version and
diverge anyway. This SDK is held to `EXPECTED_CONTRACT_VERSION`
(`tests/test_conformance_contract.py`), and a checkout that is not that one
fails that test — an ordinary failure, reported the same way the other implementations
report it. Adopting a new contract means raising the constant and
re-running.

## CERTCRYPT boundary

- not a claim of factual truth
- not a validator of correctness
- not a custodian of documents
- not blockchain notarization
- not a trust badge

## Boundary of this SDK

- not a replacement for the issuer's own certificate issuance logic
- not a verifier
- not a source of proof validity
- not a document custody library
- not a semantic validator of legal or factual claims

### Trademarks

The Apache-2.0 grant covers copyright, not marks: §6 of the license grants no
permission to use CERTCRYPT trade names, trademarks, service marks or product
names beyond describing the origin of the work.

Stating that your product issues CERTCRYPT certificates, or that it is built on
this SDK, is such a use. Naming your product after CERTCRYPT is not.

The distinction matters more here than in a library that only reads: what this
SDK emits is signed under **your** issuer identity, not CERTCRYPT's. A
certificate minted with it is your act — CERTCRYPT does not review, approve or
countersign it, and presenting one as CERTCRYPT having certified the underlying
material misstates what the artifact says. What the certificate carries is a
commitment that anyone can verify against the public rules, which is the whole
point and is stronger than a badge.

## Documentation

Technical documentation and the public specifications are published at
[docs.certcrypt.com](https://docs.certcrypt.com): the model, the terminology, the
claims boundary, the evaluation model a verifier applies, and the normative
specifications the artifacts in this SDK conform to.

## Links

| Surface | Address |
| --- | --- |
| Website | [certcrypt.com](https://certcrypt.com) |
| Documentation | [docs.certcrypt.com](https://docs.certcrypt.com) |
| Verify an artifact | [verify.certcrypt.dev](https://verify.certcrypt.dev) |
| Blog | [blog.certcrypt.com](https://blog.certcrypt.com) |
| Support | [support.certcrypt.com](https://support.certcrypt.com) |
| Service status | [status.certcrypt.com](https://status.certcrypt.com) |
| Open source | opensource@certcrypt.com |
| Security | security@certcrypt.com — see [`SECURITY.md`](SECURITY.md) |

**The two repositories on the other side of what this SDK emits:**

| Repository | Relationship |
| --- | --- |
| [certcrypt-verifier-toolkit-js](https://github.com/CERTCRYPT/certcrypt-verifier-toolkit-js) | the verifier that evaluates what this SDK mints — this SDK's own suite round-trips its certificates through it |
| [certcrypt-conformance](https://github.com/CERTCRYPT/certcrypt-conformance) | the public contract both sides are held to; this SDK checks byte parity against its primitive vectors |

Emission and verification are deliberately separate, and the contract in the
middle is data rather than code. That is what makes a certificate this SDK mints
checkable by someone who has neither your systems nor this SDK — which is the
property the whole design exists to produce.

## Changelog

Release notes are in [`CHANGELOG.md`](CHANGELOG.md). From 1.0.0 this package
follows semantic versioning: breaking a documented export requires a major
release. Deliberately outside that promise, because it is not API: which verdict a
given artifact receives. A check may be tightened in a minor or a patch, and an
artifact that verified before may then fail — that is a corrected verdict, and the
entry says so.

## License

Copyright 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.
