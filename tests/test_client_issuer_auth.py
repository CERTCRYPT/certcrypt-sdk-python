"""The issuer proof to a node is bound to its request, and fresh per attempt.

Twin of certcrypt-sdk-js `client.issuer-auth.test.ts`.
"""

from certcrypt.client import CertcryptNodeClient, issuer_auth_message
from certcrypt.types import LooseCommitment


# The same vector is asserted by certcrypt-node (auth.rs) and certcrypt-sdk-js:
# three implementations, one message.
def test_the_issuer_proof_message_matches_the_shared_vector():
    assert issuer_auth_message(
        "1700000000000.abc", "post", "http://127.0.0.1:4041/v1/issue", b"{}"
    ) == (
        "certcrypt:issuer-auth:1|1700000000000.abc|127.0.0.1:4041|POST /v1/issue|"
        "840eb7aa2a9935de63366bacbe9d97e978a859e93dc792a0334de60ed52f8e99"
    )
    # A default port is not part of the host; the query is part of the path.
    assert issuer_auth_message(
        "1.x", "GET", "https://node.example/v1/emissions/unresolved?since=0"
    ) == (
        "certcrypt:issuer-auth:1|1.x|node.example|GET /v1/emissions/unresolved?since=0|"
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )
    assert issuer_auth_message("1.x", "GET", "https://node.example:443/v1/x").split("|")[2] == (
        "node.example"
    )


class _Recording:
    def __init__(self, statuses, body='{"dead":[]}'):
        self.statuses = list(statuses)
        self.body = body
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"headers": headers, "body": body})
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return status, (self.body if status == 200 else ""), {}


def _client(transport, asked):
    def proof(method, url, body):
        asked.append((method, url, body))
        return f"proof-{len(asked)}"

    return CertcryptNodeClient(
        "http://node.test",
        transport=transport,
        retry_base_ms=0,
        retry_cap_ms=0,
        now_ms=lambda: 0,
        sleep=lambda s: None,
        issuer_auth_proof=proof,
    )


# The node accepts a challenge once: a retry that resent the first attempt's
# header would be refused as a replay once that attempt had reached the node.
def test_a_retried_read_carries_a_fresh_proof_for_that_request_on_every_attempt():
    transport, asked = _Recording([503, 503, 200]), []
    _client(transport, asked).list_dead_letters()
    assert [c["headers"]["x-certcrypt-issuer-auth"] for c in transport.calls] == [
        "proof-1",
        "proof-2",
        "proof-3",
    ]
    assert all(a == ("GET", "http://node.test/v1/outbox/dead", b"") for a in asked)


def test_a_submit_binds_its_proof_to_the_exact_body_it_sends():
    transport = _Recording(
        [200],
        body='{"request_id":"r","results":[{"operation_id":"op-1","commitment_index":0,'
        '"state":{"state":"accepted"}}]}',
    )
    asked = []
    _client(transport, asked).issue(
        [
            LooseCommitment(
                capacity_evidence={"profile": "zero-data.unlinkable"},
                operative={"holder_id": "h", "pool_id": "p"},
            )
        ]
    )
    assert len(asked) == 1
    method, url, body = asked[0]
    assert (method, url) == ("POST", "http://node.test/v1/issue")
    assert body == transport.calls[0]["body"], "the proof covers the bytes on the wire"
