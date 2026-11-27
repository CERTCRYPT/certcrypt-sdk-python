# Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The issuer's signing key, from its seed alone, against the contract.

Conformance family `issuer-key-derivation`. A divergence here produces
certificates that still verify, each carrying its own public keys, while one
seed signs under two identities. Nothing downstream notices, so the contract is
read here: the two public keys, the default key id per tree size, and the key
id being a label that never changes the key.
"""

import json
from pathlib import Path

import pytest

from certcrypt import Certcrypt, derive_issuer_key
from certcrypt.artifacts.holder_keyset import HolderKeySet

_VECTORS = (
    Path(__file__).resolve().parents[2]
    / "certcrypt-conformance"
    / "fixtures"
    / "primitives"
    / "issuer-key-derivation"
    / "vectors.json"
)

pytestmark = pytest.mark.skipif(
    not _VECTORS.exists(),
    reason=(
        "conformance vectors not found: check out certcrypt-conformance as a "
        f"sibling of this repository (looked for {_VECTORS})"
    ),
)


def _doc() -> dict:
    return json.loads(_VECTORS.read_text("utf-8"))


def _vectors() -> list:
    return _doc()["vectors"] if _VECTORS.exists() else []


def _key_id_cases() -> list:
    return _doc()["key_id_cases"] if _VECTORS.exists() else []


def test_profile_is_the_one_this_sdk_implements():
    assert _doc()["profile"] == "issuer-key-derivation/1"


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["name"])
def test_seed_derives_the_contract_keys(vector):
    key = derive_issuer_key(vector["master_seed_hex"], "any-label")
    assert key.pub_p256_b64 == vector["expected_pub_p256_b64"]
    assert key.pub_mldsa_b64 == vector["expected_pub_mldsa_b64"]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["name"])
def test_default_key_id_is_issuer_plus_root_prefix(vector):
    root = HolderKeySet.from_master_seed(
        vector["master_seed_hex"], vector["tree_size"]
    ).root
    assert root == vector["expected_holder_key_set_root"]

    issuer = Certcrypt(
        node_base_url="http://node.invalid",
        keyset_seed=vector["master_seed_hex"],
        rules_version="rules/conformance",
        system_id="certcrypt",
        system_root_fingerprint="aa" * 32,
        tree_size=vector["tree_size"],
    )
    # What issue() signs under when no id is configured.
    assert issuer._issuer_key.id == vector["expected_default_key_id"]
    assert issuer._issuer_key.pub_p256_b64 == vector["expected_pub_p256_b64"]
    assert issuer._issuer_key.pub_mldsa_b64 == vector["expected_pub_mldsa_b64"]


@pytest.mark.parametrize("case", _key_id_cases(), ids=lambda c: c["name"])
def test_key_id_is_a_label_that_never_changes_the_key(case):
    key = derive_issuer_key(case["master_seed_hex"], case["issuer_key_id"])
    assert key.id == case["issuer_key_id"]
    assert key.pub_p256_b64 == case["expected_pub_p256_b64"]
    assert key.pub_mldsa_b64 == case["expected_pub_mldsa_b64"]

    # The same holds through the issuer's own configuration path.
    issuer = Certcrypt(
        node_base_url="http://node.invalid",
        keyset_seed=case["master_seed_hex"],
        rules_version="rules/conformance",
        system_id="certcrypt",
        system_root_fingerprint="aa" * 32,
        issuer_key_id=case["issuer_key_id"],
    )
    assert issuer._issuer_key.id == case["issuer_key_id"]
    assert issuer._issuer_key.pub_p256_b64 == case["expected_pub_p256_b64"]
    assert issuer._issuer_key.pub_mldsa_b64 == case["expected_pub_mldsa_b64"]
