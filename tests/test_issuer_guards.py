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

"""The guards an issuer meets before anything is signed: what construction
refuses, the order `prepare()` checks things in, and what counts as "not given"
for an optional value — an absent one falls back, an explicit one is used as
given, including 0 and the empty string.
"""

import pytest

from certcrypt import Certcrypt, HolderKeySet, InMemoryLeafStore, SubjectInput

_SEED = "22" * 32
_RULES = "rules/conformance"
_ROOT_FP = "ab" * 32
_KEY_SET_ROOT = HolderKeySet.from_master_seed(_SEED, 1).root


def _binding() -> dict:
    return {
        "level1_binding": {
            "system_id": "certcrypt",
            "rules_version": _RULES,
            "system_root_fingerprint": _ROOT_FP,
            "authorized_role": "issuer",
            "authorization_issuer_kid": "kid-l1",
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_until": "2099-01-01T00:00:00Z",
            "holder_key_set_root": _KEY_SET_ROOT,
        },
        "level1_signature": {
            "alg": "composite",
            "mode": "AND",
            "signatures": [{"alg": "ML-DSA-65", "sig_b64": "c2ln"}],
        },
    }


def _unreachable(*_args):
    raise AssertionError("no request should leave the process for a guard")


def _kwargs(**extra):
    kw = dict(
        node_base_url="http://node.test",
        keyset_seed=_SEED,
        rules_version=_RULES,
        system_root_fingerprint=_ROOT_FP,
        system_id="certcrypt",
        pool_id="pool-1",
        holder_id="holder-1",
        signed_level1=_binding(),
    )
    kw.update(extra)
    return kw


def _issuer(**extra):
    from certcrypt import CertcryptNodeClient

    kw = _kwargs(**extra)
    kw.setdefault("client", CertcryptNodeClient("http://node.test", transport=_unreachable))
    return Certcrypt(**kw)


_SUBJECTS = [SubjectInput("subject.text/1", b"hello\n")]


def _projected(prepared) -> dict:
    """The signed projected commitment the evidence carries."""
    return prepared.commitment.capacity_evidence["projected_commitment"]


# --- construction ---------------------------------------------------------------


def test_unlinkable_mode_refuses_a_tree_of_one_leaf_with_the_shared_message():
    with pytest.raises(ValueError) as excinfo:
        Certcrypt(**_kwargs(mode="unlinkable", tree_size=1, leaf_store=InMemoryLeafStore()))
    assert str(excinfo.value) == "unlinkable mode needs a treeSize >= 2 (a distinct leaf per cert)"


def test_unlinkable_mode_refuses_construction_without_a_leaf_store_naming_it():
    with pytest.raises(
        ValueError,
        match="requires a leaf_store: each commitment must be signed with a leaf never used before",
    ):
        Certcrypt(**_kwargs(mode="unlinkable", tree_size=4))


@pytest.mark.parametrize("ttl", [0, -1, 1.5])
def test_a_commitment_ttl_that_is_not_positive_and_whole_is_refused_at_construction(ttl):
    with pytest.raises(ValueError, match="must be a positive whole number of seconds"):
        Certcrypt(**_kwargs(commitment_ttl_seconds=ttl))


def test_the_retry_options_set_on_certcrypt_reach_the_node_client_base_and_cap_included():
    issuer = Certcrypt(
        **_kwargs(
            retry_max_elapsed_ms=15_000,
            retry_max_attempts=3,
            retry_base_ms=50,
            retry_cap_ms=2_000,
        )
    )
    policy = issuer.client._retry_policy
    assert (
        policy.max_elapsed_ms,
        policy.max_attempts,
        policy.backoff_base_ms,
        policy.backoff_cap_ms,
    ) == (15_000, 3, 50, 2_000)


# --- the order prepare() checks things in ----------------------------------------


def test_prepare_checks_the_pool_before_anything_about_the_input():
    with pytest.raises(ValueError, match="^no pool_id"):
        _issuer(pool_id=None).prepare(subjects=[])


def test_prepare_checks_the_holder_before_the_system_configuration():
    with pytest.raises(ValueError, match="^no holder_id"):
        _issuer(holder_id=None, system_id="").prepare(subjects=[])


def test_prepare_checks_the_system_id_before_the_subjects():
    with pytest.raises(ValueError, match="requires system_id"):
        _issuer(system_id="").prepare(subjects=[])


# --- absent falls back, explicit is used as given --------------------------------


def test_an_explicit_declared_effective_units_of_0_is_used_as_given():
    prepared = _issuer().prepare(subjects=_SUBJECTS, declared_effective_units="0")
    assert _projected(prepared)["declared_effective_units"] == "0"


def test_an_explicit_empty_declared_effective_units_is_used_as_given_not_replaced():
    prepared = _issuer().prepare(subjects=_SUBJECTS, declared_effective_units="")
    assert _projected(prepared)["declared_effective_units"] == ""


def test_an_absent_declared_effective_units_is_the_subjects_sum():
    prepared = _issuer().prepare(subjects=_SUBJECTS + _SUBJECTS)
    assert _projected(prepared)["declared_effective_units"] == "2"


def test_an_explicit_empty_issued_at_is_refused_not_replaced_by_the_clock():
    with pytest.raises(Exception):
        _issuer().prepare(subjects=_SUBJECTS, issued_at="")


def test_an_explicit_issued_at_and_the_ttl_fix_expires_at():
    prepared = _issuer(commitment_ttl_seconds=60).prepare(
        subjects=_SUBJECTS, issued_at="2026-08-16T12:00:00Z"
    )
    p = _projected(prepared)
    assert (p["issued_at"], p["expires_at"]) == ("2026-08-16T12:00:00Z", "2026-08-16T12:01:00Z")
