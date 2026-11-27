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

"""The conformance contract this SDK is held to must be the one checked out.

Having the contract is not enough. Two implementations can each build green
against a DIFFERENT version of it and diverge anyway; what keeps them in step is
agreeing on the same `VERSION`.

This is an ordinary test, so a mismatch reports as a failure like any other —
the same way the other implementations report it. The check lives here rather than
in `conftest.py`, because pytest does not collect tests from a conftest.
"""

import os
from pathlib import Path

#: The conformance contract version this repository is held to. Bump it together
#: with the checkout, never ahead of it: the value is a claim about what this code
#: has actually been run against.
EXPECTED_CONTRACT_VERSION = "1.0.0"

#: Opt out of the equality check while still requiring the contract, for the one
#: legitimate case: trying a newer suite before adopting it.
_ENV_ALLOW_VERSION_MISMATCH = "CERTCRYPT_ALLOW_CONFORMANCE_VERSION_MISMATCH"

#: The conformance checkout, as a sibling of this repository.
_CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "certcrypt-conformance"


def contract_version_error() -> str | None:
    """The mismatch message, or `None` when the contract version is acceptable.

    `None` also when the contract is ABSENT: that case belongs to the
    skip-to-failure hook in `conftest.py`, which can name the specific vector
    that was missing instead of reporting a vaguer version problem.
    """
    version_file = _CONTRACT_ROOT / "VERSION"
    if not version_file.is_file():
        return None
    found = version_file.read_text("utf-8").strip()
    if found == EXPECTED_CONTRACT_VERSION:
        return None
    if os.environ.get(_ENV_ALLOW_VERSION_MISMATCH) == "1":
        print(
            f"\nWARNING: conformance contract is {found}, this repo claims "
            f"{EXPECTED_CONTRACT_VERSION}, and {_ENV_ALLOW_VERSION_MISMATCH}=1 — "
            "this run does NOT back a conformance claim"
        )
        return None
    return (
        f"conformance contract version mismatch: the checkout is {found}, this repo is "
        f"held to {EXPECTED_CONTRACT_VERSION}. Two implementations that each build green "
        "against a different contract version have no agreement between them. Either "
        f"check out {EXPECTED_CONTRACT_VERSION}, or adopt {found} by raising "
        f"EXPECTED_CONTRACT_VERSION in tests/test_conformance_contract.py and re-running. "
        f"Set {_ENV_ALLOW_VERSION_MISMATCH}=1 to explore a bump without adopting it."
    )


def test_contract_version_matches():
    """Fail naming the disagreement when the checkout is not the claimed version.

    Asserted once, here, rather than inside every parity test: a version mismatch
    invalidates all of them at the same time, so one failure naming it is clearer
    than the same failure repeated across the suite.
    """
    problem = contract_version_error()
    assert problem is None, problem


def test_expected_version_is_pinned():
    """The claim itself must be a concrete version, never blank or a placeholder.

    Cheap, and it guards the thing the other test depends on: an empty or
    wildcard `EXPECTED_CONTRACT_VERSION` would make every checkout "match" and
    quietly retire the gate.
    """
    assert EXPECTED_CONTRACT_VERSION, "EXPECTED_CONTRACT_VERSION must not be empty"
    assert EXPECTED_CONTRACT_VERSION[0].isdigit(), (
        f"EXPECTED_CONTRACT_VERSION must be a version, got {EXPECTED_CONTRACT_VERSION!r}"
    )
