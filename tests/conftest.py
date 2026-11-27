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

"""Turning sibling-checkout skips into failures where a green run is evidence.

Most tests here are self-contained. The ones that matter most are not: byte
parity against the published conformance vectors, and the round-trip that hands
an SDK-minted certificate to `certcrypt-verifier-toolkit-js` and requires it to
verify. Checking parity against a vector means having the vector.

Those tests are guarded with `pytest.mark.skipif`, and this hook turns such a
skip into a FAILURE. That is the default, and the default is the point: a
skipped test reports no failure, so a run without the vectors ends in `passed`
having never checked parity at all — the one property these tests exist to
prove. Requiring the operator to opt INTO rigor gets it exactly backward,
because whoever forgets the flag is precisely whoever needed it.

Set `CERTCRYPT_ALLOW_MISSING_CONFORMANCE=1` to go back to skipping. It is for a
contributor working on this repo alone who knows the parity half did not run;
it is never for CI, and never for a release check.

## The contract VERSION is checked too

Requiring the contract to be PRESENT is not enough. Two implementations can each
build green against a DIFFERENT version of it and diverge anyway; what keeps
them in step is agreeing on the same `VERSION`. So a checkout whose VERSION is
not `EXPECTED_CONTRACT_VERSION` (`tests/test_conformance_contract.py`) fails,
and raising that constant is the deliberate act of adopting a new contract.

That mismatch surfaces as a FAILING TEST, like every other contract failure —
not as a pytest usage error that aborts collection. Aborting would be defensible
(a wrong contract invalidates every parity assertion at once) but it reads as
"you invoked pytest wrong" rather than "this SDK and the contract disagree", and
it would make this binding fail differently from the others held to the same
contract.
"""

import os

import pytest

#: Substrings identifying a skip caused by an absent sibling checkout, as opposed
#: to a legitimate skip (an unavailable optional backend, a platform guard).
#: Each sibling guard in this suite phrases its reason with one of them.
_SIBLING_SKIP_MARKERS = (
    "conformance vectors not found",
    "cross-binding check needs Node",
)


#: Opt OUT of requiring the contract. Absent, a missing sibling is a failure.
_ENV_ALLOW_MISSING = "CERTCRYPT_ALLOW_MISSING_CONFORMANCE"


def _requires_siblings() -> bool:
    """Missing siblings fail unless someone explicitly said otherwise."""
    return os.environ.get(_ENV_ALLOW_MISSING) != "1"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Fail, rather than skip, when a sibling checkout is missing, unless opted out.

    Rewriting the report instead of the marks keeps the guards themselves as the
    single source of truth for WHICH tests need a sibling: this hook only decides
    what an absent one means. A skip for any other reason passes through
    untouched.
    """
    outcome = yield
    if not _requires_siblings():
        return
    report = outcome.get_result()
    if report.skipped and isinstance(report.longrepr, tuple):
        _path, _lineno, reason = report.longrepr
        if any(marker in reason for marker in _SIBLING_SKIP_MARKERS):
            report.outcome = "failed"
            # pytest prefixes the reason with "Skipped: "; strip it, since this
            # report is no longer a skip.
            detail = reason.removeprefix("Skipped: ")
            report.longrepr = (
                "the conformance contract is required, so this cannot be skipped: "
                f"{detail}\nSet {_ENV_ALLOW_MISSING}=1 to acknowledge running "
                "without it."
            )
