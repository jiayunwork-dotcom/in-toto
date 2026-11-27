#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Compact terminal demonstration for the reusable verification cache.

Run from the repository root:

    python3 demo/verification_cache_demo.py

The exhaustive requirement coverage lives in
``tests/test_verification_cache.py``; this script prints the important runtime
metrics and exercises the main user-visible scenarios.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from in_toto.cache import VerificationCache  # noqa: E402
from in_toto.exceptions import ThresholdVerificationError  # noqa: E402
from in_toto.models.layout import Layout  # noqa: E402
from in_toto.models.metadata import Metablock  # noqa: E402
from in_toto.verifylib import in_toto_verify  # noqa: E402

# The repository's tests/pems helper loads the same keys used by the tests.
from tests.common import SignerStore  # noqa: E402
from tests.test_verification_cache import (  # noqa: E402
    TestTwoIndependentBranches,
    write_signed,
)


def line(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main():
    case = TestTwoIndependentBranches(
        "test_cold_hot_parity_and_zero_hot_crypto_and_search"
    )
    case.setUp()
    try:
        case.build_fixture()
        cache = VerificationCache(max_entries=16)

        line("1. Two independent sublayout branches: cold then hot")
        cold = case.verify(cache=cache)
        counts, signature_patch, solve_patch = case.patch_calls()
        signature_patch.start()
        solve_patch.start()
        hot = case.verify(cache=cache)
        signature_patch.stop()
        solve_patch.stop()
        print("summary products :", sorted(hot.products))
        print("hot verify_signature calls :", counts["signature"])
        print("hot grouped solver calls   :", counts["solve"])
        print("cache stats               :", cache.stats())
        assert cold.to_dict() == hot.to_dict()
        assert counts == {"signature": 0, "solve": 0}

        line("2. Same filename/length/mtime content replacement in branch A")
        original = open(case.a_link_path, "rb").read()
        stat = os.stat(case.a_link_path)
        old_digest = case.a_product["a.out"]["sha256"].encode()
        tampered = original.replace(old_digest, b"9" * 64)
        assert len(tampered) == len(original)
        with open(case.a_link_path, "wb") as handle:
            handle.write(tampered)
        os.utime(
            case.a_link_path,
            ns=(stat.st_atime_ns, stat.st_mtime_ns),
        )

        counts, signature_patch, solve_patch = case.patch_calls()
        signature_patch.start()
        solve_patch.start()
        try:
            case.verify(cache=cache)
        except ThresholdVerificationError:
            print(
                "tampered branch correctly failed with ThresholdVerificationError"
            )
        else:
            raise AssertionError("tampered evidence unexpectedly passed")
        finally:
            signature_patch.stop()
            solve_patch.stop()
        print(
            "actual low-level signature calls during miss:", counts["signature"]
        )
        print("solver calls after threshold failure        :", counts["solve"])

        with open(case.a_link_path, "wb") as handle:
            handle.write(original)
        os.utime(
            case.a_link_path,
            ns=(stat.st_atime_ns, stat.st_mtime_ns),
        )
        counts, signature_patch, solve_patch = case.patch_calls()
        signature_patch.start()
        solve_patch.start()
        restored = case.verify(cache=cache)
        signature_patch.stop()
        solve_patch.stop()
        print("restored summary products:", sorted(restored.products))
        print("restore hot signature/solver calls:", counts)
        assert counts == {"signature": 0, "solve": 0}

        line("3. LRU cap and clear")
        small = VerificationCache(max_entries=2)
        old_cwd = os.getcwd()
        cap_dir = tempfile.mkdtemp(prefix="in-toto-cache-demo-cap-")
        os.chdir(cap_dir)
        try:
            keys = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}
            real_verify = Metablock.verify_signature
            actual = []

            def counting_verify(instance, key):
                actual.append(1)
                return real_verify(instance, key)

            versions = []
            for version in range(5):
                layout = Layout(readme=f"demo-evidence-{version}")
                write_signed(".", "root.layout", layout, SignerStore.rsa)
                with patch.object(
                    Metablock, "verify_signature", counting_verify
                ):
                    in_toto_verify(
                        Metablock.load("root.layout"),
                        keys,
                        persist_inspection_links=False,
                        cache=small,
                    )
                versions.append(Path("root.layout").read_bytes())
                assert len(small) <= 2

            before = len(actual)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load("root.layout"),
                    keys,
                    persist_inspection_links=False,
                    cache=small,
                )
            print("entries after five distinct evidence versions:", len(small))
            print(
                "latest revisit actual signature calls         :",
                len(actual) - before,
            )
            print(
                "cache stats                                  :", small.stats()
            )
            assert len(small) <= 2
            assert len(actual) == before  # latest layer + signature retained

            Path("root.layout").write_bytes(versions[0])
            before_old = len(actual)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load("root.layout"),
                    keys,
                    persist_inspection_links=False,
                    cache=small,
                )
            old_revisit_calls = len(actual) - before_old
            before_old_repeat = len(actual)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load("root.layout"),
                    keys,
                    persist_inspection_links=False,
                    cache=small,
                )
            old_repeat_calls = len(actual) - before_old_repeat
            print(
                "evicted oldest revisit signature calls      :",
                old_revisit_calls,
            )
            print(
                "second oldest revisit signature calls       :",
                old_repeat_calls,
            )
            assert old_revisit_calls > 0
            assert old_repeat_calls == 0

            small.clear()
            assert len(small) == 0
            before = len(actual)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load("root.layout"),
                    keys,
                    persist_inspection_links=False,
                    cache=small,
                )
            print("after clear, signature calls:", len(actual) - before)
            assert len(actual) > before
        finally:
            os.chdir(old_cwd)

        line("Demo passed")
        print(
            "Run `python3 -m pytest tests/test_verification_cache.py -v` "
            "for trust, clock, grouped-proof, inspection and isolation cases."
        )
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main()
