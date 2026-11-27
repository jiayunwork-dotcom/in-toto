#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0

"""Behavior tests for the reusable in-toto verification cache."""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from in_toto.cache import VerificationCache
from in_toto.exceptions import (
    BadReturnValueError,
    LayoutExpiredError,
    LinkNotFoundError,
    RuleVerificationError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.groupedthreshold import VerificationReport
from in_toto.models.layout import (
    THRESHOLD_MODE_GROUPED,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.verifylib import in_toto_verify, solve_grouped_threshold
from tests.common import SignerStore

PEMS = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pems")
SCRIPTS = os.path.join(os.path.dirname(os.path.realpath(__file__)), "scripts")
EXPIRY = "2030-01-01T00:00:00Z"
A_EXPIRY = "2028-01-01T00:00:00Z"


def h(char):
    return {"sha256": char * 64}


def write_link(directory, step_name, signer, pubkey, products, materials=None):
    link = Link(
        name=step_name,
        materials=materials or {},
        products=products or {},
    )
    metadata = Metablock(signed=link)
    metadata.create_signature(signer)
    filename = FILENAME_FORMAT.format(
        step_name=step_name, keyid=pubkey["keyid"]
    )
    path = os.path.join(directory, filename)
    metadata.dump(path)
    return path


def write_signed(directory, filename, payload, signer):
    metadata = Metablock(signed=payload)
    metadata.create_signature(signer)
    path = os.path.join(directory, filename)
    metadata.dump(path)
    return path, metadata


def summary_fingerprint(summary):
    return json.dumps(summary.to_dict(), sort_keys=True, separators=(",", ":"))


class TemporaryVerificationDir(unittest.TestCase):
    def setUp(self):
        self.old_cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp(prefix="in-toto-cache-test-")
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self.old_cwd)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class TwoBranchFixture(TemporaryVerificationDir):
    def build_fixture(self, a_expires=EXPIRY, with_parameter_rule=False):
        self.root_signer = SignerStore.rsa
        self.root_pub = SignerStore.rsa_pub
        self.a_signer = SignerStore.ecdsa
        self.a_pub = SignerStore.ecdsa_pub
        self.b_signer = SignerStore.ed25519
        self.b_pub = SignerStore.ed25519_pub

        self.a_dir = "branch-a." + self.a_pub["keyid"][:8]
        self.b_dir = "branch-b." + self.b_pub["keyid"][:8]
        os.mkdir(self.a_dir)
        os.mkdir(self.b_dir)

        self.a_product = {"a.out": h("1")}
        self.b_product = {"b.out": h("2")}
        self.a_link_path = write_link(
            self.a_dir,
            "a-build",
            self.a_signer,
            self.a_pub,
            self.a_product,
        )
        self.b_link_path = write_link(
            self.b_dir,
            "b-build",
            self.b_signer,
            self.b_pub,
            self.b_product,
        )

        a_layout = Layout(
            keys={self.a_pub["keyid"]: self.a_pub},
            steps=[
                Step(
                    name="a-build",
                    pubkeys=[self.a_pub["keyid"]],
                    threshold=1,
                )
            ],
            threshold_mode=THRESHOLD_MODE_GROUPED,
            expires=a_expires,
        )
        self.a_layout_path, _ = write_signed(
            ".",
            FILENAME_FORMAT.format(
                step_name="branch-a", keyid=self.a_pub["keyid"]
            ),
            a_layout,
            self.a_signer,
        )

        b_layout = Layout(
            keys={self.b_pub["keyid"]: self.b_pub},
            steps=[
                Step(
                    name="b-build",
                    pubkeys=[self.b_pub["keyid"]],
                    threshold=1,
                )
            ],
            threshold_mode=THRESHOLD_MODE_GROUPED,
            expires=EXPIRY,
        )
        self.b_layout_path, _ = write_signed(
            ".",
            FILENAME_FORMAT.format(
                step_name="branch-b", keyid=self.b_pub["keyid"]
            ),
            b_layout,
            self.b_signer,
        )

        b_rules = []
        if with_parameter_rule:
            b_rules = [
                ["REQUIRE", "{WANTED}"],
                ["ALLOW", "*"],
            ]

        self.root_layout = Layout(
            keys={
                self.a_pub["keyid"]: self.a_pub,
                self.b_pub["keyid"]: self.b_pub,
            },
            steps=[
                Step(
                    name="branch-a",
                    pubkeys=[self.a_pub["keyid"]],
                    threshold=1,
                ),
                Step(
                    name="branch-b",
                    pubkeys=[self.b_pub["keyid"]],
                    threshold=1,
                    expected_products=b_rules,
                ),
            ],
            threshold_mode=THRESHOLD_MODE_GROUPED,
            expires=EXPIRY,
        )
        self.root_path, self.root_metadata = write_signed(
            ".", "root.layout", self.root_layout, self.root_signer
        )
        self.root_keys = {self.root_pub["keyid"]: self.root_pub}
        self.original_root_bytes = open(self.root_path, "rb").read()

    def verify(self, cache=None, report=None, root_keys=None, params=None):
        metadata = Metablock.load(self.root_path)
        return in_toto_verify(
            metadata,
            root_keys or self.root_keys,
            link_dir_path=".",
            substitution_parameters=params,
            persist_inspection_links=False,
            verification_report=report,
            cache=cache,
        )

    def resign_root(self, mutator):
        layout = copy.deepcopy(self.root_layout)
        mutator(layout)
        write_signed(".", self.root_path, layout, self.root_signer)

    def restore_root(self):
        with open(self.root_path, "wb") as handle:
            handle.write(self.original_root_bytes)

    def patch_calls(self):
        real_verify = Metablock.verify_signature
        real_solve = solve_grouped_threshold
        counts = {"signature": 0, "solve": 0}

        def counting_verify(instance, key):
            counts["signature"] += 1
            return real_verify(instance, key)

        def counting_solve(*args, **kwargs):
            counts["solve"] += 1
            return real_solve(*args, **kwargs)

        signature_patch = patch.object(
            Metablock, "verify_signature", counting_verify
        )
        solve_patch = patch(
            "in_toto.verifylib.solve_grouped_threshold",
            side_effect=counting_solve,
        )
        return counts, signature_patch, solve_patch


class TestTwoIndependentBranches(TwoBranchFixture):
    def test_cold_hot_parity_and_zero_hot_crypto_and_search(self):
        self.build_fixture()

        disabled = in_toto_verify(
            Metablock.load(self.root_path),
            self.root_keys,
            persist_inspection_links=False,
        )

        cache = VerificationCache()
        cold_report = VerificationReport(THRESHOLD_MODE_GROUPED)
        cold = self.verify(cache=cache, report=cold_report)
        self.assertEqual(
            summary_fingerprint(cold), summary_fingerprint(disabled)
        )
        self.assertIsNotNone(cold_report.proof)

        counts, sig_patch, solve_patch = self.patch_calls()
        with sig_patch, solve_patch:
            hot_report = VerificationReport(THRESHOLD_MODE_GROUPED)
            hot = self.verify(cache=cache, report=hot_report)

        self.assertEqual(
            summary_fingerprint(hot), summary_fingerprint(disabled)
        )
        self.assertEqual(counts["signature"], 0)
        self.assertEqual(counts["solve"], 0)
        self.assertEqual(
            hot_report.to_dict()["proof"], cold_report.to_dict()["proof"]
        )

    def assert_cold_hot_exception_parity(self, expected_type, **kwargs):
        with self.assertRaises(expected_type):
            self.verify(cache=None, **kwargs)

        cache = VerificationCache()
        with self.assertRaises(expected_type):
            self.verify(cache=cache, **kwargs)
        with self.assertRaises(expected_type):
            self.verify(cache=cache, **kwargs)

    def test_failure_type_parity_for_bad_key_and_missing_link(self):
        self.build_fixture()

        self.assert_cold_hot_exception_parity(
            SignatureVerificationError,
            root_keys={self.b_pub["keyid"]: self.b_pub},
        )

        os.remove(self.a_link_path)
        self.assert_cold_hot_exception_parity(LinkNotFoundError)

    def test_content_tamper_same_size_and_mtime_rechecks_branch_ancestors(
        self,
    ):
        self.build_fixture()
        cache = VerificationCache()
        original = open(self.a_link_path, "rb").read()
        original_stat = os.stat(self.a_link_path)
        self.verify(cache=cache)

        old_digest = self.a_product["a.out"]["sha256"].encode()
        new_digest = b"9" * 64
        tampered = original.replace(old_digest, new_digest)
        self.assertEqual(len(tampered), len(original))
        with open(self.a_link_path, "wb") as handle:
            handle.write(tampered)
        os.utime(
            self.a_link_path,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        self.assertEqual(os.path.getsize(self.a_link_path), len(original))

        meta_count = 0
        threshold_count = 0

        def count_meta(*args, **kwargs):
            nonlocal meta_count
            meta_count += 1
            return original_meta(*args, **kwargs)

        def count_threshold(*args, **kwargs):
            nonlocal threshold_count
            threshold_count += 1
            return original_threshold(*args, **kwargs)

        import in_toto.verifylib as verifylib

        original_meta = verifylib.verify_metadata_signatures
        original_threshold = verifylib.verify_link_signature_thresholds

        counts, sig_patch, solve_patch = self.patch_calls()
        with patch.object(
            verifylib, "verify_metadata_signatures", side_effect=count_meta
        ), patch.object(
            verifylib,
            "verify_link_signature_thresholds",
            side_effect=count_threshold,
        ), sig_patch, solve_patch:
            with self.assertRaises(ThresholdVerificationError):
                self.verify(cache=cache)

        # Root ancestor and branch A's layer workflow run.  Content-addressed
        # signature memoization leaves only the tampered link's actual check.
        self.assertEqual(meta_count, 2)
        self.assertEqual(threshold_count, 2)
        self.assertEqual(counts["signature"], 1)

        # Restore exact evidence and mtime; original success entry is usable.
        with open(self.a_link_path, "wb") as handle:
            handle.write(original)
        os.utime(
            self.a_link_path,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )

        counts, sig_patch, solve_patch = self.patch_calls()
        with sig_patch, solve_patch:
            restored = self.verify(cache=cache)
        self.assertIn("b.out", restored.products)
        self.assertEqual(counts["signature"], 0)
        self.assertEqual(counts["solve"], 0)

    def test_signature_tamper_rechecks_branch(self):
        self.build_fixture()
        cache = VerificationCache()
        original = open(self.a_link_path, "rb").read()
        stat = os.stat(self.a_link_path)
        self.verify(cache=cache)

        data = json.loads(original)
        signature_section = data["signatures"][0]
        old_sig = signature_section.get("sig") or signature_section.get(
            "signature"
        )
        replacement_char = "0" if old_sig[0] != "0" else "1"
        new_sig = replacement_char + old_sig[1:]
        tampered = original.replace(old_sig.encode(), new_sig.encode(), 1)
        self.assertEqual(len(tampered), len(original))
        with open(self.a_link_path, "wb") as handle:
            handle.write(tampered)
        os.utime(self.a_link_path, ns=(stat.st_atime_ns, stat.st_mtime_ns))

        with self.assertRaises(ThresholdVerificationError):
            self.verify(cache=cache)

        with open(self.a_link_path, "wb") as handle:
            handle.write(original)
        os.utime(self.a_link_path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        self.verify(cache=cache)

    def test_valid_resigned_branch_change_reselects_without_other_branch(self):
        self.build_fixture()
        cache = VerificationCache()
        self.verify(cache=cache)

        # Replace A's link with new artifacts and re-sign with the authorized
        # ECDSA key under the same filename.
        os.remove(self.a_link_path)
        new_products = {"a-changed.out": h("7")}
        self.a_link_path = write_link(
            self.a_dir,
            "a-build",
            self.a_signer,
            self.a_pub,
            new_products,
        )

        counts, sig_patch, solve_patch = self.patch_calls()
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        with sig_patch, solve_patch:
            result = self.verify(cache=cache, report=report)

        # One new link signature plus A's grouped search; B is a layer hit.
        self.assertEqual(counts["signature"], 1)
        self.assertEqual(counts["solve"], 2)
        self.assertEqual(report.proof.get_products("branch-a"), new_products)
        self.assertIn("b.out", result.products)

        counts, sig_patch, solve_patch = self.patch_calls()
        with sig_patch, solve_patch:
            self.verify(cache=cache)
        self.assertEqual(counts["signature"], 0)
        self.assertEqual(counts["solve"], 0)


class TestCacheTrustConditions(TwoBranchFixture):
    def test_changed_root_public_key_does_not_hit_success(self):
        self.build_fixture()
        cache = VerificationCache()
        self.verify(cache=cache)

        with self.assertRaises(SignatureVerificationError):
            self.verify(
                cache=cache,
                root_keys={self.b_pub["keyid"]: self.b_pub},
            )

        self.verify(cache=cache)

    def test_changed_authorized_signers_threshold_and_rules(self):
        self.build_fixture()
        cache = VerificationCache()
        self.verify(cache=cache)

        # Authorized signer changes to B for branch A; expected A filename absent.
        self.resign_root(
            lambda layout: layout.steps[0].__setattr__(
                "pubkeys", [self.b_pub["keyid"]]
            )
        )
        with self.assertRaises(Exception):
            self.verify(cache=cache)
        self.restore_root()
        self.verify(cache=cache)

        # Threshold change requires two links.
        self.resign_root(
            lambda layout: layout.steps[0].__setattr__("threshold", 2)
        )
        with self.assertRaises(Exception):
            self.verify(cache=cache)
        self.restore_root()
        self.verify(cache=cache)

        # A newly signed DISALLOW rule rejects the cached successful artifacts.
        self.resign_root(
            lambda layout: layout.steps[1].__setattr__(
                "expected_products", [["DISALLOW", "*"]]
            )
        )
        with self.assertRaises(
            (RuleVerificationError, ThresholdVerificationError)
        ):
            self.verify(cache=cache)
        self.restore_root()
        self.verify(cache=cache)

    def test_substitution_parameter_change(self):
        self.build_fixture(with_parameter_rule=True)
        cache = VerificationCache()
        params = {"WANTED": "b.out"}
        self.verify(cache=cache, params=params)

        with self.assertRaises(
            (RuleVerificationError, ThresholdVerificationError)
        ):
            self.verify(cache=cache, params={"WANTED": "missing.out"})

        self.verify(cache=cache, params=params)

    def test_clock_crosses_any_layer_expiry(self):
        self.build_fixture(a_expires=A_EXPIRY)
        cache = VerificationCache()

        with patch("in_toto.verifylib.datetime") as mock_datetime:
            mock_datetime.datetime.now.return_value = datetime(
                2026, 1, 1, tzinfo=timezone.utc
            )
            self.verify(cache=cache)

        with patch("in_toto.verifylib.datetime") as mock_datetime:
            mock_datetime.datetime.now.return_value = datetime(
                2029, 1, 1, tzinfo=timezone.utc
            )
            with self.assertRaises(LayoutExpiredError):
                self.verify(cache=cache)

        with patch("in_toto.verifylib.datetime") as mock_datetime:
            mock_datetime.datetime.now.return_value = datetime(
                2026, 1, 1, tzinfo=timezone.utc
            )
            self.verify(cache=cache)


class TestGroupedProofIsolationAndLinkage(TemporaryVerificationDir):
    def setUp(self):
        super().setUp()
        self.owner = SignerStore.rsa
        self.owner_pub = SignerStore.rsa_pub
        self.ec_signer = SignerStore.ecdsa
        self.ec_pub = SignerStore.ecdsa_pub
        self.ed_signer = SignerStore.ed25519
        self.ed_pub = SignerStore.ed25519_pub

        self.ec_products = {"a-selected-ec": h("3")}
        self.ed_products = {"b-other-ed": h("4")}
        self.ec_path = write_link(
            ".", "work", self.ec_signer, self.ec_pub, self.ec_products
        )
        write_link(".", "work", self.ed_signer, self.ed_pub, self.ed_products)

        self.layout = Layout(
            keys={
                self.ec_pub["keyid"]: self.ec_pub,
                self.ed_pub["keyid"]: self.ed_pub,
            },
            steps=[
                Step(
                    name="work",
                    pubkeys=[self.ec_pub["keyid"], self.ed_pub["keyid"]],
                    threshold=1,
                    expected_products=[["ALLOW", "*"]],
                )
            ],
            threshold_mode=THRESHOLD_MODE_GROUPED,
            expires=EXPIRY,
        )
        self.root_path, _ = write_signed(
            ".", "root.layout", self.layout, self.owner
        )
        self.keys = {self.owner_pub["keyid"]: self.owner_pub}

    def verify(self, cache=None, report=None):
        return in_toto_verify(
            Metablock.load(self.root_path),
            self.keys,
            persist_inspection_links=False,
            verification_report=report,
            cache=cache,
        )

    def test_reselection_rule_trace_summary_and_object_isolation(self):
        cache = VerificationCache()
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        summary = self.verify(cache=cache, report=report)
        self.assertEqual(
            report.proof.get_selected_link("work").products,
            self.ec_products,
        )
        original_summary = summary_fingerprint(summary)
        original_proof = copy.deepcopy(report.proof.to_dict())
        original_report_dict = copy.deepcopy(report.to_dict())

        # Aggressively mutate every caller-owned object exposed by the result.
        summary.name = "mutated"
        summary.materials.clear()
        summary.products["injected"] = h("9")
        report.threshold_mode = "mutated"
        report.assignments_evaluated = 999
        report.rule_evaluations = 999
        group = report.selected_groups["work"]
        group.main_keyids.append("evil")
        group.link.products.clear()
        report.proof._groups.clear()

        report2 = VerificationReport(THRESHOLD_MODE_GROUPED)
        summary2 = self.verify(cache=cache, report=report2)
        self.assertEqual(summary_fingerprint(summary2), original_summary)
        self.assertEqual(report2.proof.to_dict(), original_proof)
        self.assertEqual(report2.to_dict(), original_report_dict)

        # Replace EC evidence with a product that sorts after the ED group.
        os.remove(self.ec_path)
        new_ec_products = {"zz-reselected": h("5")}
        self.ec_path = write_link(
            ".", "work", self.ec_signer, self.ec_pub, new_ec_products
        )

        real_solve = solve_grouped_threshold
        calls = []

        def counting_solve(*args, **kwargs):
            calls.append(1)
            return real_solve(*args, **kwargs)

        report3 = VerificationReport(THRESHOLD_MODE_GROUPED)
        with patch(
            "in_toto.verifylib.solve_grouped_threshold",
            side_effect=counting_solve,
        ):
            summary3 = self.verify(cache=cache, report=report3)

        self.assertEqual(len(calls), 1)
        selected = report3.proof.get_selected_group("work")
        self.assertEqual(selected.link_keyids, [self.ed_pub["keyid"]])
        self.assertEqual(report3.proof.get_products("work"), self.ed_products)
        self.assertEqual(summary3.products, self.ed_products)

        # The global consumption trace is repopulated for the new selection.
        import in_toto.ruleengine

        self.assertEqual(in_toto.ruleengine.RULE_TRACE["source_name"], "work")
        self.assertEqual(
            in_toto.ruleengine.RULE_TRACE["products"],
            list(self.ed_products.keys()),
        )
        self.assertEqual(
            in_toto.ruleengine.RULE_TRACE["trace"][-1]["queue"], []
        )


class TestInspectionsAlwaysRun(TemporaryVerificationDir):
    def test_current_inspection_results_and_command_counts(self):
        marker = os.path.join(self.tmp, "inspection-marker")
        current_artifact = os.path.join(self.tmp, "current-product.txt")
        with open(current_artifact, "w", encoding="utf8") as handle:
            handle.write("current")

        touch_script = os.path.join(SCRIPTS, "touch")
        layout = Layout(
            steps=[],
            inspect=[
                Inspection(
                    name="counted-touch",
                    run=[sys.executable, touch_script, marker],
                    expected_products=[
                        ["REQUIRE", "current-product.txt"],
                        ["ALLOW", "*"],
                    ],
                )
            ],
            expires=EXPIRY,
        )
        root_path, _ = write_signed(
            ".",
            "root.layout",
            layout,
            SignerStore.rsa,
        )
        keys = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}
        cache = VerificationCache()

        real_run = subprocess.run
        command_calls = []

        def counting_run(*args, **kwargs):
            command_calls.append(args[0] if args else kwargs.get("args"))
            return real_run(*args, **kwargs)

        with patch("in_toto.runlib.subprocess.run", side_effect=counting_run):
            in_toto_verify(
                Metablock.load(root_path),
                keys,
                link_dir_path=".",
                persist_inspection_links=False,
                cache=cache,
            )
            in_toto_verify(
                Metablock.load(root_path),
                keys,
                link_dir_path=".",
                persist_inspection_links=False,
                cache=cache,
            )
        self.assertEqual(len(command_calls), 2)
        self.assertTrue(os.path.exists(marker))

        # Remove a current product.  The cached step proof must not make the
        # fresh inspection rule inherit the prior success.
        os.remove(current_artifact)
        with patch("in_toto.runlib.subprocess.run", side_effect=counting_run):
            with self.assertRaises(RuleVerificationError):
                in_toto_verify(
                    Metablock.load(root_path),
                    keys,
                    link_dir_path=".",
                    persist_inspection_links=False,
                    cache=cache,
                )
        self.assertEqual(len(command_calls), 3)

    def test_step_proof_reuse_still_runs_inspection_and_rules(self):
        signer = SignerStore.rsa
        pub = SignerStore.rsa_pub
        write_link(
            ".",
            "build",
            signer,
            pub,
            {"build.out": h("8")},
        )
        marker = os.path.join(self.tmp, "step-inspection-marker")
        layout = Layout(
            keys={pub["keyid"]: pub},
            steps=[
                Step(
                    name="build",
                    pubkeys=[pub["keyid"]],
                    expected_products=[["ALLOW", "*"]],
                )
            ],
            inspect=[
                Inspection(
                    name="touch-after-step",
                    run=[
                        sys.executable,
                        os.path.join(SCRIPTS, "touch"),
                        marker,
                    ],
                    expected_materials=[["ALLOW", "*"]],
                    expected_products=[["ALLOW", "*"]],
                )
            ],
            expires=EXPIRY,
        )
        root_path, _ = write_signed(".", "root.layout", layout, signer)
        keys = {pub["keyid"]: pub}
        cache = VerificationCache()

        real_run = subprocess.run
        calls = []

        def counting_run(*args, **kwargs):
            calls.append(1)
            return real_run(*args, **kwargs)

        real_verify = Metablock.verify_signature
        signatures = []

        def counting_signature(instance, key):
            signatures.append(1)
            return real_verify(instance, key)

        with patch("in_toto.runlib.subprocess.run", side_effect=counting_run):
            first = in_toto_verify(
                Metablock.load(root_path),
                keys,
                persist_inspection_links=False,
                cache=cache,
            )

        with patch(
            "in_toto.runlib.subprocess.run", side_effect=counting_run
        ), patch.object(Metablock, "verify_signature", counting_signature):
            second = in_toto_verify(
                Metablock.load(root_path),
                keys,
                persist_inspection_links=False,
                cache=cache,
            )

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(len(calls), 2)
        self.assertEqual(signatures, [])
        self.assertIn("build.out", second.products)

    def test_failing_repo_expr_inspection_does_not_publish_success(self):
        layout = Layout(
            steps=[],
            inspect=[
                Inspection(
                    name="repo-expr-failure",
                    run=[sys.executable, os.path.join(SCRIPTS, "expr")],
                )
            ],
            expires=EXPIRY,
        )
        root_path, _ = write_signed(".", "root.layout", layout, SignerStore.rsa)
        keys = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}

        # Disabled-cache reference execution.
        with self.assertRaises(BadReturnValueError):
            in_toto_verify(
                Metablock.load(root_path),
                keys,
                persist_inspection_links=False,
            )

        cache = VerificationCache()
        for _ in range(2):
            with self.assertRaises(BadReturnValueError):
                in_toto_verify(
                    Metablock.load(root_path),
                    keys,
                    persist_inspection_links=False,
                    cache=cache,
                )

        # A failed layer publishes no reusable complete proof record.  It may
        # retain standalone successful signature memoization records, which are
        # not proofs and cannot cause in_toto_verify to return success.
        self.assertFalse(any(key.startswith("layer:") for key in cache.keys()))


class TestCacheEviction(unittest.TestCase):
    def test_positive_cap_clear_and_lru_revisit(self):
        with self.assertRaises(ValueError):
            VerificationCache(max_entries=0)
        with self.assertRaises(ValueError):
            VerificationCache(max_entries=True)

        cache = VerificationCache(max_entries=4)
        old_cwd = os.getcwd()
        tmp = tempfile.mkdtemp(prefix="in-toto-cache-eviction-")
        os.chdir(tmp)
        self.addCleanup(os.chdir, old_cwd)
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        signer = SignerStore.rsa
        pub = SignerStore.rsa_pub
        root_path = "root.layout"
        keys = {pub["keyid"]: pub}
        real_verify = Metablock.verify_signature
        actual = []

        def counting_verify(instance, key):
            actual.append(1)
            return real_verify(instance, key)

        fingerprints = []
        try:
            for version in range(6):
                layout = Layout(readme=f"evidence-version-{version}")
                write_signed(".", root_path, layout, signer)
                with patch.object(
                    Metablock, "verify_signature", counting_verify
                ):
                    in_toto_verify(
                        Metablock.load(root_path),
                        keys,
                        persist_inspection_links=False,
                        cache=cache,
                    )
                self.assertLessEqual(len(cache), 4)
                fingerprints.append(open(root_path, "rb").read())

            # Most recent and its predecessor remain under a four-record LRU
            # bound (each layer also has one signature record).
            before = len(actual)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load(root_path),
                    keys,
                    persist_inspection_links=False,
                    cache=cache,
                )
            self.assertEqual(len(actual), before)

            # Revisit the oldest evidence after LRU eviction.  It must be
            # recomputed correctly; a second revisit then hits the new entry.
            with open(root_path, "wb") as handle:
                handle.write(fingerprints[0])

            before_old = len(actual)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load(root_path),
                    keys,
                    persist_inspection_links=False,
                    cache=cache,
                )
            old_revisit_calls = len(actual) - before_old
            self.assertGreater(old_revisit_calls, 0)
            self.assertLessEqual(len(cache), 4)

            before_old_repeat = len(actual)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load(root_path),
                    keys,
                    persist_inspection_links=False,
                    cache=cache,
                )
            self.assertEqual(len(actual), before_old_repeat)

            cache.clear()
            self.assertEqual(len(cache), 0)
            with patch.object(Metablock, "verify_signature", counting_verify):
                in_toto_verify(
                    Metablock.load(root_path),
                    keys,
                    persist_inspection_links=False,
                    cache=cache,
                )
            self.assertGreater(len(actual), before)
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
