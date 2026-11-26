#!/usr/bin/env python

# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_groupedthreshold.py

<Purpose>
  Tests for the optional ``grouped`` threshold verification mode.

  Covers:
  - layout threshold mode declaration, (de-)serialization and signing
  - candidate grouping of verified links (exact materials/products equality,
    main/subkey deduplication, threshold eligibility)
  - chain-wide backtracking search over groups including cross-step MATCH
    rules, path prefixes and rule consumption semantics
  - completeness (no missed solutions), link-order independence and search
    counters
  - the queryable grouped threshold proof (no unselected results leak in)
  - end-to-end ``in_toto_verify`` behavior, including that inspections run
    exactly once and only after a consistent selection is found
  - unchanged legacy (strict, mode-less layout) behavior
"""
# pylint: disable=protected-access

import copy
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import securesystemslib._gpg.functions
from securesystemslib._gpg.constants import have_gpg

import in_toto.verifylib
from in_toto.exceptions import (
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.groupedthreshold import (
    GroupedThresholdProof,
    VerificationReport,
    group_verified_links,
    solve_grouped_threshold,
)
from in_toto.models.layout import (
    THRESHOLD_MODE_GROUPED,
    THRESHOLD_MODE_STRICT,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Envelope, Metablock
from tests.common import GPGKeysMixin, SignerStore, TmpDirMixin

SHA_A = {"sha256": "a" * 64}
SHA_B = {"sha256": "b" * 64}
SHA_C = {"sha256": "c" * 64}
SHA_D = {"sha256": "d" * 64}


def make_link(step_name, materials=None, products=None):
    return Link(
        name=step_name,
        materials=materials or {},
        products=products or {},
    )


class TestThresholdModeLayout(unittest.TestCase):
    """Tests requirement 1 (signed mode declaration) and requirement 8
    (legacy layouts remain byte-identical)."""

    def test_default_mode_is_strict_and_not_serialized(self):
        layout = Layout()
        self.assertEqual(layout.threshold_mode, THRESHOLD_MODE_STRICT)
        self.assertNotIn("threshold_mode", layout.to_dict())

        # Explicit strict mode serializes exactly like a legacy layout
        layout_strict = Layout(threshold_mode=THRESHOLD_MODE_STRICT)
        self.assertNotIn("threshold_mode", layout_strict.to_dict())

    def test_grouped_mode_roundtrip(self):
        layout = Layout(threshold_mode=THRESHOLD_MODE_GROUPED)
        data = layout.to_dict()
        self.assertEqual(data["threshold_mode"], THRESHOLD_MODE_GROUPED)

        reloaded = Layout.read(copy.deepcopy(data))
        self.assertEqual(reloaded.threshold_mode, THRESHOLD_MODE_GROUPED)
        self.assertEqual(reloaded.signable_bytes, layout.signable_bytes)

    def test_mode_survives_metablock_and_envelope_roundtrip(self):
        layout = Layout(threshold_mode=THRESHOLD_MODE_GROUPED)
        metablock = Metablock(signed=layout)
        raw = json.dumps(metablock.to_dict(), sort_keys=True)
        reloaded = Metablock.from_dict(json.loads(raw))
        self.assertEqual(reloaded.signed.threshold_mode, THRESHOLD_MODE_GROUPED)
        self.assertEqual(reloaded.signed.signable_bytes, layout.signable_bytes)

        envelope = Envelope.from_signable(layout)
        payload = json.loads(envelope.payload.decode("utf-8"))
        self.assertEqual(payload["threshold_mode"], THRESHOLD_MODE_GROUPED)
        self.assertEqual(
            envelope.get_payload().signable_bytes, layout.signable_bytes
        )

    def test_invalid_mode_rejected(self):
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            Layout(threshold_mode="anything-goes")

        layout = Layout()
        layout.threshold_mode = 42
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            layout.validate()

    def test_changing_mode_invalidates_existing_signature(self):
        """The mode is part of the signed payload."""
        signer = SignerStore.rsa
        pubkey = SignerStore.rsa_pub

        grouped = Metablock(
            signed=Layout(threshold_mode=THRESHOLD_MODE_GROUPED)
        )
        grouped.create_signature(signer)
        grouped.verify_signature(pubkey)

        # Downgrading the mode changes the signable bytes and must fail
        tampered = copy.deepcopy(grouped)
        tampered.signed.threshold_mode = THRESHOLD_MODE_STRICT
        self.assertNotIn("threshold_mode", tampered.signed.to_dict())
        with self.assertRaises(SignatureVerificationError):
            tampered.verify_signature(pubkey)

        # Conversely, a signature over a legacy strict layout does not
        # validate a grouped payload (the mode cannot be relaxed offline)
        strict = Metablock(signed=Layout())
        strict.create_signature(signer)
        upgraded = copy.deepcopy(strict)
        upgraded.signed.threshold_mode = THRESHOLD_MODE_GROUPED
        with self.assertRaises(SignatureVerificationError):
            upgraded.verify_signature(pubkey)

    def test_legacy_fixture_has_no_mode_field_and_keeps_bytes(self):
        template = Metablock.load(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "demo_files",
                "demo.layout.template",
            )
        )
        self.assertEqual(template.signed.threshold_mode, THRESHOLD_MODE_STRICT)
        self.assertNotIn("threshold_mode", template.signed.to_dict())

        signer = SignerStore.rsa
        pubkey = SignerStore.rsa_pub
        template.create_signature(signer)
        template.verify_signature(pubkey)

        raw = json.dumps(template.to_dict(), sort_keys=True)
        reloaded = Metablock.from_dict(json.loads(raw))
        self.assertEqual(
            reloaded.signed.signable_bytes,
            template.signed.signable_bytes,
        )
        reloaded.verify_signature(pubkey)


class TestGroupVerifiedLinks(unittest.TestCase):
    """Tests requirement 2: grouping, eligibility and deduplication."""

    @classmethod
    def setUpClass(cls):
        cls.alice = SignerStore.rsa_pub
        cls.bob = SignerStore.ecdsa_pub
        cls.carl = SignerStore.ed25519_pub
        cls.keyids = [cls.alice["keyid"], cls.bob["keyid"], cls.carl["keyid"]]

    def _layout(self, threshold=2):
        return Layout(
            keys={
                key["keyid"]: key for key in (self.alice, self.bob, self.carl)
            },
            steps=[
                Step(
                    name="step", pubkeys=list(self.keyids), threshold=threshold
                )
            ],
        )

    def test_groups_require_exact_materials_and_products(self):
        chain = {
            "step": {
                self.alice["keyid"]: make_link(
                    "step", materials={"m": SHA_A}, products={"p": SHA_B}
                ),
                self.bob["keyid"]: make_link(
                    "step", materials={"m": SHA_A}, products={"p": SHA_B}
                ),
                # Same paths but a different hash -> different group
                self.carl["keyid"]: make_link(
                    "step", materials={"m": SHA_A}, products={"p": SHA_C}
                ),
            }
        }
        candidates = group_verified_links(self._layout(), chain)
        self.assertEqual(len(candidates["step"]), 1)

        group = candidates["step"][0]
        self.assertEqual(group.support_count, 2)
        self.assertEqual(
            sorted(group.main_keyids),
            sorted([self.alice["keyid"], self.bob["keyid"]]),
        )
        self.assertEqual(group.link.products, {"p": SHA_B})

        # Dict insertion order must not influence grouping
        reordered = {
            "step": {
                keyid: chain["step"][keyid]
                for keyid in reversed(list(chain["step"].keys()))
            }
        }
        reordered_candidates = group_verified_links(self._layout(), reordered)
        self.assertEqual(
            sorted(reordered_candidates["step"][0].link_keyids),
            sorted(group.link_keyids),
        )
        self.assertEqual(
            sorted(reordered_candidates["step"][0].main_keyids),
            sorted(group.main_keyids),
        )

    def test_no_eligible_group_raises(self):
        chain = {
            "step": {
                self.alice["keyid"]: make_link("step", products={"p": SHA_A}),
                self.bob["keyid"]: make_link("step", products={"p": SHA_B}),
                self.carl["keyid"]: make_link("step", products={"p": SHA_C}),
            }
        }
        with self.assertRaises(ThresholdVerificationError):
            group_verified_links(self._layout(), chain)

    def test_multiple_eligible_groups(self):
        chain = {
            "step": {
                self.alice["keyid"]: make_link("step", products={"p": SHA_A}),
                self.bob["keyid"]: make_link("step", products={"p": SHA_A}),
                self.carl["keyid"]: make_link("step", products={"p": SHA_B}),
            }
        }
        # threshold 1 makes both groups eligible
        candidates = group_verified_links(self._layout(threshold=1), chain)
        self.assertEqual(len(candidates["step"]), 2)
        # Deterministic, artifact-based ordering
        artifacts = [group.link.products for group in candidates["step"]]
        self.assertEqual(
            artifacts,
            sorted(artifacts, key=lambda d: json.dumps(d, sort_keys=True)),
        )

    def test_grouping_uses_pems_signed_and_authorized_links_only(self):
        """Full signature/authorization flow feeds only valid links."""
        layout = self._layout(threshold=2)
        chain = {
            "step": {
                self.alice["keyid"]: make_link("step", products={"p": SHA_A}),
                self.bob["keyid"]: make_link("step", products={"p": SHA_A}),
                self.carl["keyid"]: make_link("step", products={"p": SHA_B}),
            }
        }
        candidates = group_verified_links(layout, chain)
        group = candidates["step"][0]
        # The unsupported single-link group must not appear as a candidate
        self.assertEqual(len(candidates["step"]), 1)
        self.assertNotIn(self.carl["keyid"], group.main_keyids)


class TestSolveGroupedThreshold(unittest.TestCase):
    """Tests requirements 3, 4 and 5 at the solver level."""

    @classmethod
    def setUpClass(cls):
        cls.alice = SignerStore.rsa_pub["keyid"]
        cls.bob = SignerStore.ecdsa_pub["keyid"]
        cls.carl = SignerStore.ed25519_pub["keyid"]

    def _layout(self, steps):
        return Layout(
            keys={
                SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub,
                SignerStore.ecdsa_pub["keyid"]: SignerStore.ecdsa_pub,
                SignerStore.ed25519_pub["keyid"]: SignerStore.ed25519_pub,
            },
            steps=steps,
        )

    def test_solver_finds_globally_consistent_match_solution(self):
        layout = self._layout(
            [
                Step(
                    name="write",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=2,
                    expected_products=[
                        ["CREATE", "foo"],
                        ["DISALLOW", "*"],
                    ],
                ),
                Step(
                    name="package",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=2,
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        chain = {
            "write": {
                self.alice: make_link("write", products={"foo": SHA_A}),
                self.bob: make_link("write", products={"foo": SHA_A}),
                self.carl: make_link("write", products={"foo": SHA_B}),
            },
            "package": {
                self.alice: make_link(
                    "package", materials={"foo": SHA_A}, products={"tar": SHA_C}
                ),
                self.bob: make_link(
                    "package", materials={"foo": SHA_A}, products={"tar": SHA_C}
                ),
                self.carl: make_link(
                    "package", materials={"foo": SHA_B}, products={"tar": SHA_C}
                ),
            },
        }
        selection = solve_grouped_threshold(layout, chain)
        self.assertEqual(selection["write"].link.products, {"foo": SHA_A})
        self.assertEqual(selection["package"].link.materials, {"foo": SHA_A})

    def test_backtracking_does_not_stick_to_first_or_largest_group(self):
        """The first and best-supported group is globally incompatible; the
        solver must backtrack to a smaller, later candidate."""
        layout = self._layout(
            [
                Step(
                    name="write",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=1,
                    expected_products=[
                        ["CREATE", "foo"],
                        ["DISALLOW", "*"],
                    ],
                ),
                Step(
                    name="package",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=1,
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        # SHA_A sorts before SHA_B, so SHA_A is tried first; it is backed by
        # two functionaries, SHA_B only by one. Only SHA_B is chain-consistent.
        chain = {
            "write": {
                self.alice: make_link("write", products={"foo": SHA_A}),
                self.bob: make_link("write", products={"foo": SHA_A}),
                self.carl: make_link("write", products={"foo": SHA_B}),
            },
            "package": {
                self.alice: make_link("package", materials={"foo": SHA_B}),
            },
        }
        selection = solve_grouped_threshold(layout, chain)
        self.assertEqual(selection["write"].link.products, {"foo": SHA_B})
        self.assertEqual(selection["write"].support_count, 1)

    def test_locally_sufficient_but_globally_unsolvable(self):
        layout = self._layout(
            [
                Step(
                    name="write",
                    pubkeys=[self.alice, self.bob],
                    threshold=2,
                ),
                Step(
                    name="package",
                    pubkeys=[self.alice, self.bob],
                    threshold=2,
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        chain = {
            "write": {
                self.alice: make_link("write", products={"foo": SHA_A}),
                self.bob: make_link("write", products={"foo": SHA_A}),
            },
            "package": {
                self.alice: make_link("package", materials={"foo": SHA_B}),
                self.bob: make_link("package", materials={"foo": SHA_B}),
            },
        }
        with self.assertRaises(ThresholdVerificationError) as ctx:
            solve_grouped_threshold(layout, chain)
        # The failure message is reused at the verifylib exception layer and
        # identifies the offending step.
        self.assertIn("package", str(ctx.exception))

    def test_result_independent_of_link_order(self):
        layout = self._layout(
            [
                Step(
                    name="write",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=1,
                ),
                Step(
                    name="package",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=1,
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        chain = {
            "write": {
                self.alice: make_link("write", products={"foo": SHA_A}),
                self.bob: make_link("write", products={"foo": SHA_B}),
            },
            "package": {
                self.alice: make_link("package", materials={"foo": SHA_B}),
                self.bob: make_link("package", materials={"foo": SHA_A}),
            },
        }
        first = solve_grouped_threshold(layout, chain)

        reversed_chain = {
            step: dict(reversed(list(links.items())))
            for step, links in chain.items()
        }
        second = solve_grouped_threshold(layout, reversed_chain)

        for step_name in ("write", "package"):
            self.assertEqual(
                first[step_name].link.materials,
                second[step_name].link.materials,
            )
            self.assertEqual(
                first[step_name].link.products,
                second[step_name].link.products,
            )

    def test_rule_order_consumption_on_selected_links(self):
        """CREATE then DISALLOW only passes for the group whose artifacts are
        fully consumed; the other group is rejected via backtracking."""
        layout = self._layout(
            [
                Step(
                    name="build",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=1,
                    expected_products=[
                        ["CREATE", "foo"],
                        ["DISALLOW", "*"],
                    ],
                )
            ]
        )
        chain = {
            "build": {
                # Artifact "bar" would remain unconsumed -> rule failure
                self.alice: make_link(
                    "build", products={"foo": SHA_A, "bar": SHA_D}
                ),
                # Only "foo" -> rules pass
                self.bob: make_link("build", products={"foo": SHA_A}),
            }
        }
        selection = solve_grouped_threshold(layout, chain)
        self.assertEqual(selection["build"].link.products, {"foo": SHA_A})

        # If every group leaves artifacts unconsumed there is no solution
        chain_all_bad = {
            "build": {
                self.alice: make_link(
                    "build", products={"foo": SHA_A, "bar": SHA_D}
                ),
                self.bob: make_link(
                    "build", products={"foo": SHA_A, "baz": SHA_D}
                ),
            }
        }
        with self.assertRaises(ThresholdVerificationError):
            solve_grouped_threshold(layout, chain_all_bad)

    def test_match_rule_with_prefixes(self):
        layout = self._layout(
            [
                Step(name="write", pubkeys=[self.alice], threshold=1),
                Step(
                    name="package",
                    pubkeys=[self.alice],
                    threshold=1,
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "IN",
                            "src",
                            "WITH",
                            "PRODUCTS",
                            "IN",
                            "out",
                            "FROM",
                            "write",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        chain = {
            "write": {
                self.alice: make_link(
                    "write", products={"out/foo": SHA_A, "other": SHA_B}
                ),
            },
            "package": {
                self.alice: make_link(
                    "package",
                    materials={"src/foo": SHA_A, "leftover": SHA_C},
                ),
            },
        }
        # "leftover" is not consumed -> the prefixed MATCH alone is not enough
        with self.assertRaises(ThresholdVerificationError):
            solve_grouped_threshold(layout, chain)

        del chain["package"][self.alice].materials["leftover"]
        selection = solve_grouped_threshold(layout, chain)
        self.assertEqual(
            selection["package"].link.materials, {"src/foo": SHA_A}
        )

    def test_match_cycle_evaluated_on_complete_assignment(self):
        # A genuine MATCH cycle: a's product rule references b's materials and
        # b's material rule references a's products. Neither rule can be
        # evaluated while selecting the first step, so both are deferred to
        # the complete assignment.
        layout = self._layout(
            [
                Step(
                    name="a",
                    pubkeys=[self.alice],
                    threshold=1,
                    expected_products=[
                        [
                            "MATCH",
                            "x",
                            "WITH",
                            "MATERIALS",
                            "FROM",
                            "b",
                        ],
                        [
                            "MATCH",
                            "y",
                            "WITH",
                            "MATERIALS",
                            "FROM",
                            "b",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
                Step(
                    name="b",
                    pubkeys=[self.alice],
                    threshold=1,
                    expected_materials=[
                        [
                            "MATCH",
                            "y",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "a",
                        ],
                        [
                            "MATCH",
                            "x",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "a",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        # Consistent cycle: every artifact of each step is consumed by that
        # step's own MATCH rule, and the hashes agree across the two links
        consistent = {
            "a": {
                self.alice: make_link(
                    "a",
                    products={"x": SHA_A, "y": SHA_A},
                    materials={"y": SHA_A},
                )
            },
            "b": {
                self.alice: make_link(
                    "b",
                    materials={"x": SHA_A, "y": SHA_A},
                    products={"y": SHA_A},
                )
            },
        }
        selection = solve_grouped_threshold(layout, consistent)
        self.assertEqual(selection["a"].link.products, {"x": SHA_A, "y": SHA_A})

        # Break one edge of the cycle: no complete assignment passes
        inconsistent = {
            "a": {
                self.alice: make_link(
                    "a",
                    products={"x": SHA_A, "y": SHA_A},
                    materials={"y": SHA_A},
                )
            },
            "b": {
                self.alice: make_link(
                    "b",
                    materials={"x": SHA_B, "y": SHA_A},
                    products={"y": SHA_A},
                )
            },
        }
        with self.assertRaises(ThresholdVerificationError):
            solve_grouped_threshold(layout, inconsistent)

    def test_search_counters_and_callback(self):
        layout = self._layout(
            [
                Step(name="a", pubkeys=[self.alice, self.bob], threshold=1),
                Step(
                    name="b",
                    pubkeys=[self.alice, self.bob],
                    threshold=1,
                    expected_materials=[
                        ["MATCH", "f", "WITH", "PRODUCTS", "FROM", "a"],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )

        # Failing chain: no material of b matches any product of a. Step b's
        # rules become evaluable as soon as a is selected, so branches are
        # pruned before completing an assignment; the callback must not fire
        # and no complete assignment may be counted.
        failing_chain = {
            "a": {
                self.alice: make_link("a", products={"f": SHA_A}),
                self.bob: make_link("a", products={"f": SHA_B}),
            },
            "b": {
                self.alice: make_link("b", materials={"f": SHA_C}),
                self.bob: make_link("b", materials={"f": SHA_D}),
            },
        }
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        assignments = []
        with self.assertRaises(ThresholdVerificationError):
            solve_grouped_threshold(
                layout,
                failing_chain,
                report=report,
                assignment_callback=assignments.append,
            )
        self.assertEqual(report.assignments_evaluated, 0)
        self.assertEqual(assignments, [])
        self.assertEqual(report.candidate_groups, {"a": 2, "b": 2})
        # Step a has no MATCH rules: one immediate evaluation per candidate
        # (2), plus one evaluation of b per candidate of a (2), and two
        # evaluations of b while trying its own candidates under the second
        # assignment of a -> 6 deterministic rule evaluations.
        self.assertEqual(report.rule_evaluations, 6)

        # Solvable chain: the first complete assignment succeeds and the
        # callback selection equals the returned selection.
        chain = {
            "a": {
                self.alice: make_link("a", products={"f": SHA_A}),
                self.bob: make_link("a", products={"f": SHA_B}),
            },
            "b": {
                self.alice: make_link("b", materials={"f": SHA_A}),
                self.bob: make_link("b", materials={"f": SHA_B}),
            },
        }
        report2 = VerificationReport(THRESHOLD_MODE_GROUPED)
        passing = []
        selection = solve_grouped_threshold(
            layout,
            chain,
            report=report2,
            assignment_callback=passing.append,
        )
        self.assertEqual(report2.assignments_evaluated, 1)
        self.assertEqual(len(passing), 1)
        self.assertEqual(
            selection["a"].link.products, passing[-1]["a"].link.products
        )

    def test_backtracking_evaluates_multiple_candidates(self):
        """The first candidate of step a fails against every candidate of b;
        the search must backtrack instead of declaring failure."""
        layout = self._layout(
            [
                Step(name="a", pubkeys=[self.alice, self.bob], threshold=1),
                Step(
                    name="b",
                    pubkeys=[self.alice, self.bob],
                    threshold=1,
                    expected_materials=[
                        ["MATCH", "f", "WITH", "PRODUCTS", "FROM", "a"],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        # The first candidate of a (hash A) matches no candidate of b; the
        # second candidate of a (hash B) matches the first candidate of b.
        chain = {
            "a": {
                self.alice: make_link("a", products={"f": SHA_A}),
                self.bob: make_link("a", products={"f": SHA_B}),
            },
            "b": {
                self.alice: make_link("b", materials={"f": SHA_B}),
                self.bob: make_link("b", materials={"f": SHA_C}),
            },
        }
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        seen = []
        selection = solve_grouped_threshold(
            layout, chain, report=report, assignment_callback=seen.append
        )
        # The consistent branch is the only complete assignment reached:
        # the incompatible a=A branch is pruned while exploring b.
        self.assertEqual(report.assignments_evaluated, 1)
        self.assertEqual(len(seen), 1)
        # Backtracking did happen: b's rules were evaluated for both a groups
        self.assertGreaterEqual(report.rule_evaluations, 4)
        self.assertEqual(selection["a"].link.products, {"f": SHA_B})
        self.assertEqual(selection["b"].link.materials, {"f": SHA_B})

    def test_proof_contains_only_selected_results(self):
        layout = self._layout(
            [
                Step(
                    name="s1",
                    pubkeys=[self.alice, self.bob, self.carl],
                    threshold=2,
                )
            ]
        )
        chain = {
            "s1": {
                self.alice: make_link("s1", products={"p": SHA_A}),
                self.bob: make_link("s1", products={"p": SHA_A}),
                self.carl: make_link("s1", products={"p": SHA_B}),
            }
        }
        selection = solve_grouped_threshold(layout, chain)
        proof = GroupedThresholdProof(selection)

        self.assertEqual(proof.get_step_names(), ["s1"])
        self.assertEqual(proof.get_products("s1"), {"p": SHA_A})
        self.assertEqual(
            sorted(proof.get_supporters("s1")),
            sorted([self.alice, self.bob]),
        )
        proof_dict = proof.to_dict()
        serialized = json.dumps(proof_dict)
        self.assertNotIn(SHA_B["sha256"], serialized)
        self.assertNotIn(self.carl, serialized)

        # Remaining proof accessors and string representations
        self.assertEqual(proof.get_selected_group("s1"), selection["s1"])
        self.assertEqual(proof.get_selected_link("s1"), selection["s1"].link)
        self.assertEqual(proof.get_materials("s1"), {})
        self.assertIn("GroupedThresholdProof", repr(proof))
        self.assertIn("LinkGroup", repr(selection["s1"]))

    def test_failure_without_any_rule_error_has_plain_message(self):
        """A rule-free layout cannot have rule failures; the generic message
        is used without an appended details section."""
        layout = self._layout(
            [Step(name="only", pubkeys=[self.alice], threshold=1)]
        )
        chain = {
            "only": {
                self.alice: make_link("only", products={"p": SHA_A}),
            }
        }
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        selection = solve_grouped_threshold(layout, chain, report=report)
        # Successful report snapshot, including its representation with proof
        report.selected_groups = selection
        report.proof = GroupedThresholdProof(selection)
        snapshot = report.to_dict()
        self.assertEqual(snapshot["threshold_mode"], THRESHOLD_MODE_GROUPED)
        self.assertIn("proof", snapshot)
        json.dumps(snapshot)
        self.assertEqual(snapshot["assignments_evaluated"], 1)

    def test_report_snapshot_without_proof(self):
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        snapshot = report.to_dict()
        self.assertNotIn("proof", snapshot)
        self.assertEqual(snapshot["candidate_groups"], {})


class TestInTotoVerifyGrouped(unittest.TestCase, TmpDirMixin):
    """End-to-end tests for requirements 1, 2, 5 and 6."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

        cls.alice = SignerStore.rsa
        cls.alice_pub = SignerStore.rsa_pub
        cls.bob = SignerStore.ecdsa
        cls.bob_pub = SignerStore.ecdsa_pub
        cls.carl = SignerStore.ed25519
        cls.carl_pub = SignerStore.ed25519_pub

        cls.h_foo_v1 = {"sha256": "1" * 64}
        cls.h_foo_v2 = {"sha256": "2" * 64}
        cls.h_tar = {"sha256": "3" * 64}

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def setUp(self):
        # Each test gets a clean link directory
        self.test_subdir = tempfile.mkdtemp(dir=self.test_dir)
        os.chdir(self.test_subdir)

    def _write_signed_link(self, step, signer, materials=None, products=None):
        metadata = Metablock(
            signed=Link(
                name=step, materials=materials or {}, products=products or {}
            )
        )
        metadata.create_signature(signer)
        metadata.dump(
            FILENAME_FORMAT.format(
                step_name=step, keyid=signer.public_key.keyid
            )
        )

    def _layout(self, mode, threshold=2):
        return Layout(
            threshold_mode=mode,
            keys={
                self.alice_pub["keyid"]: self.alice_pub,
                self.bob_pub["keyid"]: self.bob_pub,
                self.carl_pub["keyid"]: self.carl_pub,
            },
            steps=[
                Step(
                    name="write",
                    pubkeys=[
                        self.alice_pub["keyid"],
                        self.bob_pub["keyid"],
                        self.carl_pub["keyid"],
                    ],
                    threshold=threshold,
                    expected_products=[
                        ["CREATE", "foo"],
                        ["DISALLOW", "*"],
                    ],
                ),
                Step(
                    name="package",
                    pubkeys=[
                        self.alice_pub["keyid"],
                        self.bob_pub["keyid"],
                        self.carl_pub["keyid"],
                    ],
                    threshold=threshold,
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write",
                        ],
                        ["DISALLOW", "*"],
                    ],
                    expected_products=[
                        ["CREATE", "tar.gz"],
                        ["DISALLOW", "*"],
                    ],
                ),
            ],
        )

    def _write_conflicting_links(self):
        """Write threshold-2 links with a conflicting third result."""
        # write: alice and bob agree on v1, carl reports v2
        self._write_signed_link(
            "write", self.alice, products={"foo": self.h_foo_v1}
        )
        self._write_signed_link(
            "write", self.bob, products={"foo": self.h_foo_v1}
        )
        self._write_signed_link(
            "write", self.carl, products={"foo": self.h_foo_v2}
        )
        # package: alice and bob consume v1, carl consumes v2
        self._write_signed_link(
            "package",
            self.alice,
            materials={"foo": self.h_foo_v1},
            products={"tar.gz": self.h_tar},
        )
        self._write_signed_link(
            "package",
            self.bob,
            materials={"foo": self.h_foo_v1},
            products={"tar.gz": self.h_tar},
        )
        self._write_signed_link(
            "package",
            self.carl,
            materials={"foo": self.h_foo_v2},
            products={"tar.gz": self.h_tar},
        )

    def _signed_layout(self, layout):
        metablock = Metablock(signed=layout)
        metablock.create_signature(self.alice)
        return metablock

    def test_strict_mode_rejects_conflicting_links(self):
        """Requirement 8: legacy behavior is unchanged."""
        self._write_conflicting_links()
        metablock = self._signed_layout(self._layout(THRESHOLD_MODE_STRICT))
        with self.assertRaises(ThresholdVerificationError):
            in_toto.verifylib.in_toto_verify(
                metablock,
                {self.alice_pub["keyid"]: self.alice_pub},
                persist_inspection_links=False,
            )

    def test_grouped_mode_accepts_conflicting_links(self):
        self._write_conflicting_links()
        metablock = self._signed_layout(self._layout(THRESHOLD_MODE_GROUPED))
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        summary = in_toto.verifylib.in_toto_verify(
            metablock,
            {self.alice_pub["keyid"]: self.alice_pub},
            persist_inspection_links=False,
            verification_report=report,
        )

        # Requirement 5: proof and summary reflect the selected groups
        self.assertEqual(
            report.proof.get_products("write"), {"foo": self.h_foo_v1}
        )
        self.assertEqual(
            sorted(report.proof.get_supporters("write")),
            sorted([self.alice_pub["keyid"], self.bob_pub["keyid"]]),
        )
        self.assertNotIn(
            self.carl_pub["keyid"],
            report.proof.get_supporters("write"),
        )
        self.assertEqual(summary.products, {"tar.gz": self.h_tar})
        self.assertEqual(summary.materials, {})
        self.assertEqual(report.inspection_executions, 0)

    def test_inspections_run_once_only_after_solution_found(self):
        self._write_conflicting_links()

        layout = self._layout(THRESHOLD_MODE_GROUPED)
        layout.inspect.append(
            # Rules are irrelevant: the inspection is mocked out
            in_toto.models.layout.Inspection(name="check")
        )
        metablock = self._signed_layout(layout)

        with patch("in_toto.verifylib.run_all_inspections") as mock_inspections:
            mock_inspections.return_value = {"check": Link(name="check")}
            report = VerificationReport(THRESHOLD_MODE_GROUPED)
            in_toto.verifylib.in_toto_verify(
                metablock,
                {self.alice_pub["keyid"]: self.alice_pub},
                persist_inspection_links=False,
                verification_report=report,
            )
            self.assertEqual(mock_inspections.call_count, 1)
            self.assertEqual(report.inspection_executions, 1)

    def test_no_inspection_on_failed_search_and_no_proof(self):
        self._write_conflicting_links()
        # Break chain consistency: package's threshold group now consumes v2
        os.remove(
            FILENAME_FORMAT.format(
                step_name="package", keyid=self.bob_pub["keyid"]
            )
        )
        self._write_signed_link(
            "package",
            self.bob,
            materials={"foo": self.h_foo_v2},
            products={"tar.gz": self.h_tar},
        )

        metablock = self._signed_layout(self._layout(THRESHOLD_MODE_GROUPED))
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        with patch("in_toto.verifylib.run_all_inspections") as mock_inspections:
            with self.assertRaises(ThresholdVerificationError):
                in_toto.verifylib.in_toto_verify(
                    metablock,
                    {self.alice_pub["keyid"]: self.alice_pub},
                    persist_inspection_links=False,
                    verification_report=report,
                )
            self.assertEqual(mock_inspections.call_count, 0)
        self.assertIsNone(report.proof)
        self.assertEqual(report.inspection_executions, 0)

    def test_rule_trace_and_summary_follow_final_selection(self):
        """Requirement 5: failed candidates must not leak rule state."""
        self._write_conflicting_links()
        metablock = self._signed_layout(self._layout(THRESHOLD_MODE_GROUPED))
        summary = in_toto.verifylib.in_toto_verify(
            metablock,
            {self.alice_pub["keyid"]: self.alice_pub},
            persist_inspection_links=False,
        )

        # The final rule pass runs on the selected links: the trace only
        # lists artifacts of the selected groups, never carl's v2 results.
        trace_text = json.dumps(in_toto.verifylib.RULE_TRACE)
        self.assertNotIn(self.h_foo_v2["sha256"], trace_text)
        # The last evaluated item is the package step's product rules, whose
        # available materials still point at the selected v1 link
        self.assertEqual(in_toto.verifylib.RULE_TRACE["materials"], ["foo"])

        # The summary link follows the same selection
        self.assertEqual(summary.products, {"tar.gz": self.h_tar})

    def test_unsigned_layout_rejects_grouped_links(self):
        """No verifier-side switch can enable grouped mode: a strict signed
        layout fails even though grouped verification would pass."""
        self._write_conflicting_links()
        strict_metablock = self._signed_layout(
            self._layout(THRESHOLD_MODE_STRICT)
        )
        with self.assertRaises(ThresholdVerificationError):
            in_toto.verifylib.in_toto_verify(
                strict_metablock,
                {self.alice_pub["keyid"]: self.alice_pub},
                persist_inspection_links=False,
            )

        grouped_metablock = self._signed_layout(
            self._layout(THRESHOLD_MODE_GROUPED)
        )
        in_toto.verifylib.in_toto_verify(
            grouped_metablock,
            {self.alice_pub["keyid"]: self.alice_pub},
            persist_inspection_links=False,
        )

    def test_grouped_mode_works_with_dsse_envelope(self):
        """The mode is equally protected inside a DSSE envelope."""
        self._write_conflicting_links()
        envelope = Envelope.from_signable(self._layout(THRESHOLD_MODE_GROUPED))
        envelope.create_signature(self.alice)

        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        in_toto.verifylib.in_toto_verify(
            envelope,
            {self.alice_pub["keyid"]: self.alice_pub},
            persist_inspection_links=False,
            verification_report=report,
        )
        self.assertEqual(
            report.proof.get_products("write"), {"foo": self.h_foo_v1}
        )

        # Tampering with the payload mode breaks DSSE signature verification
        import copy as copy_module

        tampered = copy_module.deepcopy(envelope)
        payload = json.loads(tampered.payload.decode("utf-8"))
        payload["threshold_mode"] = THRESHOLD_MODE_STRICT
        tampered.payload = json.dumps(payload).encode("utf-8")
        with self.assertRaises(SignatureVerificationError):
            tampered.verify_signature(self.alice_pub)


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestGroupedThresholdGpgSubkeys(
    unittest.TestCase, TmpDirMixin, GPGKeysMixin
):
    """Tests requirement 2 main/subkey deduplication in grouped mode."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()
        cls.set_up_gpg_keys()

        cls.masterkey = "40e692c3ae03f6b88dff95d0d2c9fe930766998d"
        cls.subkey1 = "35830aa342b9fea0178876b02b25647ff0ef59fe"
        cls.subkey2 = "732d722578f71a9ec967a64bfead922c91eb7351"
        cls.other_main = cls.gpg_key_768c43

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_subkeys_of_same_main_key_count_once_per_group(self):
        link1 = Metablock(signed=Link(name="step", products={"p": SHA_A}))
        link1.sign_gpg(self.subkey1, self.gnupg_home)
        link2 = Metablock(signed=Link(name="step", products={"p": SHA_A}))
        link2.sign_gpg(self.subkey2, self.gnupg_home)

        layout = Layout(
            steps=[Step(name="step", pubkeys=[self.masterkey], threshold=2)],
            keys={
                self.masterkey: securesystemslib._gpg.functions.export_pubkey(
                    self.masterkey, self.gnupg_home
                )
            },
        )
        chain = {
            "step": {self.subkey1: link1.signed, self.subkey2: link2.signed}
        }
        with self.assertRaises(ThresholdVerificationError):
            group_verified_links(layout, chain)

        # A link from a second, distinct main key makes the group eligible
        link3 = Metablock(signed=Link(name="step", products={"p": SHA_A}))
        link3.sign_gpg(self.other_main, self.gnupg_home)
        layout.keys[self.other_main] = (
            securesystemslib._gpg.functions.export_pubkey(
                self.other_main, self.gnupg_home
            )
        )
        layout.steps[0].pubkeys.append(self.other_main)
        chain["step"][self.other_main] = link3.signed

        candidates = group_verified_links(layout, chain)
        self.assertEqual(len(candidates["step"]), 1)
        self.assertEqual(candidates["step"][0].support_count, 2)
        self.assertEqual(
            sorted(candidates["step"][0].main_keyids),
            sorted([self.masterkey, self.other_main]),
        )


if __name__ == "__main__":
    unittest.main()
