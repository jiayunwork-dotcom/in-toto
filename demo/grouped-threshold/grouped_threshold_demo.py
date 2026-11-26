#!/usr/bin/env python3

# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
End-to-end terminal demo for the optional "grouped" threshold verification
mode.

The demo creates all metadata in a temporary directory and signs it with the
repository's test keys (tests/pems). Nothing is written outside the temp
directory.

Scenarios:

  1. A legacy "strict" layout has no threshold_mode field on the wire and
     keeps its exact signable bytes after a dump/load round trip.
  2. Switching the signed layout to the grouped mode changes the signable
     bytes and invalidates the old signature: the mode cannot be relaxed by a
     verifier-side parameter.
  3. Three functionaries submit two different results for each of two steps.
     Strict verification rejects the disagreement; grouped verification
     passes and prints the chain-wide proof (selected artifacts and their
     supporters, without any unselected result).
  4. Every step locally has enough supporters, but no group combination
     satisfies the cross-step MATCH rule: verification fails and no
     inspection is executed.
  5. Shuffling the order in which links are presented does not change the
     outcome.

Run from the repository root:

    python3 demo/grouped-threshold/grouped_threshold_demo.py
"""

import json
import os
import shutil
import sys
import tempfile

# Allow running directly from a source checkout without installing the package
# pylint: disable=wrong-import-position
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from in_toto.exceptions import (
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.groupedthreshold import VerificationReport
from in_toto.models._signer import (
    load_crypto_signer_from_pkcs8_file,
    load_public_key_from_file,
)
from in_toto.models.layout import (
    THRESHOLD_MODE_GROUPED,
    THRESHOLD_MODE_STRICT,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.verifylib import in_toto_verify

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PEMS = os.path.join(REPO_ROOT, "tests", "pems")

HASH_FOO_V1 = {"sha256": "1" * 64}
HASH_FOO_V2 = {"sha256": "2" * 64}
HASH_TAR = {"sha256": "3" * 64}


def heading(text):
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def load_keys():
    keys = {}
    for name in ("rsa", "ecdsa", "ed25519"):
        keys[name] = load_crypto_signer_from_pkcs8_file(
            os.path.join(PEMS, "{}_private_unencrypted.pem".format(name))
        )
        keys[name + "_pub"] = load_public_key_from_file(
            os.path.join(PEMS, "{}_public.pem".format(name))
        )
    return keys


def write_link(workdir, step, signer, materials=None, products=None):
    """Create and dump a signed link metadata file."""
    metadata = Metablock(
        signed=Link(
            name=step, materials=materials or {}, products=products or {}
        )
    )
    metadata.create_signature(signer)
    path = os.path.join(
        workdir,
        FILENAME_FORMAT.format(step_name=step, keyid=signer.public_key.keyid),
    )
    metadata.dump(path)


def build_layout(mode, keys):
    functionary_ids = [
        keys["rsa_pub"]["keyid"],
        keys["ecdsa_pub"]["keyid"],
        keys["ed25519_pub"]["keyid"],
    ]
    return Layout(
        threshold_mode=mode,
        keys={
            keys["rsa_pub"]["keyid"]: keys["rsa_pub"],
            keys["ecdsa_pub"]["keyid"]: keys["ecdsa_pub"],
            keys["ed25519_pub"]["keyid"]: keys["ed25519_pub"],
        },
        steps=[
            Step(
                name="write-code",
                pubkeys=functionary_ids,
                threshold=2,
                expected_products=[
                    ["CREATE", "foo"],
                    ["DISALLOW", "*"],
                ],
            ),
            Step(
                name="package",
                pubkeys=functionary_ids,
                threshold=2,
                expected_materials=[
                    [
                        "MATCH",
                        "foo",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "write-code",
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


def write_conflicting_links(workdir, keys, package_v2_for=()):
    """Write threshold-2 links with a dissenting third result per step."""
    alice, bob, carl = keys["rsa"], keys["ecdsa"], keys["ed25519"]

    write_link(workdir, "write-code", alice, products={"foo": HASH_FOO_V1})
    write_link(workdir, "write-code", bob, products={"foo": HASH_FOO_V1})
    write_link(workdir, "write-code", carl, products={"foo": HASH_FOO_V2})

    bob_package_hash = HASH_FOO_V2 if "bob" in package_v2_for else HASH_FOO_V1
    write_link(
        workdir,
        "package",
        alice,
        materials={"foo": HASH_FOO_V1},
        products={"tar.gz": HASH_TAR},
    )
    write_link(
        workdir,
        "package",
        bob,
        materials={"foo": bob_package_hash},
        products={"tar.gz": HASH_TAR},
    )
    write_link(
        workdir,
        "package",
        carl,
        materials={"foo": HASH_FOO_V2},
        products={"tar.gz": HASH_TAR},
    )


def scenario_serialization(workdir, keys, owner):
    """Scenarios 1 and 2: wire format and signature protection."""
    heading("1. Legacy strict layout serialization is unchanged")
    strict_layout = build_layout(THRESHOLD_MODE_STRICT, keys)
    strict_mb = Metablock(signed=strict_layout)
    strict_mb.create_signature(owner)
    strict_path = os.path.join(workdir, "strict.layout")
    strict_mb.dump(strict_path)
    with open(strict_path, encoding="utf-8") as file_obj:
        on_disk = json.load(file_obj)
    print(
        "threshold_mode present in strict layout payload? {}".format(
            "threshold_mode" in on_disk["signed"]
        )
    )
    reloaded = Metablock.load(strict_path)
    print(
        "Signable bytes identical after reload? {}".format(
            reloaded.signed.signable_bytes == strict_layout.signable_bytes
        )
    )

    heading("2. Changing the mode invalidates the existing signature")
    tampered = Metablock.load(strict_path)
    tampered.signed.threshold_mode = THRESHOLD_MODE_GROUPED
    try:
        tampered.verify_signature(keys["rsa_pub"])
    except SignatureVerificationError:
        print("Old strict-mode signature does NOT verify the grouped payload.")
    grouped_mb = Metablock(signed=build_layout(THRESHOLD_MODE_GROUPED, keys))
    grouped_mb.create_signature(owner)
    grouped_mb.verify_signature(keys["rsa_pub"])
    print("A newly signed grouped layout verifies with the owner key.")


def scenario_conflict(case_dir, keys, owner):
    """Scenario 3: conflicting links under strict and grouped modes."""
    heading("3. Conflicting links: strict fails, grouped passes with a proof")
    os.makedirs(case_dir)
    write_conflicting_links(case_dir, keys)
    owner_pub = keys["rsa_pub"]

    cwd = os.getcwd()
    os.chdir(case_dir)
    try:
        strict_again = Metablock(
            signed=build_layout(THRESHOLD_MODE_STRICT, keys)
        )
        strict_again.create_signature(owner)
        try:
            in_toto_verify(
                strict_again,
                {owner_pub["keyid"]: owner_pub},
                persist_inspection_links=False,
            )
        except ThresholdVerificationError as error:
            print("Strict mode rejects: {}".format(error))

        grouped = Metablock(signed=build_layout(THRESHOLD_MODE_GROUPED, keys))
        grouped.create_signature(owner)
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        summary = in_toto_verify(
            grouped,
            {owner_pub["keyid"]: owner_pub},
            persist_inspection_links=False,
            verification_report=report,
        )
        print("Grouped mode passes. Search report:")
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        print("Summary link products: {}".format(summary.products))
    finally:
        os.chdir(cwd)


def scenario_no_solution(bad_dir, keys, owner):
    """Scenario 4: local quorums without a chain-wide solution."""
    heading("4. Locally sufficient, globally unsolvable -> fail, no inspection")
    os.makedirs(bad_dir)
    # Bob's package link switches to v2, so the only threshold group of
    # "package" consumes v2 while the only threshold group of "write-code"
    # produces v1: the MATCH rule cannot hold on any single selection.
    write_conflicting_links(bad_dir, keys, package_v2_for=("bob",))
    owner_pub = keys["rsa_pub"]

    cwd = os.getcwd()
    os.chdir(bad_dir)
    try:
        grouped = Metablock(signed=build_layout(THRESHOLD_MODE_GROUPED, keys))
        grouped.create_signature(owner)
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        try:
            in_toto_verify(
                grouped,
                {owner_pub["keyid"]: owner_pub},
                persist_inspection_links=False,
                verification_report=report,
            )
        except ThresholdVerificationError as error:
            print("Grouped mode rejects: {}".format(error))
        print(
            "Inspections executed during failed search: {}".format(
                report.inspection_executions
            )
        )
        print("Proof produced on failure: {}".format(report.proof))
    finally:
        os.chdir(cwd)


def scenario_order_independence(case_dir, order_dir, keys, owner):
    """Scenario 5: reordering link files leaves the result unchanged."""
    heading("5. Link presentation order does not change the result")
    shutil.copytree(case_dir, order_dir, dirs_exist_ok=True)
    links = sorted(f for f in os.listdir(order_dir) if f.endswith(".link"))
    moved = os.path.join(order_dir, "_reordered")
    os.makedirs(moved)
    for filename in reversed(links):
        shutil.move(
            os.path.join(order_dir, filename),
            os.path.join(moved, filename),
        )
    for filename in os.listdir(moved):
        shutil.move(
            os.path.join(moved, filename), os.path.join(order_dir, filename)
        )
    os.rmdir(moved)

    owner_pub = keys["rsa_pub"]
    cwd = os.getcwd()
    os.chdir(order_dir)
    try:
        grouped = Metablock(signed=build_layout(THRESHOLD_MODE_GROUPED, keys))
        grouped.create_signature(owner)
        report = VerificationReport(THRESHOLD_MODE_GROUPED)
        in_toto_verify(
            grouped,
            {owner_pub["keyid"]: owner_pub},
            persist_inspection_links=False,
            verification_report=report,
        )
        print(
            "Selected write-code supporters: {}".format(
                sorted(report.proof.get_supporters("write-code"))
            )
        )
        print(
            "Selected package supporters: {}".format(
                sorted(report.proof.get_supporters("package"))
            )
        )
        print("Verification result after reordering: PASS")
    finally:
        os.chdir(cwd)


def main():
    """Run all demo scenarios in an isolated temporary directory."""
    keys = load_keys()
    owner = keys["rsa"]
    workdir = tempfile.mkdtemp(prefix="in-toto-grouped-demo-")
    print("Working directory: {}".format(workdir))

    scenario_serialization(workdir, keys, owner)
    scenario_conflict(os.path.join(workdir, "case-conflict"), keys, owner)
    scenario_no_solution(os.path.join(workdir, "case-no-solution"), keys, owner)
    scenario_order_independence(
        os.path.join(workdir, "case-conflict"),
        os.path.join(workdir, "case-order"),
        keys,
        owner,
    )

    print("\nDemo finished. Artifacts kept in: {}".format(workdir))


if __name__ == "__main__":
    main()
