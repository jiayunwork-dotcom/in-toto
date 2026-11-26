# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  ruleengine.py

<Purpose>
  Artifact rule execution engine for in-toto verification.

  The individual rule verifiers (MATCH, CREATE, DELETE, MODIFY, ALLOW,
  DISALLOW, REQUIRE), the queue-based ``verify_item_rules`` driver and the
  ``RULE_TRACE`` error-trace state live in this dependency-light module so
  that both ``verifylib`` (traditional strict verification) and
  ``groupedthreshold`` (grouped threshold search) can evaluate rules without
  introducing an import cycle. ``verifylib`` re-exports every public name
  defined here for backward compatibility.
"""

import fnmatch
import logging
import os

import securesystemslib.exceptions

import in_toto.rulelib
from in_toto.exceptions import RuleVerificationError

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

RULE_TRACE = {}


def verify_match_rule(rule_data, artifacts_queue, source_artifacts, links):
    """
    <Purpose>
      Filters artifacts from artifact queue using rule pattern and optional rule
      source prefix and consumes them if there is a corresponding destination
      artifact, filtered using the same rule pattern and an optional rule
      destination prefix, and source and destination artifacts have matching
      hashes.

      NOTE: The destination artifacts are extracted from the links dictionary,
      using destination name and destination type from the rule data. The source
      artifacts could also be extracted from the links dictionary, but would
      require the caller to pass source name and source type, as those are not
      encoded in the rule. However, we choose to let the caller directly pass the
      relevant artifacts.


    <Arguments>
      rule_data:
              An unpacked "MATCH" rule (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).


      source_artifacts:
              All artifacts of the source item (including hashes).

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    consumed = set()

    # The rule can only consume artifacts if the destination link exists
    dest_link = links.get(rule_data["dest_name"])
    if not dest_link:
        return consumed

    # Extract destination artifacts from destination link
    dest_artifacts = getattr(dest_link, rule_data["dest_type"])

    # Filter part 1 - Filter artifacts using optional source prefix, and subtract
    # prefix before filtering with rule pattern (see filter part 2) to prevent
    # globbing in the prefix.
    if rule_data["source_prefix"]:
        filtered_source_paths = []
        # Add trailing slash to source prefix if it does not exist
        normalized_source_prefix = os.path.join(
            rule_data["source_prefix"], ""
        ).replace("\\", "/")

        for artifact_path in artifacts_queue:
            if artifact_path.startswith(normalized_source_prefix):
                filtered_source_paths.append(
                    artifact_path[len(normalized_source_prefix) :]
                )

    else:
        filtered_source_paths = artifacts_queue

    # Filter part 2 - glob above filtered artifact paths
    filtered_source_paths = fnmatch.filter(
        filtered_source_paths, rule_data["pattern"]
    )

    # Iterate over filtered source paths and try to match the corresponding
    # source artifact hash with the corresponding destination artifact hash
    for path in filtered_source_paths:
        # If a source prefix was specified, we subtracted the prefix above before
        # globbing. We have to re-prepend the prefix in order to retrieve the
        # corresponding source artifact below.
        if rule_data["source_prefix"]:
            full_source_path = os.path.join(
                rule_data["source_prefix"], path
            ).replace("\\", "/")

        else:
            full_source_path = path

        # If a destination prefix was specified, the destination artifact should
        # be queried with the full destination path, i.e. the prefix joined with
        # the globbed path.
        if rule_data["dest_prefix"]:
            full_dest_path = os.path.join(
                rule_data["dest_prefix"], path
            ).replace("\\", "/")

        else:
            full_dest_path = path

        # Extract source artifact hash dict
        # We know the source artifact is available, it is also in the queue
        source_artifact = source_artifacts[full_source_path]

        # Don't consume source artifact w/o corresponding dest artifact (by path)
        try:
            dest_artifact = dest_artifacts[full_dest_path]
        except KeyError:
            continue

        # Don't consume source artifact w/o corresponding dest artifact (by hash)
        if source_artifact != dest_artifact:
            continue

        # Source and destination matched, consume artifact
        consumed.add(full_source_path)

    return consumed


def verify_create_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are not in the materials set but are in the products set, i.e.
      were created.

    <Arguments>
      rule_pattern:
              A "CREATE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are products but not materials
    consumed = set(filtered_artifacts) & (products - materials)

    return consumed


def verify_delete_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in the materials set but are not in the products set, i.e.
      were deleted.

    <Arguments>
      rule_pattern:
              A "DELETE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are materials but not products
    consumed = set(filtered_artifacts) & (materials - products)

    return consumed


def verify_modify_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in both the materials dict and in the products doct, but have
      different hashes, i.e. were modified.

    <Arguments>
      rule_pattern:
              A "MODIFY" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (including hashes).

      products:
              All products of an item (including hashes).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Filter filtered artifacts that are materials and products
    filtered_artifacts = (
        set(filtered_artifacts) & set(materials.keys()) & set(products.keys())
    )

    # Consume filtered artifacts that have different hashes
    consumed = set()
    for path in filtered_artifacts:
        if materials[path] != products[path]:
            consumed.add(path)

    return consumed


def verify_allow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Consumes artifacts, filtered from the artifacts queue using rule pattern.

    <Arguments>
      rule_pattern:
              An "ALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume all filtered artifacts
    return set(filtered_artifacts)


def verify_disallow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if rule pattern applies to any artifacts in
      the queue.

      NOTE: Each set of rules should have a terminal DISALLOW rule to make
      overall verification fail in case preceding rules did not consume all
      artifacts as intended.

    <Arguments>
      rule_pattern:
              A "DISALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError
          if the rule pattern filters artifacts in the artifact queue.

    <Side Effects>
      None.

    <Returns>
      None.

    """
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    if filtered_artifacts:
        raise RuleVerificationError(
            "'DISALLOW {}' matched the following "
            "artifacts: {}\n{}".format(
                rule_pattern, filtered_artifacts, _get_artifact_rule_traceback()
            )
        )


def verify_require_rule(filename, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if the filename provided does not exist in the
      artifacts_queue

    <Arguments>
      filename:
              A single filename (see issues #193 and #152). We will ignore the
              artifact rule pattern because it's ambiguous and instead treat it
              as a literal file name.

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError:
        if the filename is not present in the artifacts queue

    <Side Effects>
      None.

    <Returns>
      None.

    """
    if filename not in artifacts_queue:
        raise RuleVerificationError(
            "'REQUIRE {filename}' did not find {filename} "
            "in: {queue}\n{traceback}".format(
                filename=filename,
                queue=artifacts_queue,
                traceback=_get_artifact_rule_traceback(),
            )
        )


def _get_artifact_rule_traceback():
    """Build and return string form global `RULE_TRACE` which may be used as
    error message for RuleVerificationError.

    """
    traceback_str = "Full trace for 'expected_{0}' of item '{1}':\n".format(
        RULE_TRACE["source_type"], RULE_TRACE["source_name"]
    )

    # Show all materials and products available in the beginning and
    # label the one that is used to generate a queue.
    for source_type in ["materials", "products"]:
        traceback_str += "Available {}{}:\n{}\n".format(
            source_type,
            [" (used for queue)", ""][RULE_TRACE["source_type"] != source_type],
            RULE_TRACE[source_type],
        )

    for trace_entry in RULE_TRACE["trace"]:
        traceback_str += "Queue after '{0}':\n".format(
            " ".join(trace_entry["rule"])
        )
        traceback_str += "{}\n".format(trace_entry["queue"])

    return traceback_str


def verify_item_rules(source_name, source_type, rules, links):
    """
    <Purpose>
      Apply all passed material or product rules (see source_type) of a given
      step or inspection (see source_name), to enforce and authorize the
      corresponding artifacts and to guarantee that artifacts are linked together
      across steps of the supply chain.

      The mode of operation is similar to that of a firewall:
      In the beginning all materials or products of the step or inspection are
      placed into an artifact queue. The rules are then applied sequentially,
      consuming artifacts in the queue, i.e. removing them from the queue upon
      successful application.

      The consumption of artifacts by itself has no effects on the verification.
      Only through a subsequent "DISALLOW" rule, that finds unconsumed artifacts,
      is an exception raised. Similarly does the "REQUIRE" rule raise exception,
      if it does not find the artifact it requires, because it has falsely been
      consumed or was not there from the beginning.



    <Arguments>
      source_name:
              The name of the item (step or inspection) being verified.

      source_type:
              One of "materials" or "products" depending on whether the rules are
              taken from the "expected_materials" or "expected_products" field of
              the item being verified.

      rules:
              The list of rules (material or product rules) for the item being
              verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      FormatError
          if source_type is not "materials" or "products", or
          if a rule in the passed list of rules does not conform with any rule
          format.

      RuleVerificationError
          if a DISALLOW rule matches disallowed artifacts, or
          if a REQUIRE rule does not find a required artifact.

    <Side Effects>
      Clears and populates the global RULE_TRACE data structure.

    """
    if source_type not in ["materials", "products"]:
        raise securesystemslib.exceptions.FormatError(
            "Argument 'source_type' of function 'verify_item_rules' has to be "
            "one of 'materials' or 'products'. Got: '{}'".format(source_type)
        )

    # Create shortcuts to item's materials and products (including hashes),
    # required to verify "modify" and "match" rules.
    materials_dict = links[source_name].materials
    products_dict = links[source_name].products

    # All other rules only require materials or products paths (without hashes)
    materials_paths = set(materials_dict.keys())
    products_paths = set(products_dict.keys())

    # Depending on the source type we create the artifact queue from the item's
    # materials or products and use it to keep track of (not) consumed artifacts.
    # The queue also only contains aritfact keys (without hashes)
    artifacts = getattr(links[source_name], source_type)
    artifacts_queue = set(artifacts.keys())

    # Reset and re-populate rule traceback info dict for a rich error message
    RULE_TRACE.clear()
    RULE_TRACE["source_name"] = source_name
    RULE_TRACE["source_type"] = source_type
    RULE_TRACE["materials"] = list(materials_dict)
    RULE_TRACE["products"] = list(products_dict)
    RULE_TRACE["trace"] = []

    # Process rules and remove consumed items from queue in each iteration
    for rule in rules:
        LOG.info("Verifying '%s'...", " ".join(rule))

        # Parse the rule and create two shortcuts to contained rule data
        rule_data = in_toto.rulelib.unpack_rule(rule)
        _type = rule_data["rule_type"]
        pattern = rule_data["pattern"]

        # Initialize empty consumed set as fallback for rules that do not consume
        # artifacts. All rules except "disallow" and "require" consume artifacts.
        consumed = set()

        if _type == "match":
            consumed = verify_match_rule(
                rule_data, artifacts_queue, artifacts, links
            )

        elif _type == "create":
            consumed = verify_create_rule(
                pattern, artifacts_queue, materials_paths, products_paths
            )

        elif _type == "delete":
            consumed = verify_delete_rule(
                pattern, artifacts_queue, materials_paths, products_paths
            )

        elif _type == "modify":
            consumed = verify_modify_rule(
                pattern, artifacts_queue, materials_dict, products_dict
            )

        elif _type == "allow":
            consumed = verify_allow_rule(pattern, artifacts_queue)

        # It's up to the "disallow" and "require" rule to raise an error if
        # artifacts were not consumed as intended
        elif _type == "disallow":
            verify_disallow_rule(pattern, artifacts_queue)

        elif _type == "require":
            verify_require_rule(pattern, artifacts_queue)

        else:  # pragma: no cover (unreachable)
            raise securesystemslib.exceptions.FormatError(
                "Invaldid rule type '{}'.".format(_type)
            )

        artifacts_queue -= consumed

        # Append rule and copy of queue to global info for a rich error message
        RULE_TRACE["trace"].append(
            {"rule": rule, "queue": list(artifacts_queue)}
        )


def verify_all_item_rules(items, links):
    """
    <Purpose>
      Iteratively verifies artifact rules of passed items (Steps or Inspections).

    <Arguments>
      items:
              A list containing Step or Inspection objects whose material
              and product rules will be verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    """
    for item in items:
        LOG.info("Verifying material rules for '%s'...", item.name)
        verify_item_rules(
            item.name, "materials", item.expected_materials, links
        )

        LOG.info("Verifying product rules for '%s'...", item.name)
        verify_item_rules(item.name, "products", item.expected_products, links)
