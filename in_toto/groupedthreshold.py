# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  groupedthreshold.py

<Purpose>
  Implements the optional ``grouped`` threshold verification mode, which a
  supply chain owner can select in the layout (see
  ``in_toto.models.layout.THRESHOLD_MODE_GROUPED``).

  In the default ``strict`` mode all links counted towards a step's threshold
  must report identical materials and products, and verification fails
  otherwise. The grouped mode tolerates conflicting link results:

  1.  Per step, links that passed the existing signature and authorization
      checks are partitioned into *candidate groups*. Two links belong to the
      same group if their materials and products mappings are exactly equal.
      A group is eligible only if the number of *distinct main keys* backing
      it reaches the step's ``threshold``. As in strict mode, links signed by
      different subkeys of the same main key are deduplicated and counted
      only once.

  2.  Exactly one eligible group is selected per step. All material and
      product artifact rules of all steps must hold on the *same* selection.
      In particular, a cross-step MATCH rule constrains the groups of the
      source and destination steps simultaneously, so the verifier cannot
      swap groups between rules.

  3.  The selection problem is solved by backtracking over the per-step
      candidate groups in layout order. A candidate that fails an artifact
      rule whose referenced destination steps are all already selected prunes
      the branch; rules referencing not-yet-selected steps are deferred. A
      complete assignment is accepted only if every step rule passes on the
      full assignment. This guarantees completeness: a locally sufficient but
      globally incompatible group never causes another, globally consistent
      solution to be missed.

  Search and storage costs
  ------------------------
  With ``S`` steps and at most ``G`` eligible groups per step, the worst case
  number of complete assignments explored is ``O(G ** S)``; each assignment
  evaluation re-runs the artifact rules, which are linear in the number of
  artifacts per link. MATCH cycles are handled naturally because rules that
  reach not-yet-selected steps are deferred until all involved steps are
  assigned, at which point the cycle is checked on the complete assignment.
  Typical layouts have few distinct artifact reports per step (small ``G``),
  so the practical cost is close to one rule pass. The produced proof only
  stores the selected representative link plus the supporting keyids per
  step; unselected links are never copied into it.
"""

import json
import logging

import in_toto.ruleengine
import in_toto.rulelib
from in_toto.exceptions import RuleVerificationError, ThresholdVerificationError

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)


class LinkGroup:
    """A candidate group of links reporting identical artifacts for a step.

    Attributes:
      step_name: Name of the layout step the group belongs to.
      link: The representative :class:`~in_toto.models.link.Link` object of
          the group. Every link in the group has the same materials and
          products, so the representative fully determines artifact rule
          behavior.
      link_keyids: Ordered list of keyids of the links in the group, i.e. the
          actual signing (sub)keys, one entry per link file.
      main_keyids: Ordered list of distinct main keyids backing the group.
          Subkeys of the same main key are deduplicated, mirroring the
          threshold counting semantics of the strict mode.
    """

    def __init__(self, step_name, link, link_keyids, main_keyids):
        self.step_name = step_name
        self.link = link
        self.link_keyids = link_keyids
        self.main_keyids = main_keyids

    @property
    def support_count(self):
        """Number of distinct main keys supporting this group."""
        return len(self.main_keyids)

    def __repr__(self):
        return "LinkGroup(step='{}', supporters={}, link_keyids={})".format(
            self.step_name, self.main_keyids, self.link_keyids
        )


class GroupedThresholdProof:
    """Queryable evidence for a successful grouped threshold verification.

    The proof records exactly one selected :class:`LinkGroup` per step and
    never contains links from unselected candidate groups.
    """

    def __init__(self, groups):
        # Mapping step name -> selected LinkGroup
        self._groups = dict(groups)

    def get_step_names(self):
        """Return the names of the steps covered by the proof."""
        return list(self._groups.keys())

    def get_selected_group(self, step_name):
        """Return the selected :class:`LinkGroup` for a step."""
        return self._groups[step_name]

    def get_selected_link(self, step_name):
        """Return the representative selected link for a step."""
        return self._groups[step_name].link

    def get_supporters(self, step_name):
        """Return the distinct main keyids supporting the selected group."""
        return list(self._groups[step_name].main_keyids)

    def get_materials(self, step_name):
        """Return the materials recorded by the step's selected link."""
        return self._groups[step_name].link.materials

    def get_products(self, step_name):
        """Return the products recorded by the step's selected link."""
        return self._groups[step_name].link.products

    def to_dict(self):
        """Return a JSON-serializable representation of the proof.

        Only selected artifacts and their supporters are included; links from
        other, unselected candidate groups are not part of the proof.
        """
        return {
            step_name: {
                "materials": group.link.materials,
                "products": group.link.products,
                "supporter_keyids": group.main_keyids,
                "link_keyids": group.link_keyids,
            }
            for step_name, group in self._groups.items()
        }

    def __repr__(self):
        return "GroupedThresholdProof({})".format(self.to_dict())


class VerificationReport:
    """Optional observability object populated during ``in_toto_verify``.

    Attributes:
      threshold_mode: The threshold mode of the verified layout.
      candidate_groups: Mapping step name -> number of eligible candidate
          groups found for that step.
      assignments_evaluated: Number of complete group assignments on which
          all step artifact rules were evaluated during the search.
      rule_evaluations: Number of per-step rule evaluation calls performed
          during the search (including evaluations on partial assignments).
      selected_groups: Mapping step name -> selected :class:`LinkGroup`.
      inspection_executions: Number of inspection commands executed. In
          grouped mode inspections are never executed while searching, so
          this is either zero (search failed) or equal to the number of
          inspections declared in the layout (search succeeded).
      proof: The :class:`GroupedThresholdProof` of a successful verification,
          or ``None``.
    """

    def __init__(self, threshold_mode):
        self.threshold_mode = threshold_mode
        self.candidate_groups = {}
        self.assignments_evaluated = 0
        self.rule_evaluations = 0
        self.selected_groups = {}
        self.inspection_executions = 0
        self.proof = None

    def to_dict(self):
        """Return a JSON-serializable snapshot of the report."""
        data = {
            "threshold_mode": self.threshold_mode,
            "candidate_groups": dict(self.candidate_groups),
            "assignments_evaluated": self.assignments_evaluated,
            "rule_evaluations": self.rule_evaluations,
            "inspection_executions": self.inspection_executions,
            "selected_groups": {
                step_name: {
                    "supporter_keyids": group.main_keyids,
                    "link_keyids": group.link_keyids,
                }
                for step_name, group in self.selected_groups.items()
            },
        }
        if self.proof is not None:
            data["proof"] = self.proof.to_dict()
        return data


def _build_main_key_for_subkeys(layout):
    """Return mapping subkey keyid -> main key object, as in strict checks."""
    main_keys_for_subkeys = {}
    for main_key in list(layout.keys.values()):
        for sub_keyid in main_key.get("subkeys", []):
            main_keys_for_subkeys[sub_keyid] = main_key
    return main_keys_for_subkeys


def _main_keyid_for_link_keyid(link_keyid, main_keys_for_subkeys):
    """Return the main keyid that counts for a link's signing keyid.

    A link signed by an authorized subkey counts towards the main key that
    delegates to the subkey; a link signed by a main key counts towards that
    main key. This mirrors the authorization/deduplication logic in
    ``verifylib.verify_link_signature_thresholds``.
    """
    main_key = main_keys_for_subkeys.get(link_keyid)
    if main_key is not None:
        return main_key["keyid"]
    return link_keyid


def group_verified_links(layout, chain_link_dict):
    """Partition verified links per step into threshold-eligible groups.

    Arguments:
      layout: The :class:`~in_toto.models.layout.Layout` defining the steps.
      chain_link_dict: Mapping step name -> mapping link keyid ->
          :class:`~in_toto.models.link.Link`, as produced by
          ``verifylib.verify_sublayouts``. Only links that passed the existing
          signature and authorization checks are present.

    Raises:
      ThresholdVerificationError: If a step has no candidate group backed by
          at least ``step.threshold`` distinct main keys.

    Returns:
      A mapping step name -> ordered list of eligible :class:`LinkGroup`
      objects. Groups are sorted by the canonical representation of their
      materials/products so that verification results are independent of link
      file ordering.
    """
    main_keys_for_subkeys = _build_main_key_for_subkeys(layout)
    candidates_per_step = {}

    for step in layout.steps:
        # Group key: exact materials and products mappings
        groups = {}

        for link_keyid, link in chain_link_dict.get(step.name, {}).items():
            # Exact materials/products equality defines a group. Canonical
            # JSON makes the grouping independent of dict insertion order.
            group_key = (
                json.dumps(link.materials, sort_keys=True),
                json.dumps(link.products, sort_keys=True),
            )
            group = groups.get(group_key)
            if group is None:
                group = LinkGroup(
                    step.name,
                    link,
                    link_keyids=[],
                    main_keyids=[],
                )
                groups[group_key] = group

            group.link_keyids.append(link_keyid)
            main_keyid = _main_keyid_for_link_keyid(
                link_keyid, main_keys_for_subkeys
            )
            if main_keyid not in group.main_keyids:
                group.main_keyids.append(main_keyid)

        eligible = [
            group
            for group in groups.values()
            if group.support_count >= step.threshold
        ]

        if not eligible:
            raise ThresholdVerificationError(
                "Step '{}' has no group of links with identical materials and"
                " products supported by at least '{}' distinct authorized"
                " functionaries (threshold).".format(step.name, step.threshold)
            )

        # Deterministic, link-order-independent candidate ordering
        eligible.sort(
            key=lambda group: (
                json.dumps(group.link.materials, sort_keys=True),
                json.dumps(group.link.products, sort_keys=True),
            )
        )
        candidates_per_step[step.name] = eligible

    return candidates_per_step


def _links_from_selection(selection):
    """Build the step-name -> Link mapping expected by the rule verifier."""
    return {step_name: group.link for step_name, group in selection.items()}


def _match_rule_dest_names(step):
    """Return the set of step names referenced by MATCH rules of a step."""
    dest_names = set()
    for rules in (step.expected_materials, step.expected_products):
        for rule in rules:
            rule_data = in_toto.rulelib.unpack_rule(rule)
            if rule_data["rule_type"] == "match":
                dest_names.add(rule_data["dest_name"])
    return dest_names


def _step_rules_pass(step, links):
    """Evaluate material and product rules of one step on given links."""
    in_toto.ruleengine.verify_item_rules(
        step.name, "materials", step.expected_materials, links
    )
    in_toto.ruleengine.verify_item_rules(
        step.name, "products", step.expected_products, links
    )


def solve_grouped_threshold(
    layout,
    chain_link_dict,
    report=None,
    assignment_callback=None,
):
    """Search for one eligible group per step satisfying all step rules.

    Arguments:
      layout: The layout, expected to use the grouped threshold mode.
      chain_link_dict: Verified links per step and keyid (see
          :func:`group_verified_links`).
      report: Optional :class:`VerificationReport` to populate with search
          counters.
      assignment_callback: Optional callable invoked with the mapping
          step name -> :class:`LinkGroup` for every complete assignment
          evaluated. Useful for tests that need to count search attempts.

    Raises:
      ThresholdVerificationError: No eligible group exists for a step, or no
          combination of eligible groups satisfies all artifact rules.
      RuleVerificationError: Propagated from the artifact rule verifier for
          the failing complete assignment.

    Returns:
      A mapping step name -> selected :class:`LinkGroup`.
    """
    candidates_per_step = group_verified_links(layout, chain_link_dict)

    if report is not None:
        for step_name, groups in candidates_per_step.items():
            report.candidate_groups[step_name] = len(groups)

    steps = list(layout.steps)
    selection = {}
    # Remember the first rule error per step for a useful final message
    failures = {}

    def backtrack(index):
        if index == len(steps):
            # Complete assignment: verify every step rule on the same
            # selection. Nothing may be deferred at this point.
            links = _links_from_selection(selection)
            if report is not None:
                report.assignments_evaluated += 1
            if assignment_callback is not None:
                assignment_callback(dict(selection))
            for step in steps:
                if report is not None:
                    report.rule_evaluations += 1
                _step_rules_pass(step, links)
            return True

        step = steps[index]
        deferred_dests = _match_rule_dest_names(step)
        links = _links_from_selection(selection)

        for group in candidates_per_step[step.name]:
            selection[step.name] = group
            partial_links = dict(links)
            partial_links[step.name] = group.link

            # Evaluate rules whose referenced destinations are already
            # selected (including self references). Rules pointing to
            # not-yet-selected steps must wait, because their result depends
            # on a group choice that has not been made.
            can_prune = False
            if not deferred_dests.difference(selection.keys()):
                try:
                    if report is not None:
                        report.rule_evaluations += 1
                    _step_rules_pass(step, partial_links)
                except RuleVerificationError as error:
                    can_prune = True
                    failures.setdefault(step.name, str(error))

            if not can_prune and backtrack(index + 1):
                return True

        selection.pop(step.name, None)
        return False

    if backtrack(0):
        return dict(selection)

    details = ""
    if failures:
        details = " First unresolved rule failures: {}".format(
            " | ".join(
                "step '{}': {}".format(step_name, error)
                for step_name, error in sorted(failures.items())
            )
        )

    raise ThresholdVerificationError(
        "No combination of threshold-satisfying link groups satisfies all"
        " step artifact rules on a single chain-wide selection.{}".format(
            details
        )
    )
