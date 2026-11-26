Grouped Threshold Verification
==============================

By default, in-toto's threshold check requires every link counted towards a
step's threshold to report identical materials and products. If a quorum of
functionaries reports one result and another functionary reports a different
result, verification fails.

A supply chain owner can opt into an alternative **grouped** threshold mode by
setting the layout's ``threshold_mode`` field to ``"grouped"``:

.. code-block:: python

   from in_toto.models.layout import Layout, THRESHOLD_MODE_GROUPED

   layout = Layout(threshold_mode=THRESHOLD_MODE_GROUPED)

The field is part of the signed layout payload:

* The default mode (``"strict"``) is implicit and is **not** serialized, so
  existing layouts keep their exact signable bytes and signatures.
* Switching an existing layout to ``"grouped"`` changes its canonical
  representation and therefore requires a fresh layout signature. A verifier
  cannot enable or relax the mode with a local parameter.

How grouped verification works
------------------------------

For every step, links that passed the existing signature and authorization
checks are partitioned into candidate groups. Two links belong to the same
group only if their materials and products mappings are exactly equal. A
group is eligible when it is backed by at least the step's ``threshold``
distinct main keys. As in strict mode, links signed by different subkeys of
the same main key are deduplicated and count only once.

Exactly one eligible group is selected per step. All material and product
artifact rules of all steps, including cross-step ``MATCH`` rules with path
prefixes and the queue-based rule consumption semantics, must hold on the
same selection. A backtracking search over the per-step candidate groups
guarantees completeness: a candidate that locally looks sufficient but is
incompatible with the rest of the chain causes backtracking instead of
failure, and neither the largest nor the first candidate is preferred. If no
combination satisfies all rules, verification fails.

Inspection commands are executed only after a consistent selection is found.
The successful verification produces a queryable proof that records the
selected artifacts and their supporting keyids per step; links belonging to
unselected groups never enter the proof or the summary link.

Search and storage costs
------------------------

With ``S`` steps and at most ``G`` eligible groups per step, at most
``O(G ** S)`` complete assignments are explored, and each artifact rule pass
is linear in the number of involved artifacts. Rules referencing
not-yet-selected steps are deferred, and rules whose destinations are already
assigned are evaluated early to prune incompatible branches; ``MATCH`` cycles
are resolved on the complete assignment. The proof stores one representative
link plus the supporting keyids per step. Typical layouts have few distinct
artifact reports per step, so the practical cost is close to a single
ordinary rule pass.

A runnable example lives in ``demo/grouped-threshold/``.

API
---

.. automodule:: in_toto.groupedthreshold
  :members:
  :special-members:
