# Grouped Threshold Verification Demo

This demo shows the optional `grouped` threshold verification mode, which a
supply chain owner can declare in a signed layout.

## What it demonstrates

1. **Legacy layouts are untouched.** A layout without the new field keeps its
   exact signable bytes; the default `strict` mode is never written to the
   payload, so existing signatures remain valid.
2. **The mode is part of the signed payload.** Changing a layout from strict
   to grouped changes its canonical bytes and invalidates the old signature.
   The verifier cannot relax the rules with a local parameter.
3. **Conflicting results may coexist.** Three functionaries submit two
   different results for each of two steps. Strict verification rejects the
   disagreement; grouped verification partitions the links into candidate
   groups, requires `threshold` distinct main keys per selected group, and
   prints a proof listing only the selected artifacts and their supporters.
4. **A chain-wide solution is required.** Every step can locally have enough
   supporters while no group combination satisfies the cross-step `MATCH`
   rule. Verification then fails, no inspection command runs, and no proof is
   produced.
5. **Order independence.** Reversing the order in which the link files are
   presented does not change the selected groups or the outcome.

## Running

From the repository root:

```shell
python3 demo/grouped-threshold/grouped_threshold_demo.py
```

The script signs all metadata with the keys in `tests/pems` and writes every
generated file into a fresh temporary directory, whose path is printed at the
start and end of the run.

## Search and storage costs

For `S` steps with at most `G` eligible candidate groups per step, the
backtracking search explores at most `O(G ** S)` complete assignments, and
each rule pass is linear in the number of artifacts of the involved links.
Rules that reference not-yet-selected steps are deferred, and rules whose
destinations are already assigned are evaluated early to prune incompatible
branches. `MATCH` cycles are therefore resolved on the complete assignment
without any special casing. The stored proof contains one representative
link and the supporting keyids per step; links of unselected groups are never
copied into it.

Typical layouts report very few distinct artifact sets per step (small `G`),
so the practical cost is close to a single ordinary rule pass.
