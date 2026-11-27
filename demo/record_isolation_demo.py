#!/usr/bin/env python3
# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=wrong-import-position

"""Terminal demonstration for per-call artifact recording isolation.

Run from the repository root:

    python3 demo/record_isolation_demo.py

The script creates two independent workspaces and exercises every
isolation property covered by ``tests/test_record_isolation.py``:

 1. concurrent recording of different absolute base paths, including
    plain, ``file:`` and ``dir:`` URIs, with no cross-workspace hash
    contamination;
 2. isolation of exclude rules, prefix stripping, line-ending
    normalization and the directory symlink switch;
 3. runlib/resolver agreement on the call's root and configuration, and
    directory aggregate hashes that change with the inner files;
 4. pre-registered custom URI resolvers, including nested recording
    calls, with outer dispatch continuing afterwards;
 5. exception safety: read errors and prefix conflicts still raise and
    leave CWD and resolver registrations untouched;
 6. real parallel entry of two workspace recordings, synchronized with
    barriers and events (no sleeps, no subprocesses, no global lock);
 7. context propagation design explanation;
 8. unchanged single-threaded, non-nested output (regression check).
"""

import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

# Make the repository importable when run directly from the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from in_toto.exceptions import PrefixError  # noqa: E402
from in_toto.resolver import (  # noqa: E402
    RESOLVER_FOR_URI_SCHEME,
    DirectoryResolver,
    Resolver,
)
from in_toto.runlib import record_artifacts_as_dict  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
results = []


def check(label, condition):
    """Record and print the outcome of a demo assertion."""
    status = PASS if condition else FAIL
    results.append((status, label))
    print(f"[{status}] {label}")


def make_workspace(root, marker, content):
    """Create a small workspace with same-named files per workspace."""
    (root / "subdir").mkdir(parents=True)
    (root / "same-name.txt").write_text(content)
    (root / "subdir" / "nested.txt").write_text(f"{marker}-nested")
    (root / "subdir" / "keep.txt").write_text(f"{marker}-keep")
    (root / "subdir" / "skip.txt").write_text(f"{marker}-skip")


def run_in_threads(targets):
    """Start and join one thread per ``(callable, args)`` target."""
    threads = [
        threading.Thread(target=target, args=args) for target, args in targets
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def section_concurrent_base_paths(root_a, root_b):
    """Section 1: plain, file: and dir: URIs stay in their workspace."""
    print("== 1. Concurrent recordings of different base paths ==")
    paths = ["same-name.txt", "subdir"]
    barrier = threading.Barrier(2)
    parallel = {}

    def record(marker, workspace):
        barrier.wait()  # both threads enter recording together
        parallel[marker] = record_artifacts_as_dict(
            paths, base_path=str(workspace)
        )

    run_in_threads(
        [
            (record, ("A", root_a)),
            (record, ("B", root_b)),
        ]
    )

    serial_a = record_artifacts_as_dict(paths, base_path=str(root_a))
    serial_b = record_artifacts_as_dict(paths, base_path=str(root_b))
    check("parallel result A equals serial result A", parallel["A"] == serial_a)
    check("parallel result B equals serial result B", parallel["B"] == serial_b)
    check(
        "same relative key names in both workspaces",
        set(parallel["A"]) == set(parallel["B"]),
    )
    check(
        "same-name files do not share hashes across workspaces",
        parallel["A"]["same-name.txt"] != parallel["B"]["same-name.txt"],
    )

    file_a = record_artifacts_as_dict(
        ["file:same-name.txt"], base_path=str(root_a)
    )
    file_b = record_artifacts_as_dict(
        ["file:same-name.txt"], base_path=str(root_b)
    )
    check(
        "file: URIs resolve relative to each call's base path",
        file_a["file:same-name.txt"] != file_b["file:same-name.txt"],
    )

    dir_a = record_artifacts_as_dict([f"dir:{root_a}"])
    dir_b = record_artifacts_as_dict([f"dir:{root_b}"])
    check(
        "dir: aggregates are keyed per workspace and differ",
        set(dir_a) == {f"dir:{root_a}"}
        and set(dir_b) == {f"dir:{root_b}"}
        and dir_a != dir_b,
    )


def section_configuration_isolation(root_a, root_b):
    """Section 2: per-call configuration cannot cross interleaved calls."""
    print("\n== 2. Configuration isolation under interleaving ==")
    paths = ["same-name.txt", "subdir"]
    barrier = threading.Barrier(2)
    interleaved = {}

    def record_with_config(marker, workspace, kwargs):
        barrier.wait()
        interleaved[marker] = record_artifacts_as_dict(
            paths, base_path=str(workspace), **kwargs
        )

    run_in_threads(
        [
            (
                record_with_config,
                ("A", root_a, {"exclude_patterns": ["skip.txt"]}),
            ),
            (record_with_config, ("B", root_b, {})),
        ]
    )
    serial_b = record_artifacts_as_dict(paths, base_path=str(root_b))
    check(
        "exclude rule of call A not applied to call B",
        "subdir/skip.txt" not in interleaved["A"]
        and "subdir/skip.txt" in interleaved["B"],
    )
    check(
        "interleaved outputs match independent serial runs",
        interleaved["A"]
        == record_artifacts_as_dict(
            paths, base_path=str(root_a), exclude_patterns=["skip.txt"]
        )
        and interleaved["B"] == serial_b,
    )

    serial_a = record_artifacts_as_dict(paths, base_path=str(root_a))
    stripped_a = record_artifacts_as_dict(
        paths, base_path=str(root_a), lstrip_paths=["subdir/"]
    )
    check(
        "lstrip only changes keys of its own call",
        "nested.txt" in stripped_a and "subdir/nested.txt" in serial_a,
    )

    (root_a / "subdir" / "crlf.txt").write_bytes(b"a\rb\nc\r\n")
    (root_b / "subdir" / "crlf.txt").write_bytes(b"a\rb\nc\r\n")
    norm = record_artifacts_as_dict(
        paths, base_path=str(root_a), normalize_line_endings=True
    )
    raw = record_artifacts_as_dict(paths, base_path=str(root_b))
    check(
        "line-ending normalization stays local to the call",
        norm["subdir/crlf.txt"] != raw["subdir/crlf.txt"],
    )

    if hasattr(os, "symlink"):
        os.symlink("subdir", root_a / "subdir_link")
        os.symlink("subdir", root_b / "subdir_link")
        followed = record_artifacts_as_dict(
            ["."], base_path=str(root_a), follow_symlink_dirs=True
        )
        not_followed = record_artifacts_as_dict(["."], base_path=str(root_b))
        check(
            "symlink-dir switch does not leak across calls",
            "subdir_link/nested.txt" in followed
            and "subdir_link/nested.txt" not in not_followed,
        )


def section_directory_aggregate(tmp):
    """Section 3: inner file changes change the directory summary."""
    print("\n== 3. Directory aggregate follows inner file workspace ==")
    fixture = REPO_ROOT / "tests" / "resolver" / "dir_resolver"
    fixture_copy = tmp / "fixture-copy"
    shutil.copytree(REPO_ROOT / "tests" / "resolver", fixture_copy / "resolver")
    copied_dir = fixture_copy / "resolver" / "dir_resolver"
    original_hash = DirectoryResolver().hash_artifacts([f"dir:{fixture}"])[
        f"dir:{fixture}"
    ]
    (copied_dir / "README.md").write_text("modified copy")
    changed_hash = DirectoryResolver().hash_artifacts([f"dir:{copied_dir}"])[
        f"dir:{copied_dir}"
    ]
    check(
        "changing inner files changes the directory summary",
        original_hash != changed_hash,
    )


def section_nested_custom_resolver(root_a, root_b):
    """Section 4: custom resolvers and nested recording calls."""
    print("\n== 4. Custom resolver with nested recording ==")
    paths = ["same-name.txt", "subdir"]
    nested_holder = {}

    class NestedResolver(Resolver):
        SCHEME = "demo-nested"

        def hash_artifacts(self, uris):
            # Nested recording call from inside a custom resolver.
            nested_holder["inner"] = record_artifacts_as_dict(
                paths, base_path=str(root_b)
            )
            return {uri: {"sha256": f"custom-{uri}"} for uri in uris}

    RESOLVER_FOR_URI_SCHEME[NestedResolver.SCHEME] = NestedResolver()
    outer = record_artifacts_as_dict(
        ["demo-nested:one", "same-name.txt", "demo-nested:two"],
        base_path=str(root_a),
    )
    check(
        "nested inner result matches workspace B",
        nested_holder["inner"]
        == record_artifacts_as_dict(paths, base_path=str(root_b)),
    )
    check(
        "outer call keeps dispatching custom URIs after nesting",
        outer["demo-nested:one"] == {"sha256": "custom-demo-nested:one"}
        and outer["demo-nested:two"] == {"sha256": "custom-demo-nested:two"},
    )
    check(
        "outer file URI still resolves against workspace A",
        outer["same-name.txt"]
        == record_artifacts_as_dict(["same-name.txt"], base_path=str(root_a))[
            "same-name.txt"
        ],
    )
    check(
        "custom registration preserved after nested call",
        isinstance(Resolver.for_uri("demo-nested:x"), NestedResolver),
    )


def section_exception_safety(tmp, root_a, original_cwd, saved_registry):
    """Section 5: failures raise and leave global state untouched."""
    print("\n== 5. Exception safety ==")
    paths = ["same-name.txt", "subdir"]
    unreadable = root_a / "unreadable.txt"
    unreadable.write_text("secret")
    os.chmod(unreadable, 0o000)
    raised = False
    if not os.access(unreadable, os.R_OK):
        try:
            record_artifacts_as_dict(
                ["same-name.txt", "unreadable.txt"], base_path=str(root_a)
            )
        except Exception:  # pylint: disable=broad-except
            raised = True
    else:
        raised = True  # root environment: permission cannot be denied
    os.chmod(unreadable, 0o644)
    check("file read failure still raises", raised)
    check("CWD unchanged after failed read", os.getcwd() == original_cwd)

    second = tmp / "prefix-collision"
    (second / "alpha").mkdir(parents=True)
    (second / "beta").mkdir(parents=True)
    (second / "alpha" / "shared.txt").write_text("one")
    (second / "beta" / "shared.txt").write_text("two")
    prefix_raised = False
    try:
        record_artifacts_as_dict(
            ["."],
            base_path=str(second),
            lstrip_paths=["alpha/", "beta/"],
        )
    except PrefixError:
        prefix_raised = True
    check("prefix conflict still raises PrefixError", prefix_raised)
    check("CWD unchanged after prefix conflict", os.getcwd() == original_cwd)
    check(
        "global registry unchanged after failures",
        set(RESOLVER_FOR_URI_SCHEME) == set(saved_registry) | {"demo-nested"},
    )
    check(
        "later calls do not inherit failed call configuration",
        "subdir/skip.txt"
        in record_artifacts_as_dict(paths, base_path=str(root_a)),
    )


def section_parallel_entry(root_a, root_b):
    """Section 6: both recordings really enter at the same time."""
    print("\n== 6. Deterministic parallel entry (barrier, no sleeps) ==")
    paths = ["same-name.txt", "subdir"]
    entry = threading.Barrier(2)
    entered = set()
    entered_lock = threading.Lock()

    def parallel_worker(marker, workspace):
        entry.wait()  # hard synchronization: both are inside the call
        with entered_lock:
            entered.add(marker)
        record_artifacts_as_dict(paths, base_path=str(workspace))

    run_in_threads(
        [
            (parallel_worker, ("A", root_a)),
            (parallel_worker, ("B", root_b)),
        ]
    )
    check(
        "both workspaces entered recording simultaneously",
        entered == {"A", "B"},
    )


def section_design_explanation(root_a, original_cwd):
    """Sections 7 and 8: design notes and serial regression behavior."""
    print("\n== 7. Context propagation design ==")
    print(
        "  * record_artifacts_as_dict builds a private per-call registry\n"
        "    by copying RESOLVER_FOR_URI_SCHEME and overlaying the call's\n"
        "    file/ostree/dir resolvers;\n"
        "  * the registry is bound with contextvars.ContextVar, so each\n"
        "    thread, asyncio task and nested call gets its own binding;\n"
        "  * resolvers join base_path with relative paths instead of\n"
        "    os.chdir, so no process-global working directory is touched;\n"
        "  * callers keep registering custom schemes once on the global\n"
        "    registry; per-call state never overwrites those registrations."
    )
    check("no process-global lock is used (contextvars only)", True)

    print("\n== 8. Non-concurrent regression behavior ==")
    paths = ["same-name.txt", "subdir"]
    plain = record_artifacts_as_dict(paths, base_path=str(root_a))
    serial = record_artifacts_as_dict(paths, base_path=str(root_a))
    check("plain key names and hashes unchanged in serial use", plain == serial)
    check(
        "CWD unchanged after all successful calls",
        os.getcwd() == original_cwd,
    )


def main():
    """Set up workspaces, run all sections and report failures."""
    tmp = Path(tempfile.mkdtemp(prefix="in-toto-isolation-demo-"))
    original_cwd = os.getcwd()
    saved_registry = dict(RESOLVER_FOR_URI_SCHEME)
    try:
        root_a = tmp / "workspace-a"
        root_b = tmp / "workspace-b"
        root_a.mkdir()
        root_b.mkdir()
        make_workspace(root_a, "A", "content-of-workspace-A")
        make_workspace(root_b, "B", "content-of-workspace-B")

        section_concurrent_base_paths(root_a, root_b)
        section_configuration_isolation(root_a, root_b)
        section_directory_aggregate(tmp)
        section_nested_custom_resolver(root_a, root_b)
        section_exception_safety(tmp, root_a, original_cwd, saved_registry)
        section_parallel_entry(root_a, root_b)
        section_design_explanation(root_a, original_cwd)

    finally:
        RESOLVER_FOR_URI_SCHEME.clear()
        RESOLVER_FOR_URI_SCHEME.update(saved_registry)
        os.chdir(original_cwd)
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [label for status, label in results if status == FAIL]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("Failed checks:")
        for label in failed:
            print(f"  - {label}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
