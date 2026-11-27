#!/usr/bin/env python
# coding=utf-8

# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-call isolation of artifact recording.

The tests in this module assert that interleaved, nested and failing calls
to ``record_artifacts_as_dict`` cannot leak resolver configuration, working
directory or resolver registrations into each other.

The concurrency tests use threads with explicit synchronization
(``threading.Barrier`` and ``threading.Event``) instead of sleeps, so that
the interleavings they cover are deterministic.
"""

import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from securesystemslib.exceptions import StorageError
from securesystemslib.hash import digest_filename

from in_toto.exceptions import PrefixError
from in_toto.resolver import (
    RESOLVER_FOR_URI_SCHEME,
    DirectoryResolver,
    FileResolver,
    Resolver,
    resolver_registry,
)
from in_toto.runlib import record_artifacts_as_dict

RESOLVER_FIXTURES = Path(__file__).parent / "resolver"
DIR_RESOLVER_FIXTURE = RESOLVER_FIXTURES / "dir_resolver"


def _copy_fixture(destination):
    """Copy the repository ``tests/resolver`` fixtures into ``destination``.

    The concurrency tests operate on private fixture copies, so the files
    shipped with the repository are never modified.
    """
    shutil.copytree(RESOLVER_FIXTURES, destination / "resolver")
    return destination / "resolver"


def _sha256_file(path):
    return digest_filename(path, algorithm="sha256").hexdigest()


class _Workspace:
    """Temporary workspace directory with a few files to record."""

    def __init__(self, root, marker, file_content):
        self.root = Path(root)
        (self.root / "subdir").mkdir(parents=True)
        # Same relative name in every workspace, but distinct contents: this
        # is what makes cross-workstate hash contamination observable.
        self.same_name = "same-name.txt"
        (self.root / self.same_name).write_text(file_content)
        (self.root / "subdir" / "nested.txt").write_text(f"{marker}-nested")
        (self.root / "subdir" / "keep.txt").write_text(f"{marker}-keep")
        (self.root / "subdir" / "skip.txt").write_text(f"{marker}-skip")

    def paths(self):
        return [self.same_name, "subdir"]


class IsolationTestCase(unittest.TestCase):
    """Base test case creating two independent temporary workspaces."""

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.tmpdir = tempfile.mkdtemp()
        self.workspace_a = Path(self.tmpdir) / "workspace-a"
        self.workspace_b = Path(self.tmpdir) / "workspace-b"
        self.workspace_a.mkdir()
        self.workspace_b.mkdir()
        self.ws_a = _Workspace(self.workspace_a, "A", "content-of-workspace-A")
        self.ws_b = _Workspace(self.workspace_b, "B", "content-of-workspace-B")
        self._saved_registry = dict(RESOLVER_FOR_URI_SCHEME)

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        # Restore the process-global registry in case a test modified it.
        RESOLVER_FOR_URI_SCHEME.clear()
        RESOLVER_FOR_URI_SCHEME.update(self._saved_registry)

    def _record_a(self, **kwargs):
        return record_artifacts_as_dict(
            self.ws_a.paths(), base_path=str(self.workspace_a), **kwargs
        )

    def _record_b(self, **kwargs):
        return record_artifacts_as_dict(
            self.ws_b.paths(), base_path=str(self.workspace_b), **kwargs
        )

    def _expected_workspace_result(self, workspace):
        """Compute the expected hashes directly from the workspace files."""
        expected = {}
        for relative in [
            workspace.same_name,
            "subdir/nested.txt",
            "subdir/keep.txt",
            "subdir/skip.txt",
        ]:
            fs_path = workspace.root / relative
            expected[relative.replace("\\", "/")] = {
                "sha256": _sha256_file(str(fs_path))
            }
        return expected


class TestWorkspaceIsolation(IsolationTestCase):
    """Plain paths, ``file:`` and ``dir:`` stay within their workspace."""

    def test_same_relative_name_different_hashes(self):
        """Same-named files in different workspaces hash to different values."""
        result_a = self._record_a()
        result_b = self._record_b()

        self.assertEqual(result_a.keys(), result_b.keys())
        self.assertNotEqual(
            result_a[self.ws_a.same_name], result_b[self.ws_b.same_name]
        )
        self.assertEqual(result_a, self._expected_workspace_result(self.ws_a))
        self.assertEqual(result_b, self._expected_workspace_result(self.ws_b))

    def test_file_scheme_relative_to_each_base_path(self):
        """``file:`` URIs resolve against the call's own base path."""
        result_a = record_artifacts_as_dict(
            [f"file:{self.ws_a.same_name}"], base_path=str(self.workspace_a)
        )
        result_b = record_artifacts_as_dict(
            [f"file:{self.ws_b.same_name}"], base_path=str(self.workspace_b)
        )

        self.assertEqual(
            result_a,
            {
                f"file:{self.ws_a.same_name}": {
                    "sha256": _sha256_file(
                        str(self.workspace_a / self.ws_a.same_name)
                    )
                }
            },
        )
        self.assertNotEqual(
            result_a[f"file:{self.ws_a.same_name}"],
            result_b[f"file:{self.ws_b.same_name}"],
        )

    def test_dir_scheme_uses_repository_fixture_copies(self):
        """Directory aggregates over private copies of the repo fixtures."""
        fixture_copy_root = Path(self.tmpdir) / "fixture-copies"
        fixture_copy_root.mkdir()
        fixtures_a = _copy_fixture(fixture_copy_root / "copy-a")
        fixtures_b = _copy_fixture(fixture_copy_root / "copy-b")

        dir_a = fixtures_a / "dir_resolver"
        dir_b = fixtures_b / "dir_resolver"

        # Modify one copy only: the aggregate hashes must diverge.
        (dir_b / "README.md").write_text("changed content in copy B")

        result_a = DirectoryResolver().hash_artifacts([f"dir:{dir_a}"])
        result_b = DirectoryResolver().hash_artifacts([f"dir:{dir_b}"])

        key_a = f"dir:{dir_a}"
        key_b = f"dir:{dir_b}"
        self.assertEqual(set(result_a), {key_a})
        self.assertEqual(set(result_b), {key_b})
        self.assertNotEqual(result_a[key_a], result_b[key_b])

        # The untouched copy still matches the repository fixture.
        repo_result = DirectoryResolver().hash_artifacts(
            [f"dir:{DIR_RESOLVER_FIXTURE}"]
        )
        self.assertEqual(
            result_a[key_a],
            repo_result[f"dir:{DIR_RESOLVER_FIXTURE}"],
        )

    def test_dir_scheme_inner_files_change_aggregate(self):
        """Replacing the inner file workspace changes the directory hash."""
        original = DirectoryResolver(
            normalize_line_endings=True
        ).hash_artifacts([f"dir:{DIR_RESOLVER_FIXTURE}"])
        original_hash = original[f"dir:{DIR_RESOLVER_FIXTURE}"]["sha256"]

        copy_root = Path(self.tmpdir) / "dir-copy"
        fixtures = _copy_fixture(copy_root)
        copied_dir = fixtures / "dir_resolver"
        (copied_dir / "subdir" / "0.txt").write_text("different bytes")

        changed = DirectoryResolver(normalize_line_endings=True).hash_artifacts(
            [f"dir:{copied_dir}"]
        )
        changed_hash = changed[f"dir:{copied_dir}"]["sha256"]

        self.assertNotEqual(original_hash, changed_hash)


class TestConcurrentIsolation(IsolationTestCase):
    """Interleaved calls in threads must equal serial calls with same args."""

    def _run_interleaved(self, kwargs_a, kwargs_b, barrier=None):
        """Run recordings for both workspaces concurrently in two threads."""
        results = {}
        errors = []

        def worker(workspace, record_kwargs, bucket):
            try:
                if barrier is not None:
                    # Both threads enter recording before either proceeds.
                    barrier.wait()
                results[bucket] = record_artifacts_as_dict(
                    workspace.paths(),
                    base_path=str(workspace.root),
                    **record_kwargs,
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                # pragma: no cover - assertion aid
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(self.ws_a, kwargs_a, "a")),
            threading.Thread(target=worker, args=(self.ws_b, kwargs_b, "b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        return results["a"], results["b"]

    def test_concurrent_plain_paths_no_hash_crosstalk(self):
        """Two workspaces hash at the same time without mixing summaries."""
        barrier = threading.Barrier(2)
        result_a, result_b = self._run_interleaved({}, {}, barrier=barrier)

        self.assertEqual(result_a, self._expected_workspace_result(self.ws_a))
        self.assertEqual(result_b, self._expected_workspace_result(self.ws_b))

    def test_concurrent_configuration_isolation(self):
        """Excludes, lstrip, line-ending and symlink flags do not cross calls."""
        # Workspace A excludes skip.txt, workspace B keeps everything.
        kwargs_a = {"exclude_patterns": ["skip.txt"]}
        kwargs_b = {}
        barrier = threading.Barrier(2)
        result_a, result_b = self._run_interleaved(
            kwargs_a, kwargs_b, barrier=barrier
        )

        self.assertNotIn("subdir/skip.txt", result_a)
        self.assertIn("subdir/skip.txt", result_b)
        # The exclude pattern of A must not have been applied to B.
        self.assertEqual(result_b, self._expected_workspace_result(self.ws_b))

        # Serial runs with the same arguments produce identical results.
        serial_a = self._record_a(**kwargs_a)
        serial_b = self._record_b(**kwargs_b)
        self.assertEqual(result_a, serial_a)
        self.assertEqual(result_b, serial_b)

    def test_concurrent_lstrip_isolation(self):
        """Prefix stripping of one call does not alter the other's keys."""
        kwargs_a = {"lstrip_paths": ["subdir/"]}
        kwargs_b = {"lstrip_paths": ["subdir/"]}
        barrier = threading.Barrier(2)
        result_a, result_b = self._run_interleaved(
            kwargs_a, kwargs_b, barrier=barrier
        )

        expected_a = self._record_a(**kwargs_a)
        expected_b = self._record_b(**kwargs_b)
        self.assertEqual(result_a, expected_a)
        self.assertEqual(result_b, expected_b)
        self.assertIn("nested.txt", result_a)
        self.assertIn("nested.txt", result_b)

    def test_concurrent_normalize_line_endings_isolation(self):
        """Line-ending normalization of one call stays local to that call."""
        # Add a file with CRLF line endings to both workspaces.
        for workspace in (self.ws_a, self.ws_b):
            (workspace.root / "subdir" / "crlf.txt").write_bytes(b"a\rb\nc\r\n")

        kwargs_a = {"normalize_line_endings": True}
        kwargs_b = {"normalize_line_endings": False}
        barrier = threading.Barrier(2)
        result_a, result_b = self._run_interleaved(
            kwargs_a, kwargs_b, barrier=barrier
        )

        self.assertEqual(result_a, self._record_a(**kwargs_a))
        self.assertEqual(result_b, self._record_b(**kwargs_b))
        self.assertNotEqual(
            result_a["subdir/crlf.txt"], result_b["subdir/crlf.txt"]
        )

    @unittest.skipIf(
        not hasattr(os, "symlink"), "symlink is not supported on this platform"
    )
    def test_concurrent_follow_symlink_dirs_isolation(self):
        """The symlinked-directory switch only affects its own call."""
        for workspace in (self.ws_a, self.ws_b):
            # A linked directory next to a regular directory; descent into
            # it is gated by ``follow_symlink_dirs`` when walking the root.
            os.symlink(
                "subdir",
                os.path.join(workspace.root, "subdir_link"),
            )

        kwargs_a = {
            "follow_symlink_dirs": True,
        }
        kwargs_b = {
            "follow_symlink_dirs": False,
        }
        # Walking the workspace root makes the top-level linked directory
        # subject to ``follow_symlink_dirs``.
        barrier = threading.Barrier(2)
        results = {}
        errors = []

        def worker(workspace, kwargs, bucket):
            try:
                barrier.wait()
                results[bucket] = record_artifacts_as_dict(
                    ["."], base_path=str(workspace.root), **kwargs
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                # pragma: no cover
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(self.ws_a, kwargs_a, "a")),
            threading.Thread(target=worker, args=(self.ws_b, kwargs_b, "b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        result_a, result_b = results["a"], results["b"]

        self.assertEqual(
            result_a,
            record_artifacts_as_dict(
                ["."], base_path=str(self.workspace_a), **kwargs_a
            ),
        )
        self.assertEqual(
            result_b,
            record_artifacts_as_dict(
                ["."], base_path=str(self.workspace_b), **kwargs_b
            ),
        )
        self.assertIn("subdir_link/nested.txt", result_a)
        self.assertNotIn("subdir_link/nested.txt", result_b)

    def test_concurrent_file_and_dir_schemes(self):
        """Mixed scheme calls in parallel keep per-workspace identities."""
        barrier = threading.Barrier(2)
        results = {}
        errors = []

        def record_file():
            try:
                barrier.wait()
                results["file"] = record_artifacts_as_dict(
                    [f"file:{self.ws_a.same_name}"],
                    base_path=str(self.workspace_a),
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                # pragma: no cover - assertion aid
                errors.append(exc)

        def record_dir():
            try:
                barrier.wait()
                results["dir"] = record_artifacts_as_dict(
                    [
                        f"dir:{self.workspace_b}",
                    ],
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                # pragma: no cover - assertion aid
                errors.append(exc)

        threads = [
            threading.Thread(target=record_file),
            threading.Thread(target=record_dir),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(
            results["file"][f"file:{self.ws_a.same_name}"]["sha256"],
            _sha256_file(str(self.workspace_a / self.ws_a.same_name)),
        )
        self.assertEqual(set(results["dir"]), {f"dir:{self.workspace_b}"})


class TestNestedAndCustomResolver(IsolationTestCase):
    """Pre-registered custom resolvers and nested recording calls."""

    def test_pre_registered_custom_resolver_remains_available(self):
        """Custom scheme resolvers survive recording calls."""

        class CustomResolver(Resolver):
            """Custom scheme resolver returning a fixed hash."""

            SCHEME = "custom-scheme"

            def hash_artifacts(self, uris):
                return {uri: {"sha256": "fixed"} for uri in uris}

        custom = CustomResolver()
        RESOLVER_FOR_URI_SCHEME[CustomResolver.SCHEME] = custom

        # A normal recording call must not remove the registration.
        self._record_a()
        self.assertIs(Resolver.for_uri("custom-scheme:something"), custom)

        # And artifacts using the custom scheme are dispatched to it.
        result = record_artifacts_as_dict(
            ["custom-scheme:artifact-1", "custom-scheme:artifact-2"]
        )
        self.assertEqual(
            result,
            {
                "custom-scheme:artifact-1": {"sha256": "fixed"},
                "custom-scheme:artifact-2": {"sha256": "fixed"},
            },
        )
        self.assertIs(Resolver.for_uri("custom-scheme:artifact-1"), custom)

    def test_nested_call_inside_custom_resolver(self):
        """Both inner and outer results are correct when nesting recording."""
        nested_results = {}
        workspace_b = self.workspace_b
        ws_b = self.ws_b

        class NestedResolver(Resolver):
            """Custom resolver that performs a nested recording call."""

            SCHEME = "nested-scheme"

            def hash_artifacts(self, uris):
                # The custom resolver itself records artifacts from a
                # different workspace while the outer recording is in flight.
                nested = record_artifacts_as_dict(
                    ws_b.paths(), base_path=str(workspace_b)
                )
                nested_results["inner"] = nested
                return {uri: {"sha256": f"nested-{uri}"} for uri in uris}

        resolver = NestedResolver()
        RESOLVER_FOR_URI_SCHEME[NestedResolver.SCHEME] = resolver

        outer = record_artifacts_as_dict(
            [
                "nested-scheme:one",
                self.ws_a.same_name,
                "nested-scheme:two",
            ],
            base_path=str(self.workspace_a),
        )

        self.assertEqual(
            nested_results["inner"],
            self._expected_workspace_result(self.ws_b),
        )
        # The outer call continues dispatching the remaining custom URIs
        # after the nested call returned.
        self.assertEqual(
            outer["nested-scheme:one"], {"sha256": "nested-nested-scheme:one"}
        )
        self.assertEqual(
            outer["nested-scheme:two"], {"sha256": "nested-nested-scheme:two"}
        )
        # The outer file URI was still resolved against the outer workspace.
        self.assertEqual(
            outer[self.ws_a.same_name]["sha256"],
            _sha256_file(str(self.workspace_a / self.ws_a.same_name)),
        )
        # The custom registration was not lost.
        self.assertIs(Resolver.for_uri("nested-scheme:x"), resolver)

    def test_nested_registry_restored_on_return(self):
        """Inner per-call registries do not leak into the outer context."""
        self_test = self
        probe_state = {}
        snapshot_scheme = "snapshot-scheme"

        class SnapshotResolver(Resolver):
            """Runs inside the nested call and observes its registry."""

            SCHEME = snapshot_scheme

            def hash_artifacts(self, uris):
                probe_state["inner_file"] = Resolver.for_uri("file:probe")
                nested = Resolver.for_uri(f"file:{self_test.ws_b.same_name}")
                probe_state["nested_base_path"] = (
                    nested._base_path  # pylint: disable=protected-access
                )
                return {uri: {"sha256": "snapshot"} for uri in uris}

        class ProbeResolver(Resolver):
            """Triggers a nested recording call from within an outer one."""

            SCHEME = "probe-scheme"

            def hash_artifacts(self, uris):
                probe_state["outer_file"] = Resolver.for_uri("file:probe")

                probe_state["nested_result"] = record_artifacts_as_dict(
                    ["snapshot-scheme:uri"],
                    base_path=str(self_test.workspace_b),
                )

                # After the nested context exits, dispatch here sees the
                # outer per-call registry again.
                probe_state["file_after_nested"] = Resolver.for_uri(
                    "file:probe"
                )
                return {uri: {"sha256": "ok"} for uri in uris}

        # Both custom resolvers are pre-registered globally: this also
        # verifies that registrations remain visible to nested calls.
        snapshot = SnapshotResolver()
        RESOLVER_FOR_URI_SCHEME[snapshot_scheme] = snapshot
        probe = ProbeResolver()
        RESOLVER_FOR_URI_SCHEME[ProbeResolver.SCHEME] = probe

        # The outer call runs against workspace A and dispatches the probe
        # URI to the custom resolver.
        result = record_artifacts_as_dict(
            ["probe-scheme:uri"], base_path=str(self.workspace_a)
        )

        self.assertEqual(result, {"probe-scheme:uri": {"sha256": "ok"}})
        self.assertIsNot(probe_state["inner_file"], probe_state["outer_file"])
        self.assertEqual(probe_state["nested_base_path"], str(self.workspace_b))
        self.assertEqual(
            probe_state["nested_result"],
            {"snapshot-scheme:uri": {"sha256": "snapshot"}},
        )
        self.assertIs(
            probe_state["file_after_nested"], probe_state["outer_file"]
        )
        # Back outside any recording context the global registry is used.
        self.assertIs(Resolver.for_uri("probe-scheme:uri"), probe)

    def test_resolver_registry_context_manager(self):
        """The context manager overlays, restores and isolates registries."""

        class ContextCustomResolver(Resolver):
            """Resolver only visible inside the context."""

            SCHEME = "context-scheme"

            def hash_artifacts(self, uris):
                return {uri: {"sha256": "context"} for uri in uris}

        class GlobalCustomResolver(Resolver):
            """Resolver pre-registered on the global registry."""

            SCHEME = "global-scheme"

            def hash_artifacts(self, uris):
                return {uri: {"sha256": "global"} for uri in uris}

        global_resolver = GlobalCustomResolver()
        RESOLVER_FOR_URI_SCHEME[GlobalCustomResolver.SCHEME] = global_resolver
        before = dict(RESOLVER_FOR_URI_SCHEME)

        file_resolver = FileResolver(base_path=str(self.workspace_a))
        with resolver_registry(
            {
                "file": file_resolver,
                ContextCustomResolver.SCHEME: ContextCustomResolver(),
            }
        ):
            # The overlay resolver wins for the file scheme.
            self.assertIs(Resolver.for_uri("file:x"), file_resolver)
            # Pre-registered global resolvers remain visible.
            self.assertIs(Resolver.for_uri("global-scheme:x"), global_resolver)
            self.assertIsInstance(
                Resolver.for_uri("context-scheme:x"),
                ContextCustomResolver,
            )

        # After the context exits the global registry is unchanged.
        self.assertEqual(RESOLVER_FOR_URI_SCHEME, before)
        # The context-only scheme is no longer registered and therefore
        # falls back to the default file scheme, which is also absent here.
        with self.assertRaises(KeyError):
            Resolver.for_uri("context-scheme:x")
        # The global registration is still intact.
        self.assertIs(Resolver.for_uri("global-scheme:x"), global_resolver)

    def test_resolver_registry_restored_on_exception(self):
        """An exception inside the context still restores the registry."""
        before = dict(RESOLVER_FOR_URI_SCHEME)
        with self.assertRaises(RuntimeError):
            with resolver_registry({"file": FileResolver()}):
                raise RuntimeError("boom")
        self.assertEqual(RESOLVER_FOR_URI_SCHEME, before)

    def test_resolver_registry_without_overlay(self):
        """A context without overlay resolvers copies the active registry."""

        class PlainGlobalResolver(Resolver):
            """Resolver registered on the global registry."""

            SCHEME = "plain-scheme"

            def hash_artifacts(self, uris):
                return {uri: {"sha256": "plain"} for uri in uris}

        plain = PlainGlobalResolver()
        RESOLVER_FOR_URI_SCHEME[PlainGlobalResolver.SCHEME] = plain
        before = dict(RESOLVER_FOR_URI_SCHEME)
        try:
            with resolver_registry():
                # No overlay was passed: global registrations are still
                # visible through the context-bound copy.
                self.assertIs(Resolver.for_uri("plain-scheme:x"), plain)
            self.assertEqual(RESOLVER_FOR_URI_SCHEME, before)
        finally:
            RESOLVER_FOR_URI_SCHEME.clear()
            RESOLVER_FOR_URI_SCHEME.update(before)


class TestFailureAndCleanup(IsolationTestCase):
    """Errors must not leave global state, CWD or registrations behind."""

    def test_cwd_restored_when_file_read_raises(self):
        """A failing hash leaves the working directory untouched."""
        unreadable = self.workspace_a / "unreadable.txt"
        unreadable.write_text("secret")
        os.chmod(unreadable, 0o000)
        try:
            if os.access(unreadable, os.R_OK):
                self.skipTest("running as root, read permission cannot fail")
            with self.assertRaises((PermissionError, StorageError)):
                record_artifacts_as_dict(
                    [self.ws_a.same_name, "unreadable.txt"],
                    base_path=str(self.workspace_a),
                )
        finally:
            os.chmod(unreadable, 0o644)

        self.assertEqual(os.getcwd(), self.original_cwd)
        # A later call still works and uses no stale configuration.
        self.assertEqual(
            self._record_a(), self._expected_workspace_result(self.ws_a)
        )

    def test_cwd_restored_when_prefix_conflict_raises(self):
        """PrefixError still raises and does not change CWD or registry."""
        # Two directories with files that collide on their mangled key once
        # each directory prefix is left-stripped.
        second_root = Path(self.tmpdir) / "second-root"
        second_root.mkdir()
        (second_root / "alpha").mkdir()
        (second_root / "beta").mkdir()
        (second_root / "alpha" / "shared.txt").write_text("one")
        (second_root / "beta" / "shared.txt").write_text("two")

        with self.assertRaises(PrefixError):
            record_artifacts_as_dict(
                ["."],
                base_path=str(second_root),
                lstrip_paths=["alpha/", "beta/"],
            )

        self.assertEqual(os.getcwd(), self.original_cwd)
        self.assertEqual(RESOLVER_FOR_URI_SCHEME, self._saved_registry)

    def test_registry_unchanged_after_failed_call(self):
        """Failed calls preserve pre-registered custom resolvers."""

        class MarkerResolver(Resolver):
            """Resolver that must never be invoked in this test."""

            SCHEME = "marker-scheme"

            def hash_artifacts(self, uris):  # pragma: no cover
                raise AssertionError("should not be called")

        marker = MarkerResolver()
        RESOLVER_FOR_URI_SCHEME[MarkerResolver.SCHEME] = marker

        with self.assertRaises((OSError, ValueError)):
            record_artifacts_as_dict(
                ["."], base_path=os.path.join(self.tmpdir, "does-not-exist")
            )

        self.assertEqual(set(RESOLVER_FOR_URI_SCHEME), {MarkerResolver.SCHEME})
        self.assertIs(Resolver.for_uri("marker-scheme:x"), marker)

        # A subsequent successful call keeps the custom resolver available
        # and does not inherit any configuration from the failed call.
        self.assertEqual(
            self._record_a(), self._expected_workspace_result(self.ws_a)
        )
        self.assertIs(Resolver.for_uri("marker-scheme:x"), marker)

    def test_failed_nested_call_restores_outer_registry(self):
        """An exception in a nested call restores the outer registry."""
        nested_error = {}

        class FailingNestedResolver(Resolver):
            """Resolver whose nested recording call is expected to fail."""

            SCHEME = "failing-scheme"

            def hash_artifacts(self, uris):
                try:
                    record_artifacts_as_dict(
                        ["."], base_path="/no/such/base/path"
                    )
                except (OSError, ValueError) as exc:
                    nested_error["exc"] = exc
                # Outer per-call registry is still intact here.
                return {uri: {"sha256": "outer"} for uri in uris}

        failing = FailingNestedResolver()
        RESOLVER_FOR_URI_SCHEME[FailingNestedResolver.SCHEME] = failing

        result = record_artifacts_as_dict(
            ["failing-scheme:uri"], base_path=str(self.workspace_a)
        )
        self.assertIn("exc", nested_error)
        self.assertEqual(result, {"failing-scheme:uri": {"sha256": "outer"}})
        self.assertIs(Resolver.for_uri("failing-scheme:uri"), failing)


class TestDeterministicInterleaving(IsolationTestCase):
    """Barrier-driven interleaving at the resolver dispatch boundary."""

    def test_dispatch_uses_per_call_resolvers_under_barrier(self):
        """Both calls pass the barrier while holding distinct resolvers."""
        dispatch_barrier = threading.Barrier(2)
        seen = {}
        seen_lock = threading.Lock()
        original_for_uri = Resolver.for_uri

        def probing_for_uri(uri):
            if uri in ("file:same-name.txt", "same-name.txt"):
                dispatch_barrier.wait()
                resolver = original_for_uri(uri)
                with seen_lock:
                    seen.setdefault(threading.current_thread().name, resolver)
                return resolver
            return original_for_uri(uri)

        Resolver.for_uri = staticmethod(probing_for_uri)
        try:
            threads = [
                threading.Thread(target=self._record_a, name="worker-A"),
                threading.Thread(target=self._record_b, name="worker-B"),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            Resolver.for_uri = original_for_uri

        # Two distinct FileResolver instances were active simultaneously.
        self.assertEqual(len(seen), 2)
        self.assertNotEqual(id(seen["worker-A"]), id(seen["worker-B"]))
        # And each call still produced its own workspace's hashes.
        self.assertEqual(
            self._record_a(), self._expected_workspace_result(self.ws_a)
        )
        self.assertEqual(
            self._record_b(), self._expected_workspace_result(self.ws_b)
        )


if __name__ == "__main__":
    unittest.main()
