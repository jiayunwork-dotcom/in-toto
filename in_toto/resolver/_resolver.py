# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Resolver interface and implementations for files, OSTree, and directory
artifacts.

Resolvers are looked up per artifact URI via a resolver registry. There are
two layers of registry:

* The process-global ``RESOLVER_FOR_URI_SCHEME`` dictionary lets callers
  pre-register custom URI scheme resolvers. It is only read, never mutated,
  while artifacts are recorded.
* Each call to ``in_toto.runlib.record_artifacts_as_dict`` runs inside a
  :class:`resolver_registry` context, which binds a *per-call* registry in a
  :class:`contextvars.ContextVar`. The per-call registry is a copy of the
  global registry with the call's configured ``file``, ``ostree`` and ``dir``
  resolvers overlaid.

Because the per-call registry and the resolver configuration live in a
context variable instead of in process-global state:

* concurrent calls in different threads (or asyncio tasks) cannot overwrite
  each other's resolvers, base paths or other configuration;
* nested calls, e.g. a custom resolver that itself records artifacts, push
  their own registry and restore the outer one when they return;
* the process-global registry, including custom scheme resolvers registered
  by the caller, is preserved across calls, including calls that fail.

The resolvers in this module additionally avoid changing the process
working directory: paths are resolved relative to a resolver's configured
``base_path`` instead. This makes interleaved calls with different
workspaces independent and guarantees that the working directory is
unchanged when a call returns or raises.
"""

import contextvars
import locale
import logging
import os
from abc import ABCMeta, abstractmethod
from contextlib import contextmanager
from functools import cmp_to_key
from itertools import combinations
from os.path import exists, isdir, isfile, join, normpath, relpath

from pathspec import GitIgnoreSpec
from securesystemslib.hash import digest, digest_filename

from in_toto.exceptions import PrefixError

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"

#: Process-global registry of resolver instances keyed by URI scheme.
#:
#: Callers may pre-register resolvers for custom URI schemes here. The
#: dictionary is never modified while artifacts are being recorded; per-call
#: configuration is kept in a separate, context-bound registry (see
#: :class:`resolver_registry` and :class:`Resolver`).
RESOLVER_FOR_URI_SCHEME = {}

# Context bound registry used while artifacts are recorded. A ``None`` value
# means that no recording context is active and the process-global registry
# is used. Context variables are natively isolated per thread and per nested
# ``contextvars.copy_context``/``asyncio`` task, so interleaved and nested
# calls never see each other's resolvers.
_CONTEXT_REGISTRY = contextvars.ContextVar(
    "in_toto_resolver_registry", default=None
)


def _current_registry():
    """Return the active resolver registry.

    The context-bound per-call registry takes precedence while a recording
    context is active; otherwise the process-global registry is returned.
    """
    registry = _CONTEXT_REGISTRY.get()
    if registry is None:
        return RESOLVER_FOR_URI_SCHEME
    return registry


@contextmanager
def resolver_registry(resolvers=None):
    """Bind a per-call resolver registry for the duration of a recording call.

    The new registry starts as a copy of the currently active registry (or
    the process-global :data:`RESOLVER_FOR_URI_SCHEME`), so custom scheme
    resolvers registered by the caller remain available. Passed ``resolvers``
    are overlaid on top of the copy.

    On exit, including when an exception is raised, the previously active
    registry is restored. Nested contexts are supported: an inner recording
    call (e.g. from within a custom resolver) does not affect the outer
    call's registry.

    The context is bound with :class:`contextvars.ContextVar`, which makes
    each thread and each nested context see its own registry without any
    process-global locking.
    """
    registry = dict(_current_registry())
    if resolvers:
        registry.update(resolvers)

    token = _CONTEXT_REGISTRY.set(registry)
    try:
        yield registry
    finally:
        _CONTEXT_REGISTRY.reset(token)


class Resolver(metaclass=ABCMeta):
    """Resolver interface and factory."""

    @classmethod
    def for_uri(cls, uri):
        """Return registered resolver instance for passed URI.

        Lookup uses the context-bound per-call registry when recording is in
        progress, and falls back to the process-global
        :data:`RESOLVER_FOR_URI_SCHEME` otherwise.
        """
        scheme, match, _ = uri.partition(":")

        registry = _current_registry()
        if not match or scheme not in registry:
            scheme = FileResolver.SCHEME

        return registry[scheme]

    @abstractmethod
    def hash_artifacts(self, uris):
        """Return hash dictionary for passed list of artifact URIs."""
        raise NotImplementedError


class FileResolver(Resolver):
    """File resolver implementation.

    Provides a ``hash_artifacts`` method to generate hashes for passed file
    paths. The resolver is configurable via its constructor.

    Paths are resolved relative to ``base_path`` without changing the
    process working directory, so resolver instances with different base
    paths can be used concurrently in the same process.

    """

    SCHEME = "file"

    def __init__(
        self,
        exclude_patterns=None,
        base_path=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
    ):
        if exclude_patterns is None:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        if base_path is not None:
            if not isinstance(base_path, str):
                raise ValueError("'base_path' must be string")
            # Preserve the failure that a working directory change used to
            # produce when the base path cannot be entered. Checking here
            # also fails early before any artifact is read, without touching
            # the process working directory.
            if not isdir(base_path):
                raise OSError(
                    f"[Errno 2] No such file or directory: '{base_path}'"
                )

        for name, val in [
            ("exclude_patterns", exclude_patterns),
            ("lstrip_paths", lstrip_paths),
        ]:
            if not isinstance(val, list) or not all(
                isinstance(i, str) for i in val
            ):
                raise ValueError(f"'{name}' must be list of strings")

        for a_, b_ in combinations(lstrip_paths, 2):
            if a_.startswith(b_) or b_.startswith(a_):
                raise PrefixError(
                    f"'{a_}' and '{b_}' triggered a left substring error"
                )

        # Compile gitignore-style patterns
        self._exclude_filter = GitIgnoreSpec.from_lines(
            "gitwildmatch", exclude_patterns
        )
        self._base_path = base_path
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths

    def _resolve(self, path):
        """Return filesystem path for ``path`` relative to the base path.

        The working directory is not changed. Relative paths are interpreted
        relative to this resolver's ``base_path`` (the current working
        directory if no base path is configured).
        """
        if self._base_path:
            return join(self._base_path, path)
        return path

    def _display_path(self, fs_path):
        """Return the artifact name for a resolved filesystem path.

        Reverses :meth:`_resolve` so that the base path never appears in the
        returned dictionary keys.
        """
        if self._base_path:
            return relpath(fs_path, self._base_path)
        return fs_path

    def _exclude(self, path):
        """Helper to check, if path matches pre-compiled exclude patterns."""
        return self._exclude_filter.match_file(path)

    def _hash(self, path):
        """Helper to generate hash dictionary for path."""
        digest_obj = digest_filename(
            path,
            algorithm=_HASH_ALGORITHM,
            normalize_line_endings=self._normalize_line_endings,
        )
        return {_HASH_ALGORITHM: digest_obj.hexdigest()}

    def _mangle(self, path, existing_paths, scheme_prefix):
        """Helper for path mangling."""

        # Normalize slashes for cross-platform metadata consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path) :]
                break

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        # Prepend passed scheme prefix
        path = scheme_prefix + path

        return path

    def _strip_scheme_prefix(self, path):
        """Helper to strip file resolver scheme prefix from path."""

        prefix = self.SCHEME + ":"
        if path.startswith(prefix):
            path = path[len(prefix) :]
        else:
            prefix = ""

        return path, prefix

    def hash_artifacts(self, uris):
        hashes = {}

        for path in uris:
            # Remove scheme prefix, but preserver to re-add later (see _mangle)
            path, prefix = self._strip_scheme_prefix(path)

            # Normalize URI before filtering and returning them
            # FIXME: Is this expected behavior? Does this make exclude patterns
            # with slashes platform-dependent? Check how 'gitwildmatch' treats
            # dots and slashes!
            path = normpath(path)

            if self._exclude(path):
                continue

            # Resolve relative to this resolver's base path. Unlike a working
            # directory change, this is local to the resolver instance and
            # therefore safe for interleaved calls with different workspaces.
            fs_path = self._resolve(path)

            if not exists(fs_path):
                logger.info("path: %s does not exist, skipping..", path)
                continue

            if isfile(fs_path):
                name = self._mangle(path, hashes, prefix)
                hashes[name] = self._hash(fs_path)

            if isdir(fs_path):
                for base, dirs, names in os.walk(
                    fs_path, followlinks=self._follow_symlink_dirs
                ):
                    # Filter directories to avoid unnecessary recursion below
                    # NOTE: Normalize to filter on directory paths without
                    # their dot-slash prefix, if path was dot.
                    dirs[:] = [
                        dirname
                        for dirname in dirs
                        if not self._exclude(
                            normpath(self._display_path(join(base, dirname)))
                        )
                    ]

                    for filename in names:
                        # NOTE: Normalize to filter on and return file paths
                        # without their dot-slash prefix, if path was dot.
                        fs_filepath = join(base, filename)
                        filepath = normpath(self._display_path(fs_filepath))

                        if self._exclude(filepath):
                            continue

                        if not isfile(fs_filepath):
                            logger.info(
                                "File '%s' appears to be a broken symlink. "
                                "Skipping...",
                                filepath,
                            )
                            continue

                        name = self._mangle(filepath, hashes, prefix)
                        hashes[name] = self._hash(fs_filepath)

        return hashes


class OSTreeResolver(Resolver):
    """Resolver for OSTree repositories."""

    SCHEME = "ostree"

    # defining this separately as it should be pinned to OSTree's default
    # rather than in-toto's
    _HASH_ALGORITHM = "sha256"

    def __init__(self, base_path=None):
        self._base_path = base_path

    def _strip_scheme_prefix(self, path):
        """Helper to strip OSTree resolver scheme prefix from path."""

        return path[len(self.SCHEME + ":") :]

    def _add_scheme_prefix(self, path):
        """Helper to add scheme back after recording the hash."""

        return f"{self.SCHEME}:{path}"

    def _resolve(self, path):
        """Return filesystem path relative to the base path, no chdir."""
        if self._base_path:
            return join(self._base_path, path)
        return path

    def _hash(self, path):
        """Helper to hash OSTree commits."""

        ref_path = self._resolve(join("refs", "heads", path))

        with open(ref_path, "r") as ref:  # pylint: disable=unspecified-encoding
            ref_contents = ref.read()
        ref_contents = ref_contents.strip("\n")

        object_path = self._resolve(
            join(
                "objects",
                ref_contents[:2],
                f"{ref_contents[2:]}.commit",
            )
        )

        digest_obj = digest_filename(
            object_path,
            algorithm=self._HASH_ALGORITHM,
        )

        return {self._HASH_ALGORITHM: digest_obj.hexdigest()}

    def hash_artifacts(self, uris):
        hashes = {}

        for path in uris:
            # Remove scheme prefix, but preserver to re-add later
            path = self._strip_scheme_prefix(path)
            hashes[self._add_scheme_prefix(path)] = self._hash(path)

        return hashes


class DirectoryResolver(Resolver):
    """Directory resolver implementation.

    Implementation of the following shell command for some directory URI:

    find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum |
        cut -f1 -d' '

    `exclude_patterns` are not applied on the directory paths passed to
    `hash_artifacts`, but on the files inside the directory. Similarly,
    `follow_symlink_dirs` and `normalize_line_endings` are used on
    subdirectories and files inside the directories passed to `hash_artifacts`.

    Directory URIs are resolved as given (relative to the process working
    directory when no base path is configured) and the inner file resolver
    receives the directory as its base path. No working directory change is
    performed, so multiple directory resolver calls with different roots can
    run concurrently in the same process.

    """

    SCHEME = "dir"

    def __init__(
        self,
        exclude_patterns=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
    ):
        if not exclude_patterns:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        self._exclude_patterns = exclude_patterns
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths

    def _strip_scheme_prefix(self, path):
        """Helper to strip file resolver scheme prefix from path."""

        return path[len(self.SCHEME + ":") :]

    def _mangle(self, path, existing_paths):
        """Helper for path mangling."""

        # Normalize slashes for cross-platform metadata consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path) :]
                break

        # Prepend passed scheme prefix
        # We do this first because the entries in existing_paths have the scheme
        # affixed already.
        path = self.SCHEME + ":" + path

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        return path

    def _hash(self, file_hashes):
        """Helper to correctly sort and hash every element."""

        text_repr = ""
        keys = list(file_hashes.keys())
        if keys:
            # Sorting requires the C locale. setlocale is process-global, so
            # restore the previous locale as soon as the sort is done. This
            # keeps the locale change from leaking into other interleaved
            # calls.
            old_locale = locale.setlocale(locale.LC_ALL)
            try:
                locale.setlocale(locale.LC_ALL, "C")
                keys.sort(key=cmp_to_key(locale.strcoll))
            finally:
                locale.setlocale(locale.LC_ALL, old_locale)

            text_repr = "\n".join(
                [f"{file_hashes[k][_HASH_ALGORITHM]}  {k}" for k in keys]
            )
            text_repr += "\n"  # trailing new line

        digest_obj = digest(_HASH_ALGORITHM)
        digest_obj.update(text_repr.encode("utf-8"))

        return {_HASH_ALGORITHM: digest_obj.hexdigest()}

    def hash_artifacts(self, uris):
        hashes = {}

        for path in uris:
            path = self._strip_scheme_prefix(path)

            if not os.path.isdir(path):
                raise ValueError(f"path '{path}' is not a directory")

            # The inner file resolver is bound to this directory root. It
            # resolves everything relative to that root without a working
            # directory change, so swapping the directory's contents (or
            # passing a different root) directly changes this aggregate hash
            # and cannot be influenced by another call's workspace.
            file_resolver = FileResolver(
                base_path=path,
                exclude_patterns=self._exclude_patterns,
                follow_symlink_dirs=self._follow_symlink_dirs,
                normalize_line_endings=self._normalize_line_endings,
            )

            file_hashes = file_resolver.hash_artifacts(["."])
            if not file_hashes:
                logger.info(
                    "path: %s has no files, recording empty dir...", path
                )

            name = self._mangle(path, hashes)
            hashes[name] = self._hash(file_hashes)

        return hashes
