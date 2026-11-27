"""Artifact resolver API.

Extensible interface to hash artifacts based on URIs.

Example usage::

    from in_toto.resolver import Resolver, RESOLVER_FOR_URI_SCHEME

    # Register resolver instances for schemes
    RESOLVER_FOR_URI_SCHEME["myscheme"] = MyResolver()

    # Resolve arbitrary URIs with registered resolvers
    resolver = Resolver.for_uri(uri)
    artifact_hashes = resolver.hash_artifacts(uris)

Resolvers registered here remain available to every
``in_toto.runlib.record_artifacts_as_dict`` call: recording binds a private,
per-call copy of this registry (see ``resolver_registry``) instead of
mutating it, so registrations never need to be repeated and survive failed
and interleaved calls.

"""

from in_toto.resolver._resolver import (
    RESOLVER_FOR_URI_SCHEME,
    DirectoryResolver,
    FileResolver,
    OSTreeResolver,
    Resolver,
    resolver_registry,
)
