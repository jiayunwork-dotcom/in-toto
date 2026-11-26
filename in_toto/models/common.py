# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  common.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres <santiago@nyu.edu>

<Started>
  Sep 23, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides base classes for various classes in the model.

"""

import inspect
import json

import attr
import securesystemslib.formats


class ValidationMixin:
    """The validation mixin provides a self-inspecting method, validate, to
    allow in-toto's objects to check that they are proper."""

    def validate(self):
        """Validates attributes of the instance.

        Raises:
          securesystemslib.formats.FormatError: An attribute value is invalid.

        """
        for method in inspect.getmembers(self, predicate=inspect.ismethod):
            if method[0].startswith("_validate_"):
                method[1]()


@attr.s(repr=False, init=False)
class Signable(ValidationMixin):
    """Objects with base class Signable are to be included in a Metablock class
    to be signed (hence the name). They provide a `signable_bytes` property
    used to create deterministic signatures."""

    def __repr__(self):
        """Returns an indented JSON string of the metadata object."""
        return json.dumps(
            self.to_dict(), indent=1, separators=(",", ": "), sort_keys=True
        )

    def to_dict(self):
        """Returns the JSON-serializable dictionary representation of self.

        Subclasses may override this to add fields that are not declared as
        ``attrs`` attributes, e.g. optional fields that must only be serialized
        when explicitly set, so that metadata signed before the field existed
        keeps its exact canonical representation.
        """
        return attr.asdict(self)

    @property
    def signable_bytes(self):
        """The UTF-8 encoded canonical JSON byte representation of the dictionary
        representation of the instance."""
        return securesystemslib.formats.encode_canonical(self.to_dict()).encode(
            "UTF-8"
        )
