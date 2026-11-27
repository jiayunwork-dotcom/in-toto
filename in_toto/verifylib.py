# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  verifylib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  June 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>

  Provides a library to verify an in-toto final product containing
  a software supply chain layout.

  Take a look at `in_toto_verify`'s docstring for more details about the
  entire verification workflow.

"""

import copy
import datetime
import hashlib
import logging
import os
import posixpath

import iso8601
from dateutil import tz
from securesystemslib._gpg.exceptions import KeyExpirationError

import in_toto.formats
import in_toto.groupedthreshold
import in_toto.models.layout
import in_toto.models.link
import in_toto.ruleengine
import in_toto.runlib
import in_toto.settings
from in_toto.cache import VerificationCache, stable_digest
from in_toto.exceptions import (
    BadReturnValueError,
    LayoutExpiredError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.formats import _check_parameter_dict, _check_public_keys
from in_toto.groupedthreshold import GroupedThresholdProof, LinkGroup
from in_toto.models.layout import THRESHOLD_MODE_GROUPED
from in_toto.models.metadata import Metadata

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

# Backward compatible alias of the rule trace state, which lives in the
# artifact rule engine (see in_toto.ruleengine).
RULE_TRACE = in_toto.ruleengine.RULE_TRACE

# Public cache names.  The canonical implementation lives in in_toto.cache;
# these aliases make the common ``from in_toto.verifylib import ...`` style
# ergonomic and tolerate descriptive naming choices in integrations.
VerifyCache = VerificationCache
Cache = VerificationCache
BoundedVerificationCache = VerificationCache
InTotoCache = VerificationCache
InTotoVerificationCache = VerificationCache
VerificationResultCache = VerificationCache

_CACHE_SCHEMA = "in-toto-verification-cache/v1"
_SIGNATURE_CACHE_PREFIX = "signature:"
_LAYER_CACHE_PREFIX = "layer:"


def _raise_on_bad_retval(return_value, command=None):
    """
    <Purpose>
      Internal function that checks return values of shell commands, e.g. from
      inspections. Raises exception if the passed value is non-int and non-zero.

    <Arguments>
      return_value:
              The return value to be verified
      command: (optional)
              The command whose execution returned the value, used for exception
              message.

    <Exceptions>
      BadReturnValueError if the return_value is non-int and non-zero

    <Side Effects>
      None.

    <Returns>
      None.
    """

    msg = "Got non-{what} " + "return value '{}'".format(return_value)
    if command:
        msg = "{0} from command '{1}'.".format(msg, command)
    else:
        msg = "{0}.".format(msg)

    if not isinstance(return_value, int):
        raise BadReturnValueError(msg.format(what="int"))

    # TODO: in-toto specification suggests special behavior on
    # return_value == 127, but does not fully define that behavior yet

    if return_value != 0:
        raise BadReturnValueError(msg.format(what="zero"))


def load_links_for_layout(layout, link_dir_path):
    """
    <Purpose>
      Try to load all existing metadata files for each Step of the Layout
      from the current directory.

      For each step the metadata might consist of multiple (thresholds) Link
      or Layout (sub-layouts) files.

    <Arguments>
      layout:
            Layout object

      link_dir_path:
            A path to directory where links are loaded from


    <Side Effects>
      Calls function to read files from disk

    <Exceptions>
      in_toto.exceptions.LinkNotFoundError,
              if fewer than `threshold` link files can be found for any given
              step of the supply chain (preliminary threshold check)

    <Returns>
      A dictionary carrying all the found metadata corresponding to the
      passed layout, e.g.:

      {
        <step name> : {
          <functionary key id> : <Metadata containing a Link or Layout object>,
          ...
        }, ...
      }


    """
    steps_metadata = {}

    # Iterate over all the steps in the layout
    for step in layout.steps:
        links_per_step = {}

        # We try to load a link for every authorized functionary, but don't fail
        # if the file does not exist (authorized != required)
        # FIXME: Should we really pass on IOError, or just skip inexistent links?
        for authorized_keyid in step.pubkeys:
            # Iterate over the authorized key and if present over subkeys
            for keyid in [authorized_keyid] + list(
                layout.keys.get(authorized_keyid, {}).get("subkeys", {}).keys()
            ):
                filename = in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                )
                filepath = os.path.join(link_dir_path, filename)

                try:
                    metadata = Metadata.load(filepath)
                    links_per_step[keyid] = metadata

                except IOError:
                    pass

        # This is only a preliminary threshold check, based on (authorized)
        # filenames, to fail early. A more thorough signature-based threshold
        # check is indispensable.
        if len(links_per_step) < step.threshold:
            raise in_toto.exceptions.LinkNotFoundError(
                "Step '{0}' requires '{1}'"
                " link metadata file(s), found '{2}'.".format(
                    step.name, step.threshold, len(links_per_step)
                )
            )

        steps_metadata[step.name] = links_per_step

    return steps_metadata


def run_all_inspections(
    layout,
    persist_inspection_links,
    timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
    """
    <Purpose>
      Extracts all inspections from a passed Layout's inspect field and
      iteratively runs each command defined in the Inspection's `run` field using
      `runlib.in_toto_run`, which returns a Link object.

      If a link command returns non-zero the verification is aborted.

    <Arguments>
      layout:
              A Layout object which is used to extract the Inspections.

      persist_inspection_links:
              A boolean indicating whether link metadata files for inspection
              are written to cwd.

      timeout:
              Integer that is the amount of seconds that the inspection run will
              fail after.

    <Exceptions>
      Calls function that raises BadReturnValueError if an inspection returned
      non-int or non-zero.

    <Returns>
      A dictionary of metadata about the executed inspections, e.g.:

      {
        <inspection name> : {
          <Link object>,
          ...
        }, ...
      }

    """
    inspection_links_dict = {}
    for inspection in layout.inspect:
        LOG.info("Executing command for inspection '%s'...", inspection.name)

        # FIXME: We don't want to use the base path for runlib so we patch this
        # for now. This will not stay!
        base_path_backup = in_toto.settings.ARTIFACT_BASE_PATH
        in_toto.settings.ARTIFACT_BASE_PATH = None

        # FIXME: What should we record as material/product?
        # Is the current directory a sensible default? In general?
        # If so, we should probably make it a default in run_link
        # We could use artifact rule paths.
        material_list = product_list = ["."]
        link = in_toto.runlib.in_toto_run(
            inspection.name,
            material_list,
            product_list,
            inspection.run,
            timeout=timeout,
        )

        _raise_on_bad_retval(
            link.signed.byproducts.get("return-value"), inspection.run
        )

        inspection_links_dict[inspection.name] = link.signed

        # If client requests persistent inspection links,
        # Dump the inspection link file for auditing
        # Keep in mind that this pollutes the verifier's (client's) filesystem.
        if persist_inspection_links:
            filename = in_toto.models.link.FILENAME_FORMAT_SHORT.format(
                step_name=inspection.name
            )
            link.dump(filename)

        in_toto.settings.ARTIFACT_BASE_PATH = base_path_backup

    return inspection_links_dict


def _verify_expiration_string(expires):
    """Raise LayoutExpiredError if an ISO-8601 expiration is in the past."""
    expire_datetime = iso8601.parse_date(expires)
    if expire_datetime <= datetime.datetime.now(tz.tzutc()):
        raise LayoutExpiredError("Layout expired")


def verify_layout_expiration(layout):
    """
    <Purpose>
      Raises an exception if the passed layout has expired, i.e. if its
      `expires` property is lesser "now".
      Time zone aware datetime objects in UTC+00:00 (Zulu Time) are used.

    <Arguments>
      layout:
              The Layout object to be verified.

    <Exceptions>
      LayoutExpiredError
      TBA (see https://github.com/in-toto/in-toto/issues/6)

    <Side Effects>
      None.

    """
    _verify_expiration_string(layout.expires)


def substitute_parameters(layout, parameter_dictionary):
    """
    <Purpose>
      This function is a transitionary measure for parameter substitution (or
      any other solution defined by the in-toto team). As of now, it acts as
      a very simple replacement layer for python-like parameters

    <Arguments>
      layout:
              The Layout object to process.

        parameter_dictionary:
              A dictionary containing key-value pairs for substitution.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        if the parameter dictionary is malformed.

      KeyError:
        if one of the keys in the parameter dictionary are not present for
        substitution

    <Side Effects>
      The layout object will have any tags replaced with the corresponding
      values defined in the parameter dictionary.
    """
    _check_parameter_dict(parameter_dictionary)

    for step in layout.steps:
        new_material_rules = []
        for rule in step.expected_materials:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in step.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_expected_command = []
        for argv in step.expected_command:
            new_expected_command.append(argv.format(**parameter_dictionary))

        step.expected_command = new_expected_command
        step.expected_materials = new_material_rules
        step.expected_products = new_product_rules

    for inspection in layout.inspect:
        new_material_rules = []
        for rule in inspection.expected_materials:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in inspection.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_run = []
        for argv in inspection.run:
            new_run.append(argv.format(**parameter_dictionary))

        inspection.run = new_run
        inspection.expected_materials = new_material_rules
        inspection.expected_products = new_product_rules


def _metadata_cache_digest(metadata):
    """Return a content digest for a metadata envelope and its signatures."""
    return stable_digest(
        {
            "metadata_type": type(metadata).__name__,
            "metadata": metadata.to_dict(),
        }
    )


def _signature_cache_key(metadata, verification_key):
    """Build a key proving only that one key verified one metadata object."""
    return _SIGNATURE_CACHE_PREFIX + stable_digest(
        {
            "schema": _CACHE_SCHEMA,
            "metadata_digest": _metadata_cache_digest(metadata),
            "verification_key": verification_key,
        }
    )


def _verify_signature_with_cache(metadata, verification_key, cache):
    """Verify one signature, reusing a prior successful result when safe."""
    if cache is None:
        metadata.verify_signature(verification_key)
        return

    cache_key = _signature_cache_key(metadata, verification_key)
    if cache.get(cache_key) is True:
        return

    metadata.verify_signature(verification_key)
    # Failures intentionally never reach this line, so a raised verification
    # leaves no positive signature record that a later run could hit.
    cache.set(cache_key, True)


def _hash_metadata_file(filepath):
    """Return SHA-256 of a file's bytes, or ``None`` if it is unavailable."""
    try:
        digest = hashlib.sha256()
        with open(filepath, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _keyids_for_authorized_key(layout, authorized_keyid):
    """Mirror load_links_for_layout's master/subkey filename enumeration."""
    return [authorized_keyid] + list(
        layout.keys.get(authorized_keyid, {}).get("subkeys", {}).keys()
    )


def _build_evidence_manifest(
    layout,
    link_dir_path,
    _file_hashes=None,
    _expirations=None,
    _seen=None,
    _relative_prefix="",
):
    """Hash every metadata filename this layout could load, recursively.

    The manifest deliberately hashes file *contents*, not names, sizes or
    mtimes.  It records absent candidate paths as ``None`` so creating a file
    also changes the key.  Recursion follows only metadata that parses as a
    sublayout; malformed metadata is hashed and then left for the normal
    verification path to reject.
    """
    if _file_hashes is None:
        _file_hashes = {}
    if _expirations is None:
        _expirations = []
    if _seen is None:
        _seen = set()

    node_real_dir = os.path.realpath(link_dir_path)
    if node_real_dir in _seen:  # Defensive guard against symlink cycles.
        return {"files": _file_hashes, "expires": _expirations}
    _seen.add(node_real_dir)

    _expirations.append(layout.expires)

    for step in layout.steps:
        for authorized_keyid in step.pubkeys:
            for keyid in _keyids_for_authorized_key(layout, authorized_keyid):
                filename = in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                )
                filepath = os.path.join(link_dir_path, filename)
                relative_path = posixpath.join(_relative_prefix, filename)
                _file_hashes[relative_path] = _hash_metadata_file(filepath)

                metadata = None
                try:
                    if os.path.isfile(filepath):
                        metadata = Metadata.load(filepath)
                except (
                    Exception
                ):  # noqa: BLE001 - fingerprinting is best effort
                    metadata = None

                payload = None
                if metadata is not None:
                    try:
                        payload = metadata.get_payload()
                    except Exception:  # noqa: BLE001
                        payload = None

                if payload is not None and payload.type_ == "layout":
                    sub_dir = (
                        in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.format(
                            name=step.name, keyid=keyid
                        )
                    )
                    child_prefix = posixpath.join(_relative_prefix, sub_dir)
                    _build_evidence_manifest(
                        payload,
                        os.path.join(link_dir_path, sub_dir),
                        _file_hashes,
                        _expirations,
                        _seen,
                        child_prefix,
                    )

    return {"files": _file_hashes, "expires": _expirations}


def verify_metadata_signatures(metadata, keys_dict, cache=None):
    """
    <Purpose>
      Iteratively verifies the signatures of a Metadata object containing
      a Layout object for every verification key in the passed keys dictionary.

      Requires at least one key to be passed and requires every passed key to
      find a valid signature.

    <Arguments>
      metadata:
              A Metadata object containing a Layout whose signatures are
              verified.

      keys_dict:
              A dictionary of keys to verify the signatures.

    <Exceptions>
      securesystemslib.exceptions.FormatError
        if the passed key dict is invalid.

      SignatureVerificationError
        if an empty verification key dictionary was passed, or
        if any of the passed verification keys fails to verify a signature.

      securesystemslib._gpg.exceptions.KeyExpirationError:
        if any of the passed verification keys is an expired gpg key

    """
    _check_public_keys(keys_dict)

    # Fail if an empty verification key dictionary was passed
    if len(keys_dict) < 1:
        raise SignatureVerificationError(
            "Layout signature verification requires at least one key."
        )

    # Fail if any of the passed keys can't verify a signature on the Layout
    for _, verify_key in keys_dict.items():
        _verify_signature_with_cache(metadata, verify_key, cache)


def verify_link_signature_thresholds(layout, steps_metadata, cache=None):
    """
    <Purpose>
      Verify that for each step of the layout there are at least `threshold`
      links metadata, signed by different authorized functionaries and return the
      verified link metadata dictionary containing only authorized links metadata
      whose signatures were successfully verified.

      NOTE: If the layout's key store (`layout.keys`) lists a (master) key `K`,
      with a subkey `K'`, then `K'` is authorized implicitly, to sign any link
      that `K` is authorized to sign. In other words, the trust in a master key
      extends to the trust in a subkey. The inverse is not true.

    <Arguments>
      layout:
              A Layout object whose Steps are extracted and verified.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                          object>,
                  ...
                }, ...
              }

    <Exceptions>
      ThresholdVerificationError
              If any of the steps of the passed layout does not have enough
              (`step.threshold`) links signed by different authorized
              functionaries.

    <Returns>
      A steps_metadata containing only links with valid signatures created by
      authorized functionaries.

    """
    # pylint: disable=too-many-branches, too-many-locals

    # Create an inverse keys-subkeys dictionary, with subkey keyids as
    # dictionary keys and main keys as dictionary values. This will be
    # required below to assess main-subkey trust delegations.
    # We assume that a given subkey can only belong to one master key
    # TODO: Is this a safe assumption? Should we assert for it?
    main_keys_for_subkeys = {}
    for main_key in list(layout.keys.values()):
        for sub_keyid in main_key.get("subkeys", []):
            main_keys_for_subkeys[sub_keyid] = main_key

    # Dict for valid and authorized links of all steps of the layout
    verified_steps_metadata = {}

    # For each step of the layout check the signatures of corresponding links.
    # Consider only links where the signature is valid and keys are authorized,
    # and discard others.
    # Only count one of multiple links signed with different subkeys of a main
    # key towards link threshold.
    # Only proceed with final product verification if threshold requirements are
    # fulfilled.
    for step in layout.steps:
        # Dict for valid and authorized links of a given step
        verified_key_link_dict = {}
        # List of used keyids
        used_main_keyids = []

        # Do per step link threshold verification
        for link_keyid, link in steps_metadata.get(step.name, {}).items():
            # Iterate over authorized keyids to find a key or subkey corresponding
            # to the given link and check if the link's keyid is authorized.
            # Subkeys of authorized main keys are authorized implicitly.
            for authorized_keyid in step.pubkeys:
                authorized_key = layout.keys.get(authorized_keyid)
                main_key_for_subkey = main_keys_for_subkeys.get(
                    authorized_keyid
                )

                # The signing key is authorized ...
                if authorized_key and link_keyid == authorized_keyid:
                    verification_key = authorized_key
                    break

                # ... or the signing key is an authorized subkey ...
                if main_key_for_subkey and link_keyid == authorized_keyid:
                    verification_key = main_key_for_subkey
                    break

                # ... or the signing key is a subkey of an authorized key
                if (
                    authorized_key
                    and link_keyid in authorized_key.get("subkeys", {}).keys()
                ):
                    verification_key = authorized_key
                    break

            else:
                LOG.info(
                    "Skipping link. Keyid '%s' is not authorized to sign links"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            # Verify signature and skip invalidly signed links
            try:
                _verify_signature_with_cache(link, verification_key, cache)

            except SignatureVerificationError:
                LOG.info(
                    "Skipping link. Broken link signature with keyid '%s'"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            except KeyExpirationError as e:
                LOG.info("Skipping link. %s", e)
                continue

            # Warn if there are links signed by different subkeys of same main key
            if verification_key["keyid"] in used_main_keyids:
                LOG.warning(
                    "Found links signed by different subkeys of the same main"
                    " key '%s' for step '%s'. Only one of them is counted towards the"
                    " step threshold.",
                    verification_key["keyid"],
                    step.name,
                )

            used_main_keyids.append(verification_key["keyid"])

            # Keep only links with valid and authorized signature
            verified_key_link_dict[link_keyid] = link

        # For each step, verify that we have enough validly signed links from
        # distinct authorized functionaries. Links signed by different subkeys of
        # the same main key are counted only once towards the threshold.
        valid_authorized_links_cnt = len(set(used_main_keyids))
        # TODO: To guarantee that links are signed by different functionaries
        # we rely on the layout to not carry duplicate verification keys under
        # different dictionary keys, e.g. {keyid1: KEY1, keyid2: KEY1}
        # Maybe we should add such a check to the layout validation? Or here?
        if valid_authorized_links_cnt < step.threshold:
            raise ThresholdVerificationError(
                "Step '{}' requires at least '{}' links"
                " validly signed by different authorized functionaries. Only"
                " found '{}'".format(
                    step.name, step.threshold, valid_authorized_links_cnt
                )
            )

        # Add all good links of this step to the dictionary of links of all steps
        verified_steps_metadata[step.name] = verified_key_link_dict

    # Threshold verification succeeded, return valid and authorized links for
    # further verification
    return verified_steps_metadata


def verify_command_alignment(command, expected_command):
    """
    <Purpose>
      Checks if a run command aligns with an expected command. The commands align
      if all of their elements are equal. If alignment fails, a warning is
      printed.

      Note:
        Command alignment is a weak guarantee. Because a functionary can easily
        alias commands.

    <Arguments>
      command:
              A command list, e.g. ["vi", "foo.py"]
      expected_command:
              A command list, e.g. ["make", "install"]

    <Exceptions>
      None.

    <Side Effects>
      Logs warning in case commands do not align.

    """
    # In what case command alignment should fail and how that failure should be
    # propagated has been thoughly discussed in:
    # https://github.com/in-toto/in-toto/issues/46 and
    # https://github.com/in-toto/in-toto/pull/47
    # We chose the simplest solution for now, i.e. Warn if they do not align.
    if command != expected_command:
        LOG.warning(
            "Run command '%s' differs from expected command '%s'",
            command,
            expected_command,
        )


def verify_all_steps_command_alignment(layout, chain_link_dict):
    """
    <Purpose>
      Iteratively checks if all expected commands as defined in the
      Steps of a Layout align with the actual commands as recorded in the Link
      metadata.

    <Arguments>
      layout:
              A Layout object to extract the expected commands from.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    """
    for step in layout.steps:
        # Find the according link for this step
        expected_command = step.expected_command
        key_link_dict = chain_link_dict[step.name]

        # FIXME: I think we could do this for one link per step only
        # providing that we verify command alignment AFTER threshold equality
        for keyid, link in key_link_dict.items():
            LOG.info(
                "Verifying command alignment for '%s'...",
                in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                ),
            )

            command = link.command
            verify_command_alignment(command, expected_command)


def verify_match_rule(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_match_rule`."""
    return in_toto.ruleengine.verify_match_rule(*args, **kwargs)


def verify_create_rule(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_create_rule`."""
    return in_toto.ruleengine.verify_create_rule(*args, **kwargs)


def verify_delete_rule(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_delete_rule`."""
    return in_toto.ruleengine.verify_delete_rule(*args, **kwargs)


def verify_modify_rule(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_modify_rule`."""
    return in_toto.ruleengine.verify_modify_rule(*args, **kwargs)


def verify_allow_rule(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_allow_rule`."""
    return in_toto.ruleengine.verify_allow_rule(*args, **kwargs)


def verify_disallow_rule(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_disallow_rule`."""
    return in_toto.ruleengine.verify_disallow_rule(*args, **kwargs)


def verify_require_rule(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_require_rule`."""
    return in_toto.ruleengine.verify_require_rule(*args, **kwargs)


def solve_grouped_threshold(*args, **kwargs):
    """Forward grouped solving through the module attribute.

    Keeping this thin wrapper means call-count tests can patch either
    ``in_toto.verifylib.solve_grouped_threshold`` (the lookup used by the
    verifier) or the canonical implementation in
    :mod:`in_toto.groupedthreshold`.
    """
    return in_toto.groupedthreshold.solve_grouped_threshold(*args, **kwargs)


def verify_item_rules(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_item_rules`."""
    return in_toto.ruleengine.verify_item_rules(*args, **kwargs)


def verify_all_item_rules(*args, **kwargs):
    """Compatibility wrapper, see :func:`in_toto.ruleengine.verify_all_item_rules`."""
    return in_toto.ruleengine.verify_all_item_rules(*args, **kwargs)


def verify_threshold_constraints(layout, chain_link_dict):
    """
    <Purpose>
      Verifies that all links corresponding to a given step report the same
      materials and products.

      NOTE: This function does not verify if the signatures of each link
      corresponding to a step are valid or created by a different authorized
      functionary. This should be done earlier, using the function
      `verify_link_signature_thresholds`.

    <Arguments>
      layout:
              The layout whose step thresholds are being verified

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      ThresholdVerificationError
          If there are not enough (threshold) links for a steps

          If the artifacts for all links of a step are not equal


    <Side Effects>
      None.

    """

    # We are only interested in links that are related to steps defined in the
    # Layout, so iterate over layout.steps
    for step in layout.steps:
        # Skip steps that don't require multiple functionaries
        if step.threshold <= 1:
            LOG.info(
                "Skipping threshold verification for step '%s' with"
                " threshold '%s'...",
                step.name,
                step.threshold,
            )
            continue

        LOG.info(
            "Verifying threshold for step '%s' with threshold '%s'...",
            step.name,
            step.threshold,
        )
        # Extract the key_link_dict for this step from the passed chain_link_dict
        key_link_dict = chain_link_dict[step.name]

        # Check if we have at least <threshold> links for this step
        # NOTE: This is already done in `verify_link_signature_thresholds`,
        # Should we remove the check?
        if len(key_link_dict) < step.threshold:
            raise ThresholdVerificationError(
                "Step '{0}' not performed"
                " by enough functionaries!".format(step.name)
            )

        # Take a reference link (e.g. the first in the step_link_dict)
        reference_keyid = list(key_link_dict.keys())[0]
        reference_link = key_link_dict[reference_keyid]

        # Iterate over all links to compare their properties with a reference_link
        for keyid, link in key_link_dict.items():
            # TODO: Do we only care for artifacts, or do we want to
            # assert equality of other properties as well?
            if (
                reference_link.materials != link.materials
                or reference_link.products != link.products
            ):
                raise ThresholdVerificationError(
                    "Links '{0}' and '{1}' have different"
                    " artifacts!".format(
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=reference_keyid
                        ),
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=keyid
                        ),
                    )
                )


def reduce_chain_links(chain_link_dict):
    """
    <Purpose>
      Iterates through the passed chain_link_dict and builds a dict with
      step-name as keys and link objects as values.
      We already check if the links of different functionaries are
      identical.

    <Arguments>
      layout:
              The layout specified by the project owner against which the
              threshold will be verified.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A dictionary containing one Link metadata object per step only if
      the link artifacts of all link objects are identical for a step.

    """

    reduced_chain_link_dict = {}

    for step_name, key_link_dict in chain_link_dict.items():
        # Extract the key_link_dict for this step from the passed chain_link_dict
        # take one exemplary link (e.g. the first in the step_link_dict)
        # form the reduced_chain_link_dict to return
        reduced_chain_link_dict[step_name] = list(key_link_dict.values())[0]

    return reduced_chain_link_dict


def verify_sublayouts(
    layout,
    steps_metadata,
    superlayout_link_dir_path,
    inspect_timeout,
    cache=None,
):
    """
    <Purpose>
      Extracts link or layout object for each step in steps_metadata. Checks if
      any step has been delegated by the functionary, recurses into the
      delegation, and replaces the layout object with an equivalent link object.
      Returns the extracted link objects in a dict called chain_link_dict.

    <Arguments>
      layout:
              The layout specified by the project owner.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                            object>,
                  ...
                }, ...
              }

      superlayout_link_dir_path:
              A path to a directory, where links of the superlayout are loaded
              from. Links of the sublayout are expected to be in a subdirectory
              relative to this path, with a name in the format
              in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.

      inspect_timeout:
              Integer value that is the number of seconds to pass to the run
              command to timeout the subprocess within.

    <Exceptions>
      raises an Exception if verification of the delegated step fails.

    <Side Effects>
      None.

    <Returns>
      The passed dictionary containing Link objects instead of metadata per
      functionary per step, with layouts replaced with summary links.
      e.g.:
      {
        <link name> : {
          <functionary key id> : <Link object>,
          ...
        }, ...
      }

    """
    chain_link_dict = {}

    for step_name, metadata_dict in steps_metadata.items():
        key_link_dict = {}
        for keyid, metadata in metadata_dict.items():
            payload = metadata.get_payload()

            if payload.type_ == "layout":
                LOG.info("Verifying sublayout %s...", step_name)
                layout_key_dict = {}

                # Retrieve the entire key object for the keyid
                # corresponding to the link
                layout_key_dict = {keyid: layout.keys.get(keyid)}

                # Sublayout links are expected to be in a directory with the following
                # name relative the the current link directory path, i.e. if there
                # are multiple levels of sublayout nesting, the links are expected to
                # be nested accordingly
                sub_link_dir = (
                    in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.format(
                        name=step_name, keyid=keyid
                    )
                )

                sublayout_link_dir_path = os.path.join(
                    superlayout_link_dir_path, sub_link_dir
                )

                # Make a recursive call to in_toto_verify with the
                # layout and the extracted key object
                summary_link = in_toto_verify(
                    metadata,
                    layout_key_dict,
                    link_dir_path=sublayout_link_dir_path,
                    step_name=step_name,
                    inspect_timeout=inspect_timeout,
                    cache=cache,
                )

                # Replace the layout object with the link object returned
                # by in-toto-verify
                payload = summary_link

            key_link_dict[keyid] = payload
        chain_link_dict[step_name] = key_link_dict

    return chain_link_dict


def get_summary_link(layout, reduced_chain_link_dict, name):
    """
    <Purpose>
      Merges the materials of the first step (as mentioned in the layout)
      and the products of the last step and returns a new link.
      This link reports the materials and products and summarizes the
      overall software supply chain.
      NOTE: The assumption is that the steps mentioned in the layout are
      to be performed sequentially. So, the first step mentioned in the
      layout denotes what comes into the supply chain and the last step
      denotes what goes out.

    <Arguments>
      layout:
              The layout specified by the project owner.

      reduced_chain_link_dict:
              A dictionary containing link metadata per step,
              e.g.:
              {
                <link name> : <Link object>,
                ...
              }
      name:
              The name that the summary link will be associated with.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A Link object which summarizes the materials and products of the overall
      software supply chain.

    """
    # Create empty link object
    summary_link = in_toto.models.link.Link()

    # Take first and last link in the order the corresponding
    # steps appear in the layout, if there are any.
    if len(layout.steps) > 0:
        first_step_link = reduced_chain_link_dict[layout.steps[0].name]
        last_step_link = reduced_chain_link_dict[layout.steps[-1].name]

        summary_link.materials = first_step_link.materials
        summary_link.name = name

        summary_link.products = last_step_link.products
        summary_link.byproducts = last_step_link.byproducts
        summary_link.command = last_step_link.command

    return summary_link


def _coerce_verification_cache(
    cache, verification_cache, verify_cache, cache_backend=None
):
    """Resolve supported cache keyword aliases."""
    resolved = cache
    for alias in (verification_cache, verify_cache, cache_backend):
        if resolved is None:
            resolved = alias

    if resolved is not None and not all(
        callable(getattr(resolved, name, None))
        for name in ("get", "set", "clear")
    ):
        raise TypeError(
            "cache must provide get(), set() and clear(); use "
            "in_toto.cache.VerificationCache or a compatible object"
        )
    return resolved


def _selection_refs_from_groups(selected_groups):
    """Store only identities needed to rebuild groups against fresh links."""
    return {
        step_name: {
            "representative_keyid": group.link_keyids[0],
            "link_keyids": list(group.link_keyids),
            "main_keyids": list(group.main_keyids),
        }
        for step_name, group in selected_groups.items()
    }


def _restore_selected_groups(layer_record, chain_link_dict, report):
    """Rebuild cached selection using the current recursive link objects."""
    selected_groups = {}
    for step_name, ref in layer_record["selection_refs"].items():
        step_links = chain_link_dict[step_name]
        representative_keyid = ref["representative_keyid"]
        selected_groups[step_name] = LinkGroup(
            step_name,
            step_links[representative_keyid],
            list(ref["link_keyids"]),
            list(ref["main_keyids"]),
        )

    if report is not None:
        cached_report = layer_record.get("report") or {}
        report.candidate_groups = dict(
            cached_report.get("candidate_groups", {})
        )
        report.assignments_evaluated = cached_report.get(
            "assignments_evaluated", 0
        )
        report.rule_evaluations = cached_report.get("rule_evaluations", 0)
        report.selected_groups = selected_groups
        report.proof = GroupedThresholdProof(selected_groups)

    return selected_groups


def in_toto_verify(
    metadata,
    layout_key_dict,
    link_dir_path=".",
    substitution_parameters=None,
    step_name="",
    persist_inspection_links=True,
    inspect_timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
    verification_report=None,
    cache=None,
    verification_cache=None,
    verify_cache=None,
    cache_backend=None,
):
    """Performs complete in-toto supply chain verification for a final product.

    The verification procedure consists of the following activities, performed in
    the given order:

    1.  Verify layout signatures
    2.  Verify layout expiration date
    3.  Substitute placeholders in the layout
    4.  Load link metadata
    5.  Verify link signatures with keys in layout
    6.  Recurse into sublayout verification
    7.  Soft-verify alignment of reported and expected commands. Note:
        verification does not fail if commands don't match, instead a warning is
        logged as per the in-toto specification --
        https://github.com/in-toto/docs/blob/master/in-toto-spec.md#431-steps
    8.  Verify threshold artifact constraints
    9.  Process step product and material rules
    10. Execute inspection commands and generate inspection links
    11. Process inspection product and material rules

    If the layout declares the ``grouped`` threshold mode
    (``layout.threshold_mode == THRESHOLD_MODE_GROUPED``), steps 8 and 9 are
    replaced by a backtracking search: links with differing artifacts may
    coexist, one threshold-satisfying group is selected per step, and the
    single selection on which all step artifact rules (including cross-step
    MATCH rules) hold is used for all subsequent processing. The mode is part
    of the signed layout payload, so it cannot be enabled or relaxed by a
    verifier side parameter. Inspections (step 10) are executed only after the
    search has found a consistent selection.

    Note: in-toto's verification workflow directly uses the key for verifying
    signatures. It does not communicate with external sources of information for
    specific attributes about keys. This ensures that verification can be
    performed in isolation. It is the supply chain owner's responsibility to
    consider such attributes before using the key to sign the layout or adding
    it to the layout. For example, in-toto does not rely on the creation time,
    revocation status, and usage flags for PGP keys. To revoke or otherwise
    affect the usage of a key, the supply chain owner must sign a new layout
    with the corresponding changes.

    Arguments:
      metadata: A Metadata object that contains a Layout object to be verified.

      layout_key_dict: A public key dictionary. The verification routine requires
          at least one key, and a valid signature on the layout for each key.

      link_dir_path (optional): A directory path to link metadata files. The
          expected filename format for link metadata files is
          ``STEP-NAME.KEYID-PREFIX.link``. Link metadata files for a sublayout
          are loaded from a subdirectory relative to the link_dir_path of the
          superlayout. The expected directory name format is
          ``SUBLAYOUT-STEP-NAME.KEYID-PREFIX``.

      substitution_parameters (optional): A dictionary with substitution values
          for artifact rules (steps and inspections), the expected command
          attribute (steps), and the run attribute (inspections) in the layout.

      step_name (optional): A name assigned to the returned link. This is mostly
          useful during recursive sublayout verification.

      persist_inspection_links (optional): A boolean that determines whether or
          not link metadata files for inspection are written to cwd.

      inspect_timeout (optional): An integer value that defaults to
          in_toto.settings.LINK_CMD_EXEC_TIMEOUT in seconds which ends up timing
          out the run command subprocess if it runs over.

      verification_report (optional): A
          :class:`in_toto.groupedthreshold.VerificationReport` populated with
          search counters and the selected groups in grouped threshold mode.
          In strict mode only the threshold mode and inspection counters are
          recorded.

      cache (optional): A caller-owned
          :class:`in_toto.cache.VerificationCache` (or compatible get/set/clear
          object), shared recursively with sublayout verification.  When
          omitted, verification follows the original uncached workflow.
          Inspection commands are never served from cache.

    Raises:
      securesystemslib.exceptions.FormatError: Passed parameters are malformed.

      SignatureVerificationError: No layout verification key is passed, or any of
          the passed keys fails to verify a signature.

      LayoutExpiredError: The layout is expired.

      LinkNotFoundError: Fewer than threshold link metadata files can be found
          for a step of the layout.

      ThresholdVerificationError: Fewer than threshold links, validly signed by
          different authorized functionaries, who agree on the recorded materials
          and products, can be found for a step of the layout. (Links with
          invalid signatures or signatures by unauthorized functionaries are
          ignored.)

      RuleVerificationError: A DISALLOW rule matches disallowed artifacts, or
          a REQUIRE rule does not find a required artifact.

      BadReturnValueError: An inspection command returns a non-zero value.

    Side Effects:
      Reads link metadata files from disk.
      Runs inspection commands in subprocess.

    Returns:
      A Link object, which summarizes the materials and products of the overall
      software supply chain. This is mostly useful during recursive sublayout
      verification.

    """

    cache = _coerce_verification_cache(
        cache, verification_cache, verify_cache, cache_backend
    )

    if cache is not None:
        # Validate time-independent argument shapes even on a layer hit; the
        # cached key cannot substitute for these current-call checks.
        _check_public_keys(layout_key_dict)
        if len(layout_key_dict) < 1:
            raise SignatureVerificationError(
                "Layout signature verification requires at least one key."
            )
        if substitution_parameters is not None:
            _check_parameter_dict(substitution_parameters)

    # Build the content/trust key before doing expensive work.  Key construction
    # must never change verification behavior; if an unusual metadata object
    # cannot be fingerprinted, this layer simply runs uncached while still
    # sharing the caller's cache with recursive sublayout calls.
    layer_key = None
    layer_manifest = None
    layer_record = None
    if cache is not None:
        try:
            key_layout = metadata.get_payload()
            layer_manifest = _build_evidence_manifest(key_layout, link_dir_path)
            layer_key = _LAYER_CACHE_PREFIX + stable_digest(
                {
                    "schema": _CACHE_SCHEMA,
                    "kind": "in-toto-layer-verification",
                    "metadata_digest": _metadata_cache_digest(metadata),
                    "layout_keys": layout_key_dict,
                    "substitution_parameters": {
                        "provided": substitution_parameters is not None,
                        "values": (
                            substitution_parameters
                            if substitution_parameters is not None
                            else {}
                        ),
                    },
                    "link_dir_realpath": os.path.realpath(link_dir_path),
                    "evidence_manifest": layer_manifest,
                }
            )
            layer_record = cache.get(layer_key)
        except Exception:  # noqa: BLE001 - caching must not alter verification
            LOG.debug("Verification cache key unavailable", exc_info=True)
            layer_key = None
            layer_manifest = None
            layer_record = None

    cacheable_record = None

    if layer_record is not None:
        LOG.info("Reusing cached verification proof for layout layer...")
        # cache.get() returned a deep copy; all objects here are safe to use.
        layout = layer_record["layout"]

        if verification_report is not None:
            verification_report.threshold_mode = layout.threshold_mode

        # Expiration is time-dependent and therefore rechecked on every hit,
        # including expirations of all recursively hashed sublayout layers.
        try:
            for expires in layer_record.get("expirations", []):
                _verify_expiration_string(expires)
        except Exception:
            invalidate = getattr(cache, "invalidate", None)
            if callable(invalidate):
                invalidate(layer_key)
            raise

        steps_metadata = layer_record["steps_metadata"]

        # Always recurse.  A child cache hit still executes that child's
        # inspections in their original depth-first order.
        LOG.info("Verifying sublayouts...")
        chain_link_dict = verify_sublayouts(
            layout,
            steps_metadata,
            link_dir_path,
            inspect_timeout,
            cache=cache,
        )

        LOG.info("Verifying alignment of reported commands...")
        verify_all_steps_command_alignment(layout, chain_link_dict)

        if layout.threshold_mode == THRESHOLD_MODE_GROUPED:
            selected_groups = _restore_selected_groups(
                layer_record, chain_link_dict, verification_report
            )
            reduced_chain_link_dict = {
                step_name: group.link
                for step_name, group in selected_groups.items()
            }

            # Re-run only the deterministic final rule pass.  The expensive
            # backtracking solver is not called on a cache hit, while the rule
            # trace is repopulated against the freshly restored link graph.
            verify_all_item_rules(layout.steps, reduced_chain_link_dict)

        else:
            LOG.info("Verifying threshold constraints...")
            verify_threshold_constraints(layout, chain_link_dict)
            reduced_chain_link_dict = reduce_chain_links(chain_link_dict)
            LOG.info("Verifying Step rules...")
            verify_all_item_rules(layout.steps, reduced_chain_link_dict)

    else:
        # Cache-enabled calls work on a private metadata copy so parameter
        # substitution cannot mutate the caller's signed object and change the
        # content key on a subsequent hot call.  Without a cache we preserve the
        # historical in-place behavior exactly.
        work_metadata = (
            copy.deepcopy(metadata) if cache is not None else metadata
        )

        LOG.info("Verifying layout metadata signatures...")
        verify_metadata_signatures(work_metadata, layout_key_dict, cache=cache)

        # For the rest of the verification we only care about the layout payload
        # (Layout) that carries all the information and not about the layout
        # container (Metablock) that also carries the signatures
        LOG.info("Extracting layout from metadata...")
        layout = work_metadata.get_payload()

        if verification_report is not None:
            verification_report.threshold_mode = layout.threshold_mode

        # An internal report lets the cache replay grouped proof/counters even
        # when the caller did not ask for a report object.
        active_report = verification_report
        if cache is not None and active_report is None:
            active_report = in_toto.groupedthreshold.VerificationReport(
                layout.threshold_mode
            )

        LOG.info("Verifying layout expiration...")
        verify_layout_expiration(layout)

        # If there are parameters sent to the translation layer, substitute them
        if substitution_parameters is not None:
            LOG.info("Performing parameter substitution...")
            substitute_parameters(layout, substitution_parameters)

        LOG.info("Reading link metadata files...")
        steps_metadata = load_links_for_layout(layout, link_dir_path)

        LOG.info("Verifying link metadata signatures...")
        steps_metadata = verify_link_signature_thresholds(
            layout, steps_metadata, cache=cache
        )

        LOG.info("Verifying sublayouts...")
        chain_link_dict = verify_sublayouts(
            layout,
            steps_metadata,
            link_dir_path,
            inspect_timeout,
            cache=cache,
        )

        LOG.info("Verifying alignment of reported commands...")
        verify_all_steps_command_alignment(layout, chain_link_dict)

        selected_groups = None
        if layout.threshold_mode == THRESHOLD_MODE_GROUPED:
            LOG.info(
                "Verifying grouped threshold constraints and Step rules..."
            )
            # Search for a chain-wide consistent group selection. No inspection
            # command is executed until this succeeds, and rule state left
            # behind by rejected candidates is overwritten by the final rule
            # pass below.
            selected_groups = solve_grouped_threshold(
                layout, chain_link_dict, report=active_report
            )
            reduced_chain_link_dict = {
                step_name: group.link
                for step_name, group in selected_groups.items()
            }

            if active_report is not None:
                active_report.selected_groups = selected_groups
                active_report.proof = GroupedThresholdProof(selected_groups)

            if verification_report is not None:
                verification_report.selected_groups = selected_groups
                verification_report.proof = active_report.proof

            # Re-run the step rules once on the confirmed selection so that the
            # global rule trace and any side effects reflect the final proof and
            # never the state of a rejected candidate.
            verify_all_item_rules(layout.steps, reduced_chain_link_dict)

        else:
            LOG.info("Verifying threshold constraints...")
            verify_threshold_constraints(layout, chain_link_dict)
            reduced_chain_link_dict = reduce_chain_links(chain_link_dict)

            # NOTE: Processing step rules before executing inspections
            # guarantees that inspection commands don't run on compromised
            # target files, however, this also precludes step match rules from
            # referencing inspection artifacts.
            LOG.info("Verifying Step rules...")
            verify_all_item_rules(layout.steps, reduced_chain_link_dict)

        if cache is not None and layer_key is not None:
            report_record = None
            if (
                layout.threshold_mode == THRESHOLD_MODE_GROUPED
                and active_report is not None
            ):
                report_record = {
                    "candidate_groups": dict(active_report.candidate_groups),
                    "assignments_evaluated": (
                        active_report.assignments_evaluated
                    ),
                    "rule_evaluations": active_report.rule_evaluations,
                }

            cacheable_record = {
                "schema": _CACHE_SCHEMA,
                "layout": layout,
                "steps_metadata": steps_metadata,
                "mode": layout.threshold_mode,
                "selection_refs": (
                    _selection_refs_from_groups(selected_groups)
                    if selected_groups is not None
                    else None
                ),
                "report": report_record,
                "expirations": (layer_manifest or {}).get(
                    "expires", [layout.expires]
                ),
                "evidence_digest": stable_digest(layer_manifest),
            }

    LOG.info("Executing Inspection commands...")
    inspection_link_dict = run_all_inspections(
        layout, persist_inspection_links, inspect_timeout
    )
    if verification_report is not None:
        verification_report.inspection_executions = len(layout.inspect)

    LOG.info("Verifying Inspection rules...")
    # Artifact rules for inspections can reference links that correspond to
    # Steps or Inspections, hence the concatenation of both collections of links
    combined_links = reduced_chain_link_dict.copy()
    combined_links.update(inspection_link_dict)
    verify_all_item_rules(layout.inspect, combined_links)

    # Commit only after every current inspection and inspection rule has passed.
    # A step proof computed during a failed call is therefore never published by
    # that call.  Existing successful records may still be used for their
    # non-inspection proof, while inspections always run again above.
    if cache is not None and layer_key is not None and cacheable_record:
        cache.set(layer_key, cacheable_record)

    # We made it this far without exception that means, verification passed
    LOG.info("The software product passed all verification.")

    # Return a link file which summarizes the entire software supply chain
    # This is mostly relevant if the currently verified supply chain is embedded
    # in another supply chain
    return get_summary_link(layout, reduced_chain_link_dict, step_name)
