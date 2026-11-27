# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
Configure base logger for in_toto (see in_toto.log for details).

"""
import in_toto.log

# Public reusable verification cache.
from in_toto.cache import Cache, VerificationCache

# in-toto version
__version__ = "3.0.0"

__all__ = ["Cache", "VerificationCache", "__version__"]
