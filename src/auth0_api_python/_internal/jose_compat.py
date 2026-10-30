"""Select the supported JOSE implementation for the current Python runtime."""

import sys

# Authlib JOSE is retained for Python 3.9; newer runtimes use joserfc.
USE_LEGACY_JOSE = sys.version_info < (3, 10)
