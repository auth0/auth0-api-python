import os

project = "auth0-api-python"
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".version")) as _version_file:
    release = _version_file.read().strip()

extensions = ["autoapi.extension", "sphinx.ext.napoleon"]

autoapi_dirs = ["../src"]
autoapi_root = "."
autoapi_keep_files = True
autoapi_add_toctree_entry = False
autoapi_options = ["members", "undoc-members", "show-inheritance", "show-module-summary"]

exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    # Skip the package page, which lists the submodules and repeats the package docstring.
    "auth0_api_python/index.rst",
]
