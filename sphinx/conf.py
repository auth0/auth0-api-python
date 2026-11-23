project = "auth0-api-python"

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
