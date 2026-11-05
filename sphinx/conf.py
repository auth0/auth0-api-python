import os

project = "auth0-api-python"
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".version")) as _version_file:
    release = _version_file.read().strip()

extensions = ["autoapi.extension", "sphinx.ext.napoleon"]

autoapi_dirs = ["../src"]
autoapi_options = ["members", "undoc-members", "show-inheritance", "show-module-summary"]
