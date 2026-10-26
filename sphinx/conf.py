import os
import sys

sys.path.insert(0, os.path.abspath("../src"))

project = "auth0-api-python"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.napoleon", "sphinx_markdown_builder"]
