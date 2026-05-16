"""
shatterpoint — OSCP Recon Crawler
Attack Surface Mapper & Technology Fingerprinter
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

__author__ = "0xj4f"

try:
    # Resolved at install time by hatch-vcs from the latest git tag.
    __version__ = _pkg_version("shatterpoint")
except PackageNotFoundError:
    # Editable install before any tag exists, or running from a source
    # checkout without metadata. Fall back to the hatch-vcs generated
    # file if present; otherwise mark the build as unversioned-dev.
    try:
        from shatterpoint._version import __version__  # type: ignore[no-redef]
    except ImportError:
        __version__ = "0.0.0+unknown"
