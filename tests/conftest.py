"""Shared pytest fixtures."""

import pytest


@pytest.fixture(autouse=True)
def isolated_cache_dir(request, tmp_path_factory, monkeypatch):
    """Keep the suite away from the developer's real ``~/.cloakbrowser``.

    A ``license.key`` (or a cached Pro version marker) in the real cache dir
    resolves the machine as Pro, which flips version-gated defaults such as the
    headless ``no_viewport`` shim and inline proxy auth — tests then assert
    against whatever the developer happens to have installed. ``monkeypatch``
    means a test setting its own ``CLOAKBROWSER_CACHE_DIR`` still wins.

    Real-browser tests (``slow`` / ``real_browser``) opt out and run like a user
    machine: the developer's key and latest binary, at a stable path. A fresh
    temp cache per test re-downloads the keyless binary every test, and its new
    path re-prompts path-keyed firewalls (LuLu) since the binary is ad-hoc signed.

    Redirects ``$HOME`` rather than setting ``CLOAKBROWSER_CACHE_DIR``: this fork
    refuses that variable at launch (config.REFUSED_ENV_VARS), so the cache root
    is ``Path.home() / ".cloakbrowser"`` with no override hook. Moving HOME keeps
    the isolation without putting a test-only seam in production code.
    """
    if request.node.get_closest_marker("slow") or request.node.get_closest_marker("real_browser"):
        return
    home = tmp_path_factory.mktemp("cloakbrowser-home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
