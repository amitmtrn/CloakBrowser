"""Unit tests for config.py — platform detection, paths, stealth args."""

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from cloakbrowser.config import (
    REFUSED_ENV_VARS,
    EngineIntegrityError,
    assert_no_env_overrides,
    binary_supports_headless_no_viewport,
    binary_supports_maximized_window,
    get_archive_ext,
    get_archive_name,
    get_binary_path,
    get_cache_dir,
    get_chromium_version,
    get_default_stealth_args,
    get_fallback_download_url,
    get_platform_tag,
    normalize_requested_version,
)


# ---------------------------------------------------------------------------
# Platform-specific binary paths
# ---------------------------------------------------------------------------


class TestGetBinaryPath:
    def test_linux(self):
        with patch("cloakbrowser.config.platform.system", return_value="Linux"):
            path = get_binary_path("145.0.0.0")
            assert str(path).endswith("chromium-145.0.0.0/chrome")

    def test_darwin(self):
        with patch("cloakbrowser.config.platform.system", return_value="Darwin"):
            path = get_binary_path("145.0.0.0")
            assert str(path).endswith(
                "chromium-145.0.0.0/Chromium.app/Contents/MacOS/Chromium"
            )

    def test_windows(self):
        with patch("cloakbrowser.config.platform.system", return_value="Windows"):
            path = get_binary_path("145.0.0.0")
            assert str(path).endswith("chromium-145.0.0.0/chrome.exe")


# ---------------------------------------------------------------------------
# Archive extension and name
# ---------------------------------------------------------------------------


class TestArchive:
    def test_ext_windows(self):
        with patch("cloakbrowser.config.platform.system", return_value="Windows"):
            assert get_archive_ext() == ".zip"

    def test_ext_unix(self):
        for system in ("Linux", "Darwin"):
            with patch("cloakbrowser.config.platform.system", return_value=system):
                assert get_archive_ext() == ".tar.gz"

    def test_archive_name(self):
        tag = get_platform_tag()
        ext = get_archive_ext()
        assert get_archive_name() == f"cloakbrowser-{tag}{ext}"

    def test_archive_name_custom_tag(self):
        name = get_archive_name("linux-x64")
        assert "cloakbrowser-linux-x64" in name


# ---------------------------------------------------------------------------
# Download URLs
# ---------------------------------------------------------------------------


class TestFallbackUrl:
    def test_github_releases_format(self):
        url = get_fallback_download_url("145.0.0.0")
        assert "github.com/CloakHQ/cloakbrowser/releases/download" in url
        assert "chromium-v145.0.0.0" in url

    def test_default_version(self):
        url = get_fallback_download_url()
        version = get_chromium_version()
        assert f"chromium-v{version}" in url


# ---------------------------------------------------------------------------
# Version pin
# ---------------------------------------------------------------------------


class TestVersionPin:
    def test_explicit_arg_accepted(self):
        """An explicit pin is honored, and a stray CLOAKBROWSER_VERSION has no say."""
        with patch.dict(os.environ, {"CLOAKBROWSER_VERSION": "146.0.0.0"}):
            assert normalize_requested_version("148.0.7778.215.2") == "148.0.7778.215.2"

    def test_ignores_env(self):
        """CLOAKBROWSER_VERSION no longer pins anything — only the API argument does.

        Inverted from the upstream ``test_reads_env``: the env var is refused at
        launch (see TestRefusedEnvVars), so normalize_requested_version must not
        consult it even as a fallback.
        """
        with patch.dict(os.environ, {"CLOAKBROWSER_VERSION": "148.0.7778.215.2"}):
            assert normalize_requested_version() is None

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError, match="Invalid browser version pin"):
            normalize_requested_version("../../148.0.7778.215.2")

    def test_rejects_non_ascii_digits(self):
        # Parity with JS (ASCII-only \d). Unicode digits must be rejected so the
        # same input behaves identically across Python / JS / .NET.
        with pytest.raises(ValueError, match="Invalid browser version pin"):
            normalize_requested_version("١٤٦.0.7680.177")


# ---------------------------------------------------------------------------
# Cache directory
# ---------------------------------------------------------------------------


class TestCacheDir:
    def test_default_path(self):
        with patch.dict(os.environ, {}, clear=False):
            # Remove override if set
            env = os.environ.copy()
            env.pop("CLOAKBROWSER_CACHE_DIR", None)
            with patch.dict(os.environ, env, clear=True):
                path = get_cache_dir()
                assert str(path).endswith(".cloakbrowser")

    def test_env_override_ignored(self, tmp_path):
        """CLOAKBROWSER_CACHE_DIR cannot move the cache root.

        Inverted from the upstream ``test_env_override``: the cache root is
        ``~/.cloakbrowser`` unconditionally, so a redirected cache (and with it a
        planted binary or license key) is not reachable through the environment.
        """
        with patch.dict(os.environ, {"CLOAKBROWSER_CACHE_DIR": str(tmp_path)}):
            assert get_cache_dir() != tmp_path
            assert get_cache_dir() == Path.home() / ".cloakbrowser"


# ---------------------------------------------------------------------------
# Platform tag
# ---------------------------------------------------------------------------


class TestPlatformTag:
    def test_unsupported_raises(self):
        with patch("cloakbrowser.config.platform.system", return_value="FreeBSD"):
            with patch("cloakbrowser.config.platform.machine", return_value="x86_64"):
                with pytest.raises(RuntimeError, match="Unsupported platform"):
                    get_platform_tag()


# ---------------------------------------------------------------------------
# Stealth args
# ---------------------------------------------------------------------------


class TestStealthArgs:
    def test_seed_uniqueness(self):
        """Two calls should produce different fingerprint seeds."""
        args1 = get_default_stealth_args()
        args2 = get_default_stealth_args()
        seed1 = [a for a in args1 if a.startswith("--fingerprint=")][0]
        seed2 = [a for a in args2 if a.startswith("--fingerprint=")][0]
        # Seeds are random 10000-99999 — extremely unlikely to collide
        assert seed1 != seed2

    @pytest.mark.parametrize("system", ["Darwin", "Linux", "Windows"])
    def test_persona_matches_the_real_host(self, system):
        """No ``--fingerprint-platform`` override on any host.

        Inverted from the upstream ``test_macos_profile`` /
        ``test_linux_windows_profile``, which asserted the spoofed personas
        (``=macos`` on Darwin, ``=windows`` on Linux). Claiming Windows from a
        Linux host contradicts the real display, GPU and font set, so the binary's
        own compile-time platform is now the only persona.
        """
        with patch("cloakbrowser.config.platform.system", return_value=system):
            args = get_default_stealth_args()
            assert not any(a.startswith("--fingerprint-platform") for a in args)
            # GPU flags removed — binary auto-generates from seed + platform
            assert not any("fingerprint-gpu-vendor" in a for a in args)
            assert not any("fingerprint-gpu-renderer" in a for a in args)

    @pytest.mark.parametrize("system", ["Darwin", "Linux", "Windows"])
    def test_sandbox_stays_on(self, system):
        """``--no-sandbox`` is never added by default, on any host.

        Upstream shipped it unconditionally, which disables the Chromium sandbox
        for every user to paper over running as root.
        """
        with patch("cloakbrowser.config.platform.system", return_value=system):
            assert "--no-sandbox" not in get_default_stealth_args()

    def test_only_the_seed_flag(self):
        """The default arg list is exactly one ``--fingerprint=<seed>`` and nothing else."""
        args = get_default_stealth_args()
        assert len(args) == 1
        assert re.fullmatch(r"--fingerprint=\d{5}", args[0])


# ---------------------------------------------------------------------------
# Engine-redirecting environment variables
# ---------------------------------------------------------------------------


class TestRefusedEnvVars:
    """Every upstream override var is refused outright, not silently ignored.

    Fleet agents inherit the launcher's environment, so each of these was a way
    to repoint the wrapper at another binary/origin or skip verification without
    touching reviewed code.
    """

    def test_clean_env_passes(self):
        for var in REFUSED_ENV_VARS:
            os.environ.pop(var, None)
        assert_no_env_overrides() is None

    @pytest.mark.parametrize("var", REFUSED_ENV_VARS)
    def test_each_var_is_refused(self, var):
        with patch.dict(os.environ, {var: "x"}):
            with pytest.raises(EngineIntegrityError, match=var):
                assert_no_env_overrides()

    @pytest.mark.parametrize("var", REFUSED_ENV_VARS)
    def test_empty_value_is_not_an_override(self, var):
        """An exported-but-empty var is indistinguishable from unset; don't block on it."""
        with patch.dict(os.environ, {var: ""}):
            assert_no_env_overrides() is None

    def test_license_key_var_still_allowed(self):
        """The Pro binary itself consumes the license vars — they must stay readable."""
        assert "CLOAKBROWSER_LICENSE_KEY" not in REFUSED_ENV_VARS
        with patch.dict(os.environ, {"CLOAKBROWSER_LICENSE_KEY": "key-123"}):
            assert_no_env_overrides() is None

    def test_message_names_every_offender(self):
        with patch.dict(
            os.environ,
            {"CLOAKBROWSER_BINARY_PATH": "/tmp/chrome", "CLOAKBROWSER_SKIP_CHECKSUM": "true"},
        ):
            with pytest.raises(EngineIntegrityError) as exc:
                assert_no_env_overrides()
        assert "CLOAKBROWSER_BINARY_PATH" in str(exc.value)
        assert "CLOAKBROWSER_SKIP_CHECKSUM" in str(exc.value)


# ---------------------------------------------------------------------------
# Headless no_viewport version gate
# ---------------------------------------------------------------------------


class TestHeadlessNoViewportGate:
    """binary_supports_headless_no_viewport() — parity-critical: JS and .NET mirror this.

    Threshold is HEADLESS_NO_VIEWPORT_MIN_VERSION (an unshipped version), so the
    resolved-version path is a no-op today; the declared-version path is what these
    tests pin.
    """

    def test_declared_below_threshold_off(self):
        # Current live Pro version — one build below the threshold => feature OFF.
        assert binary_supports_headless_no_viewport(browser_version="148.0.7778.215.3") is False

    def test_declared_at_threshold_on(self):
        assert binary_supports_headless_no_viewport(browser_version="148.0.7778.215.4") is True

    def test_declared_above_threshold_on(self):
        assert binary_supports_headless_no_viewport(browser_version="149.0.0.0") is True

    def test_declared_wins_despite_refused_binary_path(self):
        # The declared version decides the gate; CLOAKBROWSER_BINARY_PATH is refused
        # at launch and must not sway the capability decision either way.
        with patch.dict(os.environ, {"CLOAKBROWSER_BINARY_PATH": "/fake/chrome"}):
            assert binary_supports_headless_no_viewport(browser_version="149.0.0.0") is True

    def test_refused_binary_path_does_not_enable_gate(self):
        # A planted CLOAKBROWSER_BINARY_PATH cannot talk the wrapper into the
        # newer-binary code path: with no declared version the free floor decides.
        with patch.dict(os.environ, {"CLOAKBROWSER_BINARY_PATH": "/fake/chrome"}):
            assert binary_supports_headless_no_viewport() is False

    def test_resolved_free_version_off(self):
        # No key, no declared version => free version, below threshold.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLOAKBROWSER_LICENSE_KEY", None)
            os.environ.pop("CLOAKBROWSER_VERSION", None)
            assert binary_supports_headless_no_viewport() is False


class TestMaximizedWindowGate:
    """binary_supports_maximized_window() — parity-critical: JS and .NET mirror this.

    Shares HEADLESS_NO_VIEWPORT_MIN_VERSION today, so it tracks the same threshold
    as the no_viewport gate: below it, auto --start-maximized would make headless
    report outerWidth < innerWidth (a bot tell), so the flag must stay off.
    """

    def test_declared_below_threshold_off(self):
        assert binary_supports_maximized_window(browser_version="148.0.7778.215.3") is False

    def test_declared_at_threshold_on(self):
        assert binary_supports_maximized_window(browser_version="148.0.7778.215.4") is True

    def test_declared_above_threshold_on(self):
        assert binary_supports_maximized_window(browser_version="149.0.0.0") is True

    def test_refused_binary_path_does_not_enable_gate(self):
        with patch.dict(os.environ, {"CLOAKBROWSER_BINARY_PATH": "/fake/chrome"}):
            assert binary_supports_maximized_window() is False
