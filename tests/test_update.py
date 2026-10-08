"""Tests for auto-update and version management."""

from __future__ import annotations

import base64
import hashlib
import os
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cloakbrowser.config import (
    REFUSED_ENV_VARS,
    EngineIntegrityError,
    _version_newer,
    _version_tuple,
    get_cache_dir,
    get_chromium_version,
    get_download_url,
    get_effective_version,
    get_platform_tag,
)
from cloakbrowser.download import (
    BinaryVerificationError,
    _check_wrapper_update,
    _download_and_extract,
    _download_pro_binary,
    _ensure_pro_binary,
    _fetch_signed_manifest,
    _get_latest_chromium_version,
    _parse_checksums,
    _parse_manifest_version,
    _should_check_for_update,
    _verify_checksum,
    _verify_download_checksum,
    _verify_pro_download,
    _verify_signature,
    _write_version_marker,
    check_for_pro_update,
    check_for_update,
    clear_cache,
    ensure_binary,
)


@pytest.fixture
def cache_dir():
    """The binary cache root under test.

    Upstream tests pointed this at ``tmp_path`` with CLOAKBROWSER_CACHE_DIR. That
    variable is refused now, so the root is always ``~/.cloakbrowser`` — which
    conftest's HOME redirect already makes a fresh temp dir per test.
    """
    d = get_cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


class TestVersionComparison:
    def test_version_tuple_parsing(self):
        assert _version_tuple("145.0.7718.0") == (145, 0, 7718, 0)
        assert _version_tuple("142.0.7444.175") == (142, 0, 7444, 175)

    def test_newer_version(self):
        assert _version_newer("145.0.7718.0", "142.0.7444.175") is True

    def test_older_version(self):
        assert _version_newer("142.0.7444.175", "145.0.7718.0") is False

    def test_same_version(self):
        assert _version_newer("142.0.7444.175", "142.0.7444.175") is False

    def test_patch_bump(self):
        assert _version_newer("142.0.7444.176", "142.0.7444.175") is True

    def test_major_bump(self):
        assert _version_newer("143.0.0.0", "142.9.9999.999") is True

    def test_5th_segment_parsing(self):
        assert _version_tuple("145.0.7632.109.2") == (145, 0, 7632, 109, 2)

    def test_build_bump(self):
        assert _version_newer("145.0.7632.109.3", "145.0.7632.109.2") is True

    def test_build_suffix_newer_than_no_suffix(self):
        assert _version_newer("145.0.7632.109.2", "145.0.7632.109") is True

    def test_no_suffix_older_than_build_suffix(self):
        assert _version_newer("145.0.7632.109", "145.0.7632.109.2") is False

    def test_new_chromium_beats_old_build(self):
        assert _version_newer("146.0.0.0", "145.0.7632.109.2") is True


class TestDownloadUrl:
    def test_default_url_format(self):
        url = get_download_url()
        assert "cloakbrowser.dev" in url
        assert f"chromium-v{get_chromium_version()}" in url
        assert url.endswith(".tar.gz")

    def test_custom_version_url(self):
        url = get_download_url("145.0.7718.0")
        assert "chromium-v145.0.7718.0" in url

    def test_no_old_repo_reference(self):
        url = get_download_url()
        assert "chromium-stealth-builds" not in url


class TestShouldCheckForUpdate:
    """Only the rate limit can suppress an update check — there is no off switch.

    Inverted from the upstream ``test_disabled_by_env`` /
    ``test_disabled_by_env_case_insensitive`` / ``test_disabled_by_binary_override``
    / ``test_disabled_by_custom_download_url``. Staying current is the point of
    this fork, so each of those env vars must be powerless here (and is refused
    outright at ensure_binary — see TestRefusedEnvVarsAtEnsureBinary).
    """

    @pytest.mark.parametrize(
        "env",
        [
            {"CLOAKBROWSER_AUTO_UPDATE": "false"},
            {"CLOAKBROWSER_AUTO_UPDATE": "False"},
            {"CLOAKBROWSER_BINARY_PATH": "/some/path"},
            {"CLOAKBROWSER_DOWNLOAD_URL": "https://my-mirror.com"},
        ],
    )
    def test_env_cannot_disable_the_check(self, env):
        with patch.dict(os.environ, env):
            assert _should_check_for_update() is True

    def test_rate_limited(self, cache_dir):
        import time

        (cache_dir / ".last_update_check").write_text(str(time.time()))
        assert _should_check_for_update() is False

    def test_stale_rate_limit_allows_check(self, cache_dir):
        import time

        (cache_dir / ".last_update_check").write_text(str(time.time() - 7200))
        assert _should_check_for_update() is True


class TestEffectiveVersion:
    def test_no_marker_returns_platform_version(self, cache_dir):
        assert get_effective_version() == get_chromium_version()

    def test_marker_with_newer_version(self, cache_dir):
        marker = cache_dir / f"latest_version_{get_platform_tag()}"
        marker.write_text("999.0.0.0")
        # Binary doesn't exist, so should fall back
        assert get_effective_version() == get_chromium_version()

    def test_marker_with_older_version_ignored(self, cache_dir):
        marker = cache_dir / f"latest_version_{get_platform_tag()}"
        marker.write_text("100.0.0.0")
        assert get_effective_version() == get_chromium_version()


class TestGetLatestVersion:
    """Tests for _get_latest_chromium_version with platform-aware asset checking."""

    def _make_assets(self, platforms: list[str]) -> list[dict]:
        """Helper to build asset list from platform tags."""
        return [{"name": f"cloakbrowser-{p}.tar.gz"} for p in platforms]

    def _platform_tarball(self) -> str:
        return f"cloakbrowser-{get_platform_tag()}.tar.gz"

    def test_parses_chromium_tag_with_platform_asset(self):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "tag_name": "chromium-v145.0.7718.0",
                "draft": False,
                "assets": self._make_assets(
                    ["linux-x64", "darwin-arm64", "darwin-x64", "windows-x64"]
                ),
            },
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("cloakbrowser.download.httpx.get", return_value=mock_response):
            result = _get_latest_chromium_version()
            assert result == "145.0.7718.0"

    def test_skips_release_without_platform_asset(self):
        """If latest release has no asset for our platform, fall back to older release."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "tag_name": "chromium-v145.0.7718.0",
                "draft": False,
                "assets": self._make_assets(["linux-x64"]),  # Linux only
            },
            {
                "tag_name": "chromium-v142.0.7444.175",
                "draft": False,
                "assets": self._make_assets(
                    ["linux-x64", "darwin-arm64", "darwin-x64", "windows-x64"]
                ),
            },
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("cloakbrowser.download.httpx.get", return_value=mock_response):
            result = _get_latest_chromium_version()
            tag = get_platform_tag()
            if tag == "linux-x64":
                assert result == "145.0.7718.0"
            else:
                assert result == "142.0.7444.175"

    def test_skips_draft_releases(self):
        mock_response = MagicMock()
        all_platforms = ["linux-x64", "darwin-arm64", "darwin-x64", "windows-x64"]
        mock_response.json.return_value = [
            {
                "tag_name": "chromium-v999.0.0.0",
                "draft": True,
                "assets": self._make_assets(all_platforms),
            },
            {
                "tag_name": "chromium-v145.0.7718.0",
                "draft": False,
                "assets": self._make_assets(all_platforms),
            },
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("cloakbrowser.download.httpx.get", return_value=mock_response):
            result = _get_latest_chromium_version()
            assert result == "145.0.7718.0"

    def test_skips_non_chromium_tags(self):
        mock_response = MagicMock()
        all_platforms = ["linux-x64", "darwin-arm64", "darwin-x64", "windows-x64"]
        mock_response.json.return_value = [
            {
                "tag_name": "v0.2.0",
                "draft": False,
                "assets": self._make_assets(all_platforms),
            },
            {
                "tag_name": "chromium-v145.0.7718.0",
                "draft": False,
                "assets": self._make_assets(all_platforms),
            },
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("cloakbrowser.download.httpx.get", return_value=mock_response):
            result = _get_latest_chromium_version()
            assert result == "145.0.7718.0"

    def test_returns_none_when_no_platform_assets(self):
        """If no release has our platform, return None."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "tag_name": "chromium-v145.0.7718.0",
                "draft": False,
                "assets": [{"name": "cloakbrowser-freebsd-x64.tar.gz"}],
            },
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("cloakbrowser.download.httpx.get", return_value=mock_response):
            result = _get_latest_chromium_version()
            assert result is None

    def test_network_error_returns_none(self):
        with patch("cloakbrowser.download.httpx.get", side_effect=Exception("timeout")):
            result = _get_latest_chromium_version()
            assert result is None


class TestWrapperUpdateCheck:
    """Tests for _check_wrapper_update (PyPI version check)."""

    def setup_method(self):
        import cloakbrowser.download as dl

        dl._wrapper_update_checked = False

    def test_warns_when_newer_version_available(self, caplog):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"info": {"version": "99.0.0"}}
        mock_resp.raise_for_status = MagicMock()

        with patch("cloakbrowser.download.httpx.get", return_value=mock_resp):
            import logging

            with caplog.at_level(logging.WARNING):
                _check_wrapper_update()
            assert "Update available" in caplog.text
            assert "99.0.0" in caplog.text

    def test_silent_when_current(self, caplog):
        import cloakbrowser.download as dl

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"info": {"version": dl._wrapper_version}}
        mock_resp.raise_for_status = MagicMock()

        with patch("cloakbrowser.download.httpx.get", return_value=mock_resp):
            import logging

            with caplog.at_level(logging.WARNING):
                _check_wrapper_update()
            assert "Update available" not in caplog.text

    @pytest.mark.parametrize(
        "env",
        [
            {"CLOAKBROWSER_AUTO_UPDATE": "false"},
            {"CLOAKBROWSER_DOWNLOAD_URL": "https://mirror.example.com"},
        ],
    )
    def test_env_cannot_disable_the_wrapper_check(self, env):
        """Inverted from the upstream ``test_disabled_by_auto_update_env`` /
        ``test_disabled_by_custom_download_url``: neither var can silence the
        wrapper-version check any more."""
        with patch.dict(os.environ, env):
            with patch("cloakbrowser.download.httpx.get") as mock_get:
                _check_wrapper_update()
                mock_get.assert_called_once()

    def test_network_error_silent(self, caplog):
        with patch("cloakbrowser.download.httpx.get", side_effect=Exception("timeout")):
            import logging

            with caplog.at_level(logging.WARNING):
                _check_wrapper_update()
            assert "Update available" not in caplog.text

    def test_runs_only_once(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"info": {"version": "0.0.1"}}
        mock_resp.raise_for_status = MagicMock()

        with patch(
            "cloakbrowser.download.httpx.get", return_value=mock_resp
        ) as mock_get:
            _check_wrapper_update()
            _check_wrapper_update()
            assert mock_get.call_count == 1


class TestParseChecksums:
    HASH_A = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    HASH_B = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

    def test_standard_format(self):
        text = (
            f"{self.HASH_A}  cloakbrowser-linux-x64.tar.gz\n"
            f"{self.HASH_B}  cloakbrowser-darwin-arm64.tar.gz\n"
        )
        result = _parse_checksums(text)
        assert result["cloakbrowser-linux-x64.tar.gz"] == self.HASH_A
        assert result["cloakbrowser-darwin-arm64.tar.gz"] == self.HASH_B

    def test_binary_mode_asterisk(self):
        text = f"{self.HASH_A} *cloakbrowser-linux-x64.tar.gz\n"
        result = _parse_checksums(text)
        assert "cloakbrowser-linux-x64.tar.gz" in result

    def test_empty_lines_skipped(self):
        text = f"\n\n{self.HASH_A}  file.tar.gz\n\n"
        result = _parse_checksums(text)
        assert len(result) == 1

    def test_uppercase_lowered(self):
        text = f"{self.HASH_A.upper()}  file.tar.gz\n"
        result = _parse_checksums(text)
        assert result["file.tar.gz"] == self.HASH_A

    def test_empty_input(self):
        assert _parse_checksums("") == {}
        assert _parse_checksums("   \n  \n") == {}


class TestVerifyChecksum:
    def test_matching_checksum(self, tmp_path):
        content = b"test binary content"
        file = tmp_path / "test.tar.gz"
        file.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        # Should not raise
        _verify_checksum(file, expected)

    def test_mismatched_checksum(self, tmp_path):
        file = tmp_path / "test.tar.gz"
        file.write_bytes(b"real content")
        with pytest.raises(RuntimeError, match="Checksum verification failed"):
            _verify_checksum(file, "0" * 64)


class TestClearCache:
    def test_removes_dir(self, cache_dir):
        # Create some content
        (cache_dir / "chromium-145").mkdir()
        (cache_dir / "chromium-145" / "chrome").write_bytes(b"binary")
        clear_cache()
        assert not cache_dir.exists()

    def test_noop_if_missing(self):
        # No cache_dir fixture: the cache root has never been created in this test.
        assert not get_cache_dir().exists()
        clear_cache()  # Should not raise


class TestCheckForUpdate:
    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_returns_none_when_current(self, _mock_update):
        with patch(
            "cloakbrowser.download._get_latest_chromium_version", return_value=None
        ):
            assert check_for_update() is None

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_returns_none_on_network_error(self, _mock_update):
        with patch(
            "cloakbrowser.download._get_latest_chromium_version",
            side_effect=Exception("timeout"),
        ):
            # _get_latest_chromium_version catches exceptions internally, but
            # check_for_update itself can also fail — test graceful None return
            with patch(
                "cloakbrowser.download._get_latest_chromium_version", return_value=None
            ):
                assert check_for_update() is None

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_returns_version_when_newer(self, _mock_update, cache_dir):
        with patch(
            "cloakbrowser.download._get_latest_chromium_version",
            return_value="999.0.0.0",
        ):
            with patch("cloakbrowser.download._download_and_extract"):
                result = check_for_update()
                assert result == "999.0.0.0"

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_skips_download_if_already_cached(self, _mock_update, cache_dir):
        # Create the binary dir so it looks already downloaded
        binary_dir = cache_dir / "chromium-999.0.0.0"
        binary_dir.mkdir()
        with patch(
            "cloakbrowser.download._get_latest_chromium_version",
            return_value="999.0.0.0",
        ):
            with patch("cloakbrowser.download._download_and_extract") as mock_dl:
                result = check_for_update()
                assert result == "999.0.0.0"
                mock_dl.assert_not_called()


class TestRefusedEnvVarsAtEnsureBinary:
    """ensure_binary is the single chokepoint where an inherited environment that
    tries to redirect the engine is refused, before any resolution work happens."""

    @pytest.mark.parametrize("var", REFUSED_ENV_VARS)
    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_every_refused_var_blocks_the_launch(self, _mock_update, var):
        with patch.dict(os.environ, {var: "x"}):
            with patch(
                "cloakbrowser.download.check_platform_available",
                side_effect=AssertionError("MUST refuse before resolving a binary"),
            ):
                with pytest.raises(EngineIntegrityError, match=var):
                    ensure_binary()

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_refusal_precedes_license_resolution(self, _mock_update):
        """A refused var must not even trigger a license lookup (no network, no
        chance of the Pro path acting on an attacker-chosen origin)."""
        with patch.dict(os.environ, {"CLOAKBROWSER_DOWNLOAD_URL": "https://evil.test"}):
            with patch(
                "cloakbrowser.license.resolve_license_key",
                side_effect=AssertionError("MUST refuse before touching the license"),
            ):
                with pytest.raises(EngineIntegrityError):
                    ensure_binary()


class TestEnsureBinary:
    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_binary_path_env_is_refused_even_when_the_file_exists(
        self, _mock_update, tmp_path
    ):
        """Inverted from the upstream ``test_local_override``, which asserted that
        CLOAKBROWSER_BINARY_PATH launched an arbitrary local file.

        That was the sharpest escalation path in an inherited environment: any
        process that could set one variable chose which executable the wrapper
        ran. A real, existing file must be refused just as loudly as a bogus one,
        so the refusal cannot be mistaken for a missing-file error.
        """
        binary = tmp_path / "chrome"
        binary.write_bytes(b"binary")
        with patch.dict(os.environ, {"CLOAKBROWSER_BINARY_PATH": str(binary)}):
            with pytest.raises(EngineIntegrityError, match="CLOAKBROWSER_BINARY_PATH"):
                ensure_binary()

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_binary_path_env_is_refused_before_any_filesystem_check(self, _mock_update):
        """Upstream raised FileNotFoundError here; the var never gets that far now."""
        with patch.dict(
            os.environ, {"CLOAKBROWSER_BINARY_PATH": "/nonexistent/chrome"}
        ):
            with pytest.raises(EngineIntegrityError, match="CLOAKBROWSER_BINARY_PATH"):
                ensure_binary()

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_cached_binary_found(self, _mock_update, cache_dir):
        # Create a fake cached binary
        with patch("cloakbrowser.download.get_binary_path") as mock_path:
            fake_binary = cache_dir / "chrome"
            fake_binary.write_bytes(b"binary")
            fake_binary.chmod(0o755)
            mock_path.return_value = fake_binary
            with patch("cloakbrowser.download.check_platform_available"):
                result = ensure_binary()
                assert result == str(fake_binary)

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_pinned_free_version_uses_exact_download(self, _mock_update, cache_dir):
        requested = "146.0.7680.177.5"
        fake_binary = cache_dir / "chrome"
        with patch("cloakbrowser.download.check_platform_available"):
            with patch(
                "cloakbrowser.download.get_binary_path", return_value=fake_binary
            ):

                def fake_download(version):
                    assert version == requested
                    fake_binary.write_bytes(b"binary")
                    fake_binary.chmod(0o755)

                with patch(
                    "cloakbrowser.download._download_and_extract",
                    side_effect=fake_download,
                ) as mock_dl:
                    result = ensure_binary(browser_version=requested)
                    mock_dl.assert_called_once_with(requested)
                    assert result == str(fake_binary)
                    # A pinned (rollback) download must NOT write the 'latest'
                    # marker — an unpinned launch must still resolve to latest.
                    assert not (
                        cache_dir / f"latest_version_{get_platform_tag()}"
                    ).exists()
                    assert not (cache_dir / "latest_version").exists()

    def test_pinned_pro_version_skips_latest_marker(self, cache_dir):
        # A pinned Pro (rollback) download must NOT write latest_pro_version_*,
        # so an unpinned Pro launch still resolves to the latest build.
        requested = "148.0.7778.215.2"
        fake_binary = cache_dir / "Chromium"
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        with patch(
            "cloakbrowser.download.get_binary_path", return_value=fake_binary
        ):

            def fake_pro_download(version, key):
                assert version == requested
                fake_binary.write_bytes(b"binary")
                fake_binary.chmod(0o755)

            with (
                patch(
                    "cloakbrowser.download._download_pro_binary",
                    side_effect=fake_pro_download,
                ),
                patch(
                    "cloakbrowser.license.get_pro_latest_version"
                ) as mock_latest,
            ):
                result = _ensure_pro_binary(
                    "cb_key",
                    requested_version=requested,
                    release_channel="preview",
                )
                assert result == str(fake_binary)
                mock_latest.assert_not_called()
                assert not marker.exists()

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_version_env_is_refused_not_merely_validated(self, _mock_update):
        """Inverted from the upstream ``test_pinned_free_env_rejects_unsafe_version``.

        Upstream read CLOAKBROWSER_VERSION and only rejected it when the value
        failed path-traversal validation; a *well-formed* value silently pinned the
        engine. Now the variable never reaches the validator at all.
        """
        with patch.dict(os.environ, {"CLOAKBROWSER_VERSION": "../../146.0.0.0"}):
            with pytest.raises(EngineIntegrityError, match="CLOAKBROWSER_VERSION"):
                ensure_binary()
        with patch.dict(os.environ, {"CLOAKBROWSER_VERSION": "146.0.7680.177.5"}):
            with pytest.raises(EngineIntegrityError, match="CLOAKBROWSER_VERSION"):
                ensure_binary()

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_unsafe_version_pin_still_rejected_via_the_api(self, _mock_update):
        """The traversal guard that used to live on the env path still applies to
        the browser_version argument, which is the only way to pin now."""
        with pytest.raises(ValueError, match="Invalid browser version pin"):
            ensure_binary(browser_version="../../146.0.0.0")

    @patch("cloakbrowser.download._maybe_trigger_update_check")
    def test_downloads_when_missing(self, _mock_update, cache_dir):
        fake_binary = cache_dir / "chrome"
        with patch("cloakbrowser.download.check_platform_available"):
            with patch("cloakbrowser.download.get_binary_path") as mock_path:
                # effective == platform_version (no marker), so fallback block skipped.
                # Call 1: get_binary_path(effective) → nonexistent (triggers download)
                # Call 2: get_binary_path() → fake_binary (post-download verify)
                mock_path.side_effect = [
                    cache_dir / "nonexistent",  # pre-download: not cached
                    fake_binary,  # post-download: binary ready
                ]
                with patch(
                    "cloakbrowser.download._download_and_extract"
                ) as mock_dl:
                    fake_binary.write_bytes(b"binary")
                    result = ensure_binary()
                    mock_dl.assert_called_once()
                    assert result == str(fake_binary)


def _make_pro_binary(version: str):
    """Create a fake cached, executable Pro binary for `version`."""
    from cloakbrowser.config import get_binary_path

    bp = get_binary_path(version, pro=True)
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_bytes(b"binary")
    bp.chmod(0o755)
    return bp


class TestUnpinnedProUpgrade:
    """Ticket 431: an unpinned Pro launch must track the server's latest stable,
    never roll down to a stale cached build, and never fall back to the free binary."""

    OLD = "148.0.7778.215.3"
    NEW = "148.0.7778.215.5"

    def test_upgrades_to_server_latest(self, cache_dir):
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        marker.write_text(self.OLD)
        _make_pro_binary(self.OLD)  # stale build cached

        def fake_download(version, key):
            assert version == self.NEW
            _make_pro_binary(self.NEW)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch(
                "cloakbrowser.download._download_pro_binary",
                side_effect=fake_download,
            ) as mock_dl,
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary("cb_key")
            mock_dl.assert_called_once()
            assert result == str(get_binary_path(self.NEW, pro=True))
            assert marker.read_text() == self.NEW  # marker advanced, not stuck

    def test_preview_uses_server_version_and_preview_marker(self, cache_dir):
        stable_marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        preview_marker = (
            cache_dir / f"latest_pro_version_preview_{get_platform_tag()}"
        )
        stable_marker.write_text(self.OLD)
        _make_pro_binary(self.OLD)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ) as mock_latest,
            patch(
                "cloakbrowser.download._download_pro_binary",
                side_effect=lambda version, key: _make_pro_binary(version),
            ) as mock_dl,
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary(
                "cb_key", release_channel="preview"
            )
            expected_path = str(get_binary_path(self.NEW, pro=True))

        mock_latest.assert_called_once_with("preview")
        mock_dl.assert_called_once_with(self.NEW, "cb_key")
        assert result == expected_path
        assert preview_marker.read_text() == self.NEW
        assert stable_marker.read_text() == self.OLD

    def test_preview_with_no_preview_build_warns_stable_fallback(self, cache_dir, capsys):
        """Preview requested but the server has no preview for this platform (fallback
        to stable) → print a one-line notice at launch."""
        import cloakbrowser.download as dl
        from cloakbrowser.license import ProReleaseInfo

        dl._preview_fallback_warned = False  # reset once-per-process guard
        _make_pro_binary(self.NEW)  # stable-fallback build already cached → no download

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch(
                "cloakbrowser.license.get_pro_latest_release",
                return_value=ProReleaseInfo(self.NEW, "preview", "stable", True),
            ),
            patch("cloakbrowser.download._download_pro_binary") as mock_dl,
        ):
            _ensure_pro_binary("cb_key", release_channel="preview")

        mock_dl.assert_not_called()
        assert "no preview build is available" in capsys.readouterr().err

    def test_genuine_preview_does_not_warn(self, cache_dir, capsys):
        """A real preview build (no fallback) prints no fallback notice."""
        import cloakbrowser.download as dl
        from cloakbrowser.license import ProReleaseInfo

        dl._preview_fallback_warned = False
        _make_pro_binary(self.NEW)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch(
                "cloakbrowser.license.get_pro_latest_release",
                return_value=ProReleaseInfo(self.NEW, "preview", "preview", False),
            ),
            patch("cloakbrowser.download._download_pro_binary"),
        ):
            _ensure_pro_binary("cb_key", release_channel="preview")

        assert "no preview build is available" not in capsys.readouterr().err

    def test_cached_newer_build_advances_marker_no_download(self, cache_dir):
        """Marker names an OLD build but a NEWER build is already cached (the customer's
        multi-version cache): resolve to newest, no download, and advance the marker so
        `info` never diverges from what launches."""
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        marker.write_text(self.OLD)
        _make_pro_binary(self.OLD)
        _make_pro_binary(self.NEW)  # newer build already on disk

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch("cloakbrowser.download._download_pro_binary") as mock_dl,
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary("cb_key")
            mock_dl.assert_not_called()  # already cached, no download
            assert result == str(get_binary_path(self.NEW, pro=True))
            assert marker.read_text() == self.NEW  # marker advanced, no stale divergence

    def test_steady_state_no_download(self, cache_dir):
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        marker.write_text(self.NEW)
        _make_pro_binary(self.NEW)  # already on latest

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch("cloakbrowser.download._download_pro_binary") as mock_dl,
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary("cb_key")
            mock_dl.assert_not_called()
            assert result == str(get_binary_path(self.NEW, pro=True))

    def test_server_down_uses_cached_pro(self, cache_dir):
        """Server unreachable → launch the cached Pro build, never fail, never free."""
        (cache_dir / f"latest_pro_version_{get_platform_tag()}").write_text(self.OLD)
        _make_pro_binary(self.OLD)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version", return_value=None
            ),
            patch("cloakbrowser.download._download_pro_binary") as mock_dl,
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary("cb_key")
            mock_dl.assert_not_called()
            assert result == str(get_binary_path(self.OLD, pro=True))

    def test_download_failure_falls_back_to_cached(self, cache_dir):
        """A failed upgrade download falls back to the cached Pro build, not free."""
        (cache_dir / f"latest_pro_version_{get_platform_tag()}").write_text(self.OLD)
        _make_pro_binary(self.OLD)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch(
                "cloakbrowser.download._download_pro_binary",
                side_effect=RuntimeError("network down"),
            ),
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary("cb_key")
            assert result == str(get_binary_path(self.OLD, pro=True))

    def test_verification_error_surfaces_not_cached_fallback(self, cache_dir):
        """A tampering signal (BinaryVerificationError) must propagate verbatim, even
        with a cached Pro build present — never masked by the cached-fallback path."""
        (cache_dir / f"latest_pro_version_{get_platform_tag()}").write_text(self.OLD)
        _make_pro_binary(self.OLD)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch(
                "cloakbrowser.download._download_pro_binary",
                side_effect=BinaryVerificationError("checksum mismatch"),
            ),
        ):
            with pytest.raises(BinaryVerificationError, match="checksum mismatch"):
                _ensure_pro_binary("cb_key")

    def test_no_cache_no_server_raises_never_free(self, cache_dir):
        """No cached Pro build AND no server → hard error, never the free binary."""
        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version", return_value=None
            ),
            patch("cloakbrowser.download._download_pro_binary") as mock_dl,
        ):
            with pytest.raises(RuntimeError, match="latest Pro version"):
                _ensure_pro_binary("cb_key")
            mock_dl.assert_not_called()

    def test_auto_update_env_cannot_freeze_a_stale_pro_build(self, cache_dir):
        """Inverted from the upstream ``test_auto_update_false_keeps_cached_no_server_check``.

        CLOAKBROWSER_AUTO_UPDATE=false used to pin a fleet to whatever Pro build
        happened to be cached, skipping the server check entirely. The upgrade must
        now happen regardless of what the environment says.
        """
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        marker.write_text(self.OLD)
        _make_pro_binary(self.OLD)

        with (
            patch.dict(os.environ, {"CLOAKBROWSER_AUTO_UPDATE": "false"}),
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ) as mock_latest,
            patch(
                "cloakbrowser.download._download_pro_binary",
                side_effect=lambda version, key: _make_pro_binary(version),
            ) as mock_dl,
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary("cb_key")

        mock_latest.assert_called_once()  # server still consulted
        mock_dl.assert_called_once_with(self.NEW, "cb_key")
        assert result == str(get_binary_path(self.NEW, pro=True))
        assert marker.read_text() == self.NEW

    def test_missing_cache_downloads_latest_never_free(self, cache_dir):
        """Marker names a build whose binary is gone → fetch latest Pro, never 146.x."""
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        marker.write_text(self.OLD)  # marker present, but NO binary on disk

        def fake_download(version, key):
            assert version == self.NEW  # never the free base (146.x)
            _make_pro_binary(self.NEW)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch(
                "cloakbrowser.download._download_pro_binary",
                side_effect=fake_download,
            ),
        ):
            from cloakbrowser.config import get_binary_path

            result = _ensure_pro_binary("cb_key")
            assert result == str(get_binary_path(self.NEW, pro=True))


class TestCheckForProUpdate:
    """`cloakbrowser update` for Pro installs (ticket 431 Fix 1)."""

    OLD = "148.0.7778.215.3"
    NEW = "148.0.7778.215.5"

    def test_downloads_and_writes_marker(self, cache_dir):
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        marker.write_text(self.OLD)
        _make_pro_binary(self.OLD)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch(
                "cloakbrowser.download._download_pro_binary",
                side_effect=lambda v, k: _make_pro_binary(v),
            ) as mock_dl,
        ):
            result = check_for_pro_update("cb_key")
            mock_dl.assert_called_once()
            assert result == self.NEW
            assert marker.read_text() == self.NEW

    def test_already_latest_returns_none(self, cache_dir):
        marker = cache_dir / f"latest_pro_version_{get_platform_tag()}"
        marker.write_text(self.NEW)
        _make_pro_binary(self.NEW)

        with (
            patch(
                "cloakbrowser.license.get_pro_latest_version",
                return_value=self.NEW,
            ),
            patch("cloakbrowser.download._download_pro_binary") as mock_dl,
        ):
            assert check_for_pro_update("cb_key") is None
            mock_dl.assert_not_called()

    def test_server_down_returns_none(self, cache_dir):
        with patch(
            "cloakbrowser.license.get_pro_latest_version", return_value=None
        ):
            assert check_for_pro_update("cb_key") is None


class TestEffectiveVersionProNoFreeFallback:
    """get_effective_version(pro=True) must return None — never the free base —
    when no cached Pro binary matches the marker (ticket 431 Fix 4)."""

    def test_none_when_no_cached_pro_binary(self, cache_dir):
        # Marker points at a version whose binary is not on disk.
        (cache_dir / f"latest_pro_version_{get_platform_tag()}").write_text(
            "148.0.7778.215.5"
        )
        assert get_effective_version(pro=True) is None

    def test_none_when_no_marker(self, cache_dir):
        assert get_effective_version(pro=True) is None
        # Free tier still resolves to a concrete version.
        assert get_effective_version(pro=False) == get_chromium_version()


class TestWriteVersionMarker:
    def test_creates_file(self, cache_dir):
        _write_version_marker("999.0.0.0")
        marker = cache_dir / f"latest_version_{get_platform_tag()}"
        assert marker.exists()
        assert marker.read_text() == "999.0.0.0"


class TestDownloadFallback:
    """Verify primary server (cloakbrowser.dev) → GitHub Releases fallback on HTTP errors."""

    def test_binary_download_falls_back_on_http_error(self, cache_dir):
        """HTTP error from primary triggers GitHub Releases fallback for binary download."""
        with patch.dict(os.environ, {}, clear=False):
            urls_called = []

            def mock_download_file(url, dest):
                urls_called.append(url)
                if "cloakbrowser.dev" in url:
                    raise Exception("HTTP 429 Too Many Requests")
                # GitHub fallback succeeds
                dest.write_bytes(b"fake")

            # This test exercises URL fallback, not verification — stub the
            # (now signature-based, non-bypassable) verify step.
            with (
                patch(
                    "cloakbrowser.download._download_file",
                    side_effect=mock_download_file,
                ),
                patch("cloakbrowser.download._verify_download_checksum"),
                patch("cloakbrowser.download._extract_archive"),
                patch("cloakbrowser.download._show_welcome"),
            ):
                _download_and_extract()

            assert len(urls_called) == 2
            assert "cloakbrowser.dev" in urls_called[0]
            assert "github.com" in urls_called[1]

    def test_github_fallback_is_unconditional(self, cache_dir):
        """Inverted from the upstream ``test_binary_download_no_fallback_with_custom_url``.

        Upstream skipped the GitHub fallback whenever CLOAKBROWSER_DOWNLOAD_URL was
        set. With no mirror path left, both pinned origins are always tried, and
        the error only propagates once both have failed.
        """
        urls_called = []

        def failing_download(url, dest):
            urls_called.append(url)
            raise Exception("503")

        with patch.dict(
            os.environ, {"CLOAKBROWSER_DOWNLOAD_URL": "https://my-mirror.com/releases"}
        ):
            with patch(
                "cloakbrowser.download._download_file", side_effect=failing_download
            ):
                with pytest.raises(Exception, match="503"):
                    _download_and_extract()

        assert len(urls_called) == 2
        assert "cloakbrowser.dev" in urls_called[0]
        assert "github.com" in urls_called[1]
        assert not any("my-mirror.com" in u for u in urls_called)


# ---------------------------------------------------------------------------
# Signed-manifest verification (Ed25519). Trust root is the pinned public key,
# not the same-origin SHA256SUMS — this is what closes M1 (#308).
# ---------------------------------------------------------------------------
def _make_key():
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, base64.b64encode(raw).decode()


def _sign(priv, manifest_bytes: bytes) -> bytes:
    """Return SHA256SUMS.sig content (base64 of the raw signature), as served."""
    return base64.b64encode(priv.sign(manifest_bytes))


class TestSignatureVerification:
    """_verify_signature: the cryptographic gate over the raw manifest bytes."""

    def test_valid_signature_passes(self):
        priv, pub_b64 = _make_key()
        manifest = b"abc  cloakbrowser-linux-x64.tar.gz\n"
        sig = _sign(priv, manifest)
        with patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]):
            _verify_signature(manifest, sig)  # no raise

    def test_tampered_manifest_fails(self):
        priv, pub_b64 = _make_key()
        manifest = b"abc  cloakbrowser-linux-x64.tar.gz\n"
        sig = _sign(priv, manifest)
        tampered = manifest.replace(b"abc", b"xyz")
        with patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]):
            with pytest.raises(RuntimeError, match="signature verification failed"):
                _verify_signature(tampered, sig)

    def test_wrong_key_fails(self):
        priv, _ = _make_key()
        _, other_pub = _make_key()
        manifest = b"data\n"
        sig = _sign(priv, manifest)
        with patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [other_pub]):
            with pytest.raises(RuntimeError, match="signature verification failed"):
                _verify_signature(manifest, sig)

    def test_malformed_signature_fails(self):
        _, pub_b64 = _make_key()
        with patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]):
            with pytest.raises(RuntimeError, match="Malformed"):
                _verify_signature(b"data\n", b"!!!not base64!!!")

    def test_placeholder_key_is_skipped_not_crashing(self):
        """An unparseable pinned key (placeholder) must not abort — a real key still validates."""
        priv, pub_b64 = _make_key()
        manifest = b"data\n"
        sig = _sign(priv, manifest)
        with patch(
            "cloakbrowser.download.BINARY_SIGNING_PUBKEYS",
            ["REPLACE_WITH_REAL_ED25519_PUBLIC_KEY_BASE64", pub_b64],
        ):
            _verify_signature(manifest, sig)  # no raise

    def test_key_rotation_second_key_accepts(self):
        """A manifest signed with the new key validates while the old key stays pinned."""
        old_priv, old_pub = _make_key()
        new_priv, new_pub = _make_key()
        manifest = b"rotated\n"
        sig = _sign(new_priv, manifest)
        with patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [old_pub, new_pub]):
            _verify_signature(manifest, sig)  # no raise


class TestVerifyDownloadChecksumSigned:
    """_verify_download_checksum on the official path: signature + version + hash, fail-closed."""

    def _hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _manifest(self, body: str, version: str | None = None) -> bytes:
        """Build a signed-manifest body with the bound version line prepended."""
        v = version if version is not None else get_chromium_version()
        return f"version={v}\n{body}".encode()

    def test_valid_manifest_and_hash_passes(self, tmp_path):
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"the real binary")
        tarball = get_download_url().rsplit("/", 1)[-1]
        manifest = self._manifest(f"{self._hash(b'the real binary')}  {tarball}\n")
        sig = _sign(priv, manifest)

        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download._fetch_signed_manifest",
                return_value=(manifest, sig),
            ),
        ):
            _verify_download_checksum(archive)  # no raise

    def test_tampered_binary_fails_hash(self, tmp_path):
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"a malicious binary")  # different bytes
        tarball = get_download_url().rsplit("/", 1)[-1]
        manifest = self._manifest(f"{self._hash(b'the real binary')}  {tarball}\n")
        sig = _sign(priv, manifest)

        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download._fetch_signed_manifest",
                return_value=(manifest, sig),
            ),
        ):
            with pytest.raises(RuntimeError, match="Checksum verification failed"):
                _verify_download_checksum(archive)

    def test_wrong_version_fails_downgrade(self, tmp_path):
        """A genuinely-signed manifest for a DIFFERENT version is rejected (downgrade)."""
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"the real binary")
        tarball = get_download_url().rsplit("/", 1)[-1]
        # Manifest declares an old version, but we ask for get_chromium_version().
        manifest = self._manifest(
            f"{self._hash(b'the real binary')}  {tarball}\n", version="1.0.0.0"
        )
        sig = _sign(priv, manifest)
        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download._fetch_signed_manifest",
                return_value=(manifest, sig),
            ),
        ):
            with pytest.raises(RuntimeError, match="Version mismatch"):
                _verify_download_checksum(archive)

    def test_missing_version_line_fails(self, tmp_path):
        """A signed manifest without a version line is rejected (binding required)."""
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"the real binary")
        tarball = get_download_url().rsplit("/", 1)[-1]
        manifest = (
            f"{self._hash(b'the real binary')}  {tarball}\n".encode()
        )  # no version=
        sig = _sign(priv, manifest)
        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download._fetch_signed_manifest",
                return_value=(manifest, sig),
            ),
        ):
            with pytest.raises(RuntimeError, match="Version mismatch"):
                _verify_download_checksum(archive)

    def test_missing_signed_manifest_fails_closed(self, tmp_path):
        archive = tmp_path / "binary"
        archive.write_bytes(b"x")
        with (
            patch("cloakbrowser.download._fetch_signed_manifest", return_value=None),
        ):
            with pytest.raises(RuntimeError, match="signed SHA256SUMS"):
                _verify_download_checksum(archive)

    def test_manifest_without_entry_fails(self, tmp_path):
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"x")
        manifest = self._manifest(
            "deadbeef  some-other-file.tar.gz\n"
        )  # no entry for our tarball
        sig = _sign(priv, manifest)
        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download._fetch_signed_manifest",
                return_value=(manifest, sig),
            ),
        ):
            with pytest.raises(RuntimeError, match="no entry for"):
                _verify_download_checksum(archive)

    def test_no_env_escape_from_the_signature_check(self, tmp_path):
        """Inverted from the upstream ``test_custom_url_uses_plain_checksum_and_skip``.

        That test asserted the one branch where verification was optional: a
        self-hosted CLOAKBROWSER_DOWNLOAD_URL fell back to a same-origin SHA256SUMS
        that CLOAKBROWSER_SKIP_CHECKSUM could skip outright. The branch is gone, so
        the signature is consulted and fails closed even with both vars set.
        """
        archive = tmp_path / "binary"
        archive.write_bytes(b"x")
        with patch.dict(
            os.environ,
            {
                "CLOAKBROWSER_DOWNLOAD_URL": "https://my-mirror.test",
                "CLOAKBROWSER_SKIP_CHECKSUM": "true",
            },
        ):
            with patch(
                "cloakbrowser.download._fetch_signed_manifest", return_value=None
            ) as mocked:
                with pytest.raises(RuntimeError, match="signed SHA256SUMS"):
                    _verify_download_checksum(archive)
            mocked.assert_called_once()


class TestVerifyProDownloadSigned:
    """_verify_pro_download: Pro binaries get the SAME non-bypassable signature
    check as the free official path (parity — closes the Pro M1 gap)."""

    PRO_VERSION = "147.0.1.0"

    def _hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _tarball(self) -> str:
        return get_download_url().rsplit("/", 1)[-1]

    def _mock_fetch(self, manifest: bytes, sig: bytes):
        """httpx.get stub: returns the .sig for *.sig URLs, manifest otherwise."""

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.content = sig if url.endswith(".sig") else manifest
            return resp

        return mock_get

    def test_valid_pro_manifest_passes(self, tmp_path):
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"the real pro binary")
        manifest = (
            f"version={self.PRO_VERSION}\n"
            f"{self._hash(b'the real pro binary')}  {self._tarball()}\n"
        ).encode()
        sig = _sign(priv, manifest)
        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download.httpx.get",
                side_effect=self._mock_fetch(manifest, sig),
            ),
        ):
            _verify_pro_download(archive, self.PRO_VERSION)  # no raise

    def test_skip_checksum_does_not_bypass(self, tmp_path):
        """CLOAKBROWSER_SKIP_CHECKSUM must NOT weaken Pro verification (the point)."""
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"a malicious pro binary")  # bytes differ from manifest
        manifest = (
            f"version={self.PRO_VERSION}\n"
            f"{self._hash(b'the real pro binary')}  {self._tarball()}\n"
        ).encode()
        sig = _sign(priv, manifest)
        with (
            patch.dict(os.environ, {"CLOAKBROWSER_SKIP_CHECKSUM": "true"}),
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download.httpx.get",
                side_effect=self._mock_fetch(manifest, sig),
            ),
        ):
            with pytest.raises(RuntimeError, match="Checksum verification failed"):
                _verify_pro_download(archive, self.PRO_VERSION)

    def test_missing_manifest_is_transient_not_tampering(self, tmp_path):
        """A failed manifest FETCH is transient (router falls back to free), so it
        must be a plain RuntimeError — NOT a BinaryVerificationError, which the
        router re-raises as a hard failure."""
        archive = tmp_path / "binary"
        archive.write_bytes(b"x")
        with patch("cloakbrowser.download.httpx.get", side_effect=Exception("404")):
            with pytest.raises(RuntimeError) as ei:
                _verify_pro_download(archive, self.PRO_VERSION)
        assert not isinstance(ei.value, BinaryVerificationError)

    def test_wrong_version_fails_downgrade(self, tmp_path):
        """A genuinely-signed Pro manifest for a DIFFERENT version is rejected."""
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"the real pro binary")
        manifest = (
            f"version=1.0.0.0\n"  # declares old version, we ask for PRO_VERSION
            f"{self._hash(b'the real pro binary')}  {self._tarball()}\n"
        ).encode()
        sig = _sign(priv, manifest)
        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download.httpx.get",
                side_effect=self._mock_fetch(manifest, sig),
            ),
        ):
            with pytest.raises(RuntimeError, match="Version mismatch"):
                _verify_pro_download(archive, self.PRO_VERSION)

    def test_tampered_manifest_fails_signature(self, tmp_path):
        """A manifest tampered after signing fails the signature gate (not the hash)."""
        priv, pub_b64 = _make_key()
        archive = tmp_path / "binary"
        archive.write_bytes(b"the real pro binary")
        manifest = (
            f"version={self.PRO_VERSION}\n"
            f"{self._hash(b'the real pro binary')}  {self._tarball()}\n"
        ).encode()
        sig = _sign(priv, manifest)
        tampered = manifest.replace(self._tarball().encode(), b"evil.tar.gz")
        with (
            patch("cloakbrowser.download.BINARY_SIGNING_PUBKEYS", [pub_b64]),
            patch(
                "cloakbrowser.download.httpx.get",
                side_effect=self._mock_fetch(tampered, sig),
            ),
        ):
            with pytest.raises(RuntimeError, match="signature verification failed"):
                _verify_pro_download(archive, self.PRO_VERSION)


class TestProDownloadVersionPinned:
    """The Pro download must request the explicit version, NOT /latest, so the
    served artifact matches the version-pinned signed manifest it's verified
    against (no latest-advances TOCTOU)."""

    def test_download_url_is_version_pinned(self):
        from cloakbrowser.config import DOWNLOAD_BASE_URL

        captured = {}

        def fake_download_file(url, dest, headers=None):
            captured["url"] = url

        with (
            patch(
                "cloakbrowser.download._download_file", side_effect=fake_download_file
            ),
            patch("cloakbrowser.download._verify_pro_download"),
            patch("cloakbrowser.download._extract_archive"),
        ):
            _download_pro_binary("147.0.1.0", "cb_key")

        assert captured["url"] == f"{DOWNLOAD_BASE_URL}/api/download/147.0.1.0"
        assert not captured["url"].endswith("/latest")


class TestVersionBinding:
    """The 'version=<v>' line: read by new wrappers, ignored by old parsers."""

    def test_parse_manifest_version(self):
        manifest = "version=146.0.7680.177.5\nabc  cloakbrowser-linux-x64.tar.gz\n"
        assert _parse_manifest_version(manifest) == "146.0.7680.177.5"

    def test_parse_manifest_version_absent(self):
        assert _parse_manifest_version("abc  cloakbrowser-linux-x64.tar.gz\n") is None

    def test_old_checksum_parser_ignores_version_line(self):
        """Regression: the version line must not pollute the old hash map."""
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        manifest = f"version=146.0.7680.177.5\n{h}  cloakbrowser-linux-x64.tar.gz\n"
        result = _parse_checksums(manifest)
        assert result == {"cloakbrowser-linux-x64.tar.gz": h}


class TestFetchSignedManifest:
    """_fetch_signed_manifest pairs SHA256SUMS + .sig from the same origin."""

    def test_fetches_both_from_primary(self):
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.content = b"SIG" if url.endswith(".sig") else b"MANIFEST"
            return resp

        with patch("cloakbrowser.download.httpx.get", side_effect=mock_get):
            result = _fetch_signed_manifest("1.2.3.4")
        assert result == (b"MANIFEST", b"SIG")

    def test_falls_back_to_github_when_primary_missing_sig(self):
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.content = b"SIG" if url.endswith(".sig") else b"MANIFEST"
            if "cloakbrowser.dev" in url and url.endswith(".sig"):
                resp.raise_for_status.side_effect = Exception("404")
            else:
                resp.raise_for_status = MagicMock()
            return resp

        with patch("cloakbrowser.download.httpx.get", side_effect=mock_get):
            result = _fetch_signed_manifest("1.2.3.4")
        assert result == (b"MANIFEST", b"SIG")

    def test_returns_none_when_all_fail(self):
        with patch("cloakbrowser.download.httpx.get", side_effect=Exception("network")):
            assert _fetch_signed_manifest("1.2.3.4") is None


# ---------------------------------------------------------------------------
# Welcome-banner cadence: free re-shows every 3 days, Pro shows once ever.
# ---------------------------------------------------------------------------
class TestWelcomeCadence:
    def test_pro_shows_once_then_never(self, tmp_path):
        import time as _time
        from cloakbrowser.download import _welcome_due

        marker = tmp_path / ".welcome_shown"
        assert _welcome_due(marker, pro=True) is True  # absent -> show
        marker.write_text(str(int(_time.time())))
        assert _welcome_due(marker, pro=True) is False  # exists -> never again

    def test_free_reshows_after_interval(self, tmp_path):
        import time as _time
        from cloakbrowser.download import _welcome_due, WELCOME_FREE_INTERVAL

        marker = tmp_path / ".welcome_shown"
        assert _welcome_due(marker, pro=False) is True  # absent -> show
        marker.write_text(str(int(_time.time())))
        assert _welcome_due(marker, pro=False) is False  # fresh -> skip
        marker.write_text(str(int(_time.time()) - WELCOME_FREE_INTERVAL - 10))
        assert _welcome_due(marker, pro=False) is True  # stale -> show again

    def test_legacy_empty_marker(self, tmp_path):
        from cloakbrowser.download import _welcome_due

        marker = tmp_path / ".welcome_shown"
        marker.write_text("")  # pre-cadence empty marker
        assert _welcome_due(marker, pro=False) is True  # unparseable -> free re-shows
        assert _welcome_due(marker, pro=True) is False  # pro: existence = already shown
