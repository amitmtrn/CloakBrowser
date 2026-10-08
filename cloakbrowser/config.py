"""Stealth configuration and platform detection for cloakbrowser."""

from __future__ import annotations

import logging
import os
import platform
import random
import re
import time
import uuid
from pathlib import Path

logger = logging.getLogger("cloakbrowser")


class EngineIntegrityError(RuntimeError):
    """Raised when the environment tries to redirect which engine gets launched."""


class FingerprintSeedError(RuntimeError):
    """Raised when a profile's pinned fingerprint seed is missing or corrupt."""


# ---------------------------------------------------------------------------
# Engine identity is decided by this fork's pin, never by the environment.
#
# Fleet agents inherit the launcher's environment, so upstream's override vars
# are a privilege-escalation path: any of them lets an agent point the wrapper
# at a different binary, a different origin, or skip verification entirely,
# without touching reviewed code. This is an allowlist by omission — the vars
# below are refused outright rather than ignored, so an attempt is loud instead
# of silently downgrading to upstream defaults.
#
# Deliberately NOT a prefix sweep of CLOAKBROWSER_*: the license vars are
# consumed by the Pro binary itself and the fork's own launcher sets them.
# ---------------------------------------------------------------------------
REFUSED_ENV_VARS = (
    "CLOAKBROWSER_BINARY_PATH",
    "CLOAKBROWSER_CACHE_DIR",
    "CLOAKBROWSER_VERSION",
    "CLOAKBROWSER_RELEASE_CHANNEL",
    "CLOAKBROWSER_DOWNLOAD_URL",
    "CLOAKBROWSER_SKIP_CHECKSUM",
    "CLOAKBROWSER_AUTO_UPDATE",
    "CLOAKBROWSER_WIDEVINE_CDM",
    "CLOAKBROWSER_FETCH_WIDEVINE",
)


def assert_no_env_overrides() -> None:
    """Refuse to launch if the environment carries an engine-redirecting var."""
    present = sorted(v for v in REFUSED_ENV_VARS if os.environ.get(v))
    if present:
        raise EngineIntegrityError(
            "Refusing to launch: this fork pins the browser engine in code, but "
            f"the environment sets {', '.join(present)}. Unset them. If you need a "
            "different engine, change the pin in cloakbrowser/config.py and have "
            "it reviewed."
        )


# ---------------------------------------------------------------------------
# Chromium version shipped with this release.
# Different platforms may ship different versions during transition periods.
# CHROMIUM_VERSION is the latest across all platforms (for display/reference).
# Use get_chromium_version() for the current platform's actual version.
# ---------------------------------------------------------------------------
CHROMIUM_VERSION = "146.0.7680.177.5"

PLATFORM_CHROMIUM_VERSIONS: dict[str, str] = {
    "linux-x64": "146.0.7680.177.5",
    "linux-arm64": "146.0.7680.177.3",
    "darwin-arm64": "145.0.7632.109.2",
    "darwin-x64": "145.0.7632.109.2",
    "windows-x64": "146.0.7680.177.5",
}

# ---------------------------------------------------------------------------
# Ed25519 public keys for verifying downloaded binaries.
#
# Each release publishes SHA256SUMS and a detached signature SHA256SUMS.sig.
# The wrapper verifies that signature against the keys below before trusting
# any hash in the manifest, so the download origin alone cannot certify a
# tampered binary. Values are base64 of the 32-byte raw public key. Multiple
# entries are accepted to allow key rotation.
# ---------------------------------------------------------------------------
BINARY_SIGNING_PUBKEYS: list[str] = [
    "MKFKwIhUcKWq5xTuNA0Ovg99njcDEcEJvmWYYhApvaU=",
]

# ---------------------------------------------------------------------------
# Playwright default args to suppress — these leak automation signals.
# --enable-automation: exposes navigator.webdriver = true
# --enable-unsafe-swiftshader: forces software WebGL rendering via SwiftShader,
#   producing a distinctive renderer string that no real user browser has
# ---------------------------------------------------------------------------
IGNORE_DEFAULT_ARGS = ["--enable-automation", "--enable-unsafe-swiftshader"]


# ---------------------------------------------------------------------------
# Default stealth arguments passed to the patched Chromium binary.
# These activate source-level fingerprint patches compiled into the binary.
# ---------------------------------------------------------------------------
SEED_MIN, SEED_MAX = 10000, 99999

# Shared with the JS and .NET wrappers: decimal seed + newline, so a profile
# keeps its seed whichever wrapper opens it.
PROFILE_SEED_FILE = ".cloakbrowser-seed"


def _random_seed() -> int:
    return random.randint(SEED_MIN, SEED_MAX)


def _read_profile_seed(path: Path) -> int | None:
    """Stored seed, or None if the file is missing. Corrupt raises."""
    try:
        data = path.read_bytes()
        # Empty = a concurrent launch's exclusive create (no-hard-link fallback)
        # hasn't written yet; give it ~1s before calling the file corrupt.
        for _ in range(20):
            if data:
                break
            time.sleep(0.05)
            data = path.read_bytes()
    except FileNotFoundError:
        return None
    text = data.strip()
    if text.isdigit() and text.isascii() and SEED_MIN <= int(text) <= SEED_MAX:
        return int(text)
    # Upstream unlinks the file and mints a fresh seed, which silently presents
    # the account a brand-new device. Refuse instead: a corrupt seed is either
    # disk damage or tampering, and both need a human.
    raise FingerprintSeedError(
        f"Fingerprint seed file {path} is corrupt ({data[:32]!r}). Refusing to "
        "launch with a new identity. Restore the profile's seed from backup, or "
        "delete the profile if a new identity is genuinely intended."
    )


def _profile_is_initialized(profile: Path) -> bool:
    """True if Chromium has already written this profile (so it has an identity)."""
    return any((profile / marker).exists() for marker in ("Local State", "Default"))


def _write_synced(path: Path, mode: str, content: str) -> None:
    # newline="\n": same bytes as the JS/.NET wrappers (no \r\n on Windows)
    with open(path, mode, encoding="ascii", newline="\n") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


def persistent_seed_args(
    user_data_dir: str | os.PathLike, stealth_args: bool, args: list[str] | None
) -> list[str] | None:
    """Pin a persistent profile's fingerprint seed in ``<user_data_dir>/.cloakbrowser-seed``.

    The first launch creates the seed; later launches reuse it. Returned as a
    user arg, so it overrides the random stealth default via build_args dedup.
    An explicit ``--fingerprint`` in ``args`` (including ``=off``) or
    ``stealth_args=False`` leaves the file alone.

    A seed missing from an *already-initialized* profile is treated as tampering
    and refused, not silently re-minted — otherwise anyone who can unlink the
    file can hand the account a new device on the next launch.
    """
    if not stealth_args or not user_data_dir:
        return args
    if any(a.split("=", 1)[0] == "--fingerprint" for a in args or []):
        return args

    profile = Path(os.fspath(user_data_dir))
    path = profile / PROFILE_SEED_FILE
    seed = _read_profile_seed(path)
    if seed is None:
        if _profile_is_initialized(profile):
            raise FingerprintSeedError(
                f"Profile {profile} has Chromium data but no {PROFILE_SEED_FILE}. "
                "Refusing to launch with a new identity. Restore the seed file, or "
                "delete the profile if a new identity is genuinely intended."
            )
        profile.mkdir(parents=True, exist_ok=True)
        tmp = profile / f"{PROFILE_SEED_FILE}.{uuid.uuid4().hex}.tmp"
        content = f"{_random_seed()}\n"
        try:
            _write_synced(tmp, "w", content)
            # Publish without replacing: concurrent first launches all end up
            # with whichever seed was linked first.
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass
            except OSError as e:
                # No hard links (FAT/exFAT, some network mounts): exclusive create
                # still never overwrites. ponytail: a concurrent reader can catch
                # the file empty here and regenerate; link() avoids that window.
                logger.debug("Hard link unsupported for %s (%s); using exclusive create", path, e)
                try:
                    _write_synced(path, "x", content)
                except FileExistsError:
                    pass
        finally:
            try:
                tmp.unlink()
            except OSError as e:
                logger.warning("Failed to remove temp seed file %s: %s", tmp, e)
        # ponytail: if the winner's file is corrupt here (only via a concurrent
        # corrupt-file race), fail loudly rather than loop.
        seed = _read_profile_seed(path)
        if seed is None:
            raise FingerprintSeedError(f"Could not create fingerprint seed file {path}")
    return [f"--fingerprint={seed}", *(args or [])]


def get_default_stealth_args() -> list[str]:
    """Build fingerprint args with a random seed per launch.

    The persona always matches the real host: the binary already detects its own
    platform at compile time, so no ``--fingerprint-platform`` override is needed
    or wanted. Upstream spoofs Windows on Linux, which contradicts the real
    display, GPU and font set — the opposite of a consistent identity.

    The Chromium sandbox is left ON. Run the browser as an unprivileged user; it
    refuses to start as uid 0 without ``--no-sandbox``, and that refusal is the
    control working, not a bug to flag away.
    """
    seed = _random_seed()

    return [f"--fingerprint={seed}"]


# ---------------------------------------------------------------------------
# Default viewport — used for HEADLESS only (headed launches use no_viewport so
# the page tracks the real window). Headless has no window chrome, so a fixed
# viewport stays coherent (outer == inner) and gives deterministic dimensions.
# Models a maximized Chrome on 1080p Windows: screen=1920x1080,
# innerHeight=947 (minus ~85px Chrome UI: tabs + address bar + bookmarks).
# ---------------------------------------------------------------------------
DEFAULT_VIEWPORT = {"width": 1920, "height": 947}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
SUPPORTED_PLATFORMS: dict[tuple[str, str], str] = {
    ("Linux", "x86_64"): "linux-x64",
    ("Linux", "aarch64"): "linux-arm64",
    ("Darwin", "arm64"): "darwin-arm64",
    ("Darwin", "x86_64"): "darwin-x64",
    ("Windows", "AMD64"): "windows-x64",
    ("Windows", "x86_64"): "windows-x64",
}

# Platforms with pre-built binaries available for download (derived from version map).
AVAILABLE_PLATFORMS: set[str] = set(PLATFORM_CHROMIUM_VERSIONS.keys())


_VERSION_PIN_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){3,4}$")


def normalize_release_channel(release_channel: str | None = None) -> str:
    """Return the requested release channel, defaulting to Stable."""
    raw = release_channel if release_channel is not None else "stable"
    return "preview" if raw.strip().lower() == "preview" else "stable"


def normalize_requested_version(version: str | None = None) -> str | None:
    """Return an explicit Chromium version pin, or None.

    Only numeric dotted versions are accepted because the value is interpolated
    into cache paths and download URLs.
    """
    raw = version
    if raw is None:
        return None
    normalized = raw.strip()
    if not normalized:
        return None
    if not _VERSION_PIN_RE.fullmatch(normalized):
        raise ValueError(
            "Invalid browser version pin. Use a full numeric Chromium version, "
            "e.g. '148.0.7778.215.2'."
        )
    return normalized


def get_chromium_version() -> str:
    """Return the Chromium version for the current platform."""
    tag = get_platform_tag()
    return PLATFORM_CHROMIUM_VERSIONS.get(tag, CHROMIUM_VERSION)


def get_platform_tag() -> str:
    """Return the platform tag for binary download (e.g. 'linux-x64', 'darwin-arm64')."""
    system = platform.system()
    machine = platform.machine()
    tag = SUPPORTED_PLATFORMS.get((system, machine))
    if tag is None:
        raise RuntimeError(
            f"Unsupported platform: {system} {machine}. "
            f"Supported: {', '.join(f'{s}-{m}' for (s, m) in SUPPORTED_PLATFORMS)}"
        )
    return tag


# ---------------------------------------------------------------------------
# Binary cache paths
# ---------------------------------------------------------------------------
def get_cache_dir() -> Path:
    """Return the cache directory for downloaded binaries (``~/.cloakbrowser``)."""
    return Path.home() / ".cloakbrowser"


def get_binary_dir(version: str | None = None, pro: bool = False) -> Path:
    """Return the directory for a Chromium version binary."""
    v = version or get_chromium_version()
    suffix = "-pro" if pro else ""
    return get_cache_dir() / f"chromium-{v}{suffix}"


def get_binary_path(version: str | None = None, pro: bool = False) -> Path:
    """Return the expected path to the chrome executable."""
    binary_dir = get_binary_dir(version, pro=pro)

    if platform.system() == "Darwin":
        # macOS: Chromium.app bundle
        return binary_dir / "Chromium.app" / "Contents" / "MacOS" / "Chromium"
    elif platform.system() == "Windows":
        return binary_dir / "chrome.exe"
    else:
        # Linux: flat binary
        return binary_dir / "chrome"


def check_platform_available() -> None:
    """Raise a clear error if no pre-built binary exists for this platform."""
    tag = get_platform_tag()  # raises if platform unsupported entirely
    if tag not in AVAILABLE_PLATFORMS:
        available = ", ".join(sorted(AVAILABLE_PLATFORMS))
        import sys

        sys.exit(
            f"\n\033[1mCloakBrowser\033[0m — Pre-built binaries are currently only "
            f"available for: {available}.\n"
        )


def get_effective_version(
    pro: bool = False, release_channel: str | None = None
) -> str | None:
    """Return the best available version: auto-updated if available, else platform default.

    Reads a platform-scoped marker file from the cache directory.
    Returns the platform's hardcoded version if no update has been downloaded.

    When ``pro=True``, reads from the Pro-specific marker and returns ``None`` when
    no cached Pro binary matches it. A valid Pro license must NEVER fall back to the
    free binary, so there is deliberately no free-version fallback here — callers
    treat ``None`` as "resolve the latest Pro version from the server" instead.
    """
    base = get_chromium_version()
    cache = get_cache_dir()

    if pro:
        channel = normalize_release_channel(release_channel)
        marker_prefix = (
            "latest_pro_version_preview"
            if channel == "preview"
            else "latest_pro_version"
        )
        marker = cache / f"{marker_prefix}_{get_platform_tag()}"
        if marker.exists():
            try:
                version = marker.read_text().strip()
                if version:
                    binary = get_binary_path(version, pro=True)
                    # Match launch's _pro_binary_ready (exists AND executable) so
                    # `info` never reports a build that launch would reject.
                    if binary.exists() and os.access(binary, os.X_OK):
                        return version
            except (ValueError, OSError):
                pass
        return None

    # Free tier: try platform-scoped marker first, fall back to legacy marker
    for name in (f"latest_version_{get_platform_tag()}", "latest_version"):
        marker = cache / name
        if marker.exists():
            try:
                version = marker.read_text().strip()
                if version and _version_newer(version, base):
                    binary = get_binary_path(version)
                    if binary.exists():
                        return version
            except (ValueError, OSError):
                pass
    return base


def _version_tuple(v: str) -> tuple[int, ...]:
    """Parse '145.0.7718.0' into (145, 0, 7718, 0) for comparison."""
    return tuple(int(x) for x in v.split("."))


def _version_newer(a: str, b: str) -> bool:
    """Return True if version a is strictly newer than version b."""
    return _version_tuple(a) > _version_tuple(b)


# ---------------------------------------------------------------------------
# Download URL
# ---------------------------------------------------------------------------
DOWNLOAD_BASE_URL = "https://cloakbrowser.dev"

GITHUB_API_URL = "https://api.github.com/repos/CloakHQ/cloakbrowser/releases"

GITHUB_DOWNLOAD_BASE_URL = "https://github.com/CloakHQ/cloakbrowser/releases/download"


def get_archive_ext() -> str:
    """Return the archive extension for the current platform (.zip for Windows, .tar.gz otherwise)."""
    return ".zip" if platform.system() == "Windows" else ".tar.gz"


def get_archive_name(tag: str | None = None) -> str:
    """Return the archive filename for a platform tag (e.g. 'cloakbrowser-linux-x64.tar.gz')."""
    t = tag or get_platform_tag()
    return f"cloakbrowser-{t}{get_archive_ext()}"


def get_download_url(version: str | None = None) -> str:
    """Return the full download URL for the current platform's binary archive."""
    v = version or get_chromium_version()
    return f"{DOWNLOAD_BASE_URL}/chromium-v{v}/{get_archive_name()}"


def get_fallback_download_url(version: str | None = None) -> str:
    """Return the GitHub Releases fallback URL for the binary archive."""
    v = version or get_chromium_version()
    return f"{GITHUB_DOWNLOAD_BASE_URL}/chromium-v{v}/{get_archive_name()}"


# ---------------------------------------------------------------------------
# Headless viewport handling by binary version
# ---------------------------------------------------------------------------
# First Chromium build that reports coherent headless dimensions without an
# emulated viewport. On these binaries the wrapper launches headless with
# no_viewport; older binaries need a fixed DEFAULT_VIEWPORT to stay coherent.
# None => not shipped yet; feature off, behavior byte-identical to today.
# TODO: set to the chromium version string that first ships it.
HEADLESS_NO_VIEWPORT_MIN_VERSION: str | None = "148.0.7778.215.4"


def binary_supports_headless_no_viewport(
    license_key: str | None = None,
    browser_version: str | None = None,
    release_channel: str | None = None,
) -> bool:
    """Whether headless can launch with ``no_viewport`` on the resolved binary.

    Only binaries at or above ``HEADLESS_NO_VIEWPORT_MIN_VERSION`` qualify; older
    ones keep ``DEFAULT_VIEWPORT``.
    """
    if HEADLESS_NO_VIEWPORT_MIN_VERSION is None:
        return False
    try:
        declared = normalize_requested_version(browser_version)
    except ValueError:
        declared = None
    if declared:
        version = declared
    else:
        from .license import resolve_license_key

        pro = bool(resolve_license_key(license_key))
        version = get_effective_version(pro=pro, release_channel=release_channel)
    if version is None:
        return False
    try:
        return not _version_newer(HEADLESS_NO_VIEWPORT_MIN_VERSION, version)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Inline HTTP proxy authentication by binary version
# ---------------------------------------------------------------------------
# First Chromium build, per platform, whose binary can take inline HTTP proxy
# credentials (Chromium-native ``--proxy-server=http://user:pass@host``). Below
# the floor the wrapper MUST route credentialed HTTP/HTTPS proxies through
# Playwright's proxy dict instead — an older binary treats the ``user:pass@``
# authority as an invalid proxy host and drops proxy auth (#182).
#
# A single global threshold (like HEADLESS_NO_VIEWPORT_MIN_VERSION) can't model
# this: the capability landed in different build lineages at different points —
# linux-x64/windows-x64 have it at 146.0.7680.177.5, but the free macOS (145.x)
# and linux-arm64 (146.0.7680.177.3) floors predate it, so those only qualify
# once they resolve to a Pro/newer build (148+). Platforms absent from this map
# are treated as never-inline (unknown capability => safe fallback).
HTTP_PROXY_INLINE_AUTH_MIN_VERSION: dict[str, str] = {
    "linux-x64": "146.0.7680.177.5",
    "windows-x64": "146.0.7680.177.5",
    "linux-arm64": "148.0.7778.215.3",
    "darwin-arm64": "148.0.7778.215.3",
    "darwin-x64": "148.0.7778.215.3",
}


def binary_supports_http_proxy_inline_auth(
    license_key: str | None = None,
    browser_version: str | None = None,
    release_channel: str | None = None,
) -> bool:
    """Whether the resolved binary accepts inline HTTP proxy credentials.

    The capability is a function of the binary version; ``license_key`` only
    resolves *which* version launches (Pro build vs free default), exactly like
    ``binary_supports_headless_no_viewport``. A declared pin wins, else a valid
    Pro license resolves to the Pro build (which ships the patch), else the free
    per-platform default — then it compares to this platform's floor. Below the
    floor, credentialed HTTP proxies fall back to Playwright's proxy dict.
    """
    floor = HTTP_PROXY_INLINE_AUTH_MIN_VERSION.get(get_platform_tag())
    if floor is None:
        return False
    try:
        declared = normalize_requested_version(browser_version)
    except ValueError:
        declared = None
    if declared:
        version = declared
    else:
        from .license import resolve_license_key

        pro = bool(resolve_license_key(license_key))
        version = get_effective_version(pro=pro, release_channel=release_channel)
    if version is None:
        # Pro with no cached marker => resolve latest Pro from the server, which
        # is >= the floor by construction and always ships the patch.
        return True
    try:
        return not _version_newer(floor, version)
    except (ValueError, AttributeError):
        return False


def binary_supports_maximized_window(
    license_key: str | None = None,
    browser_version: str | None = None,
    release_channel: str | None = None,
) -> bool:
    """Whether the wrapper may auto-add ``--start-maximized``.

    Gated on the same threshold as the no_viewport shim: only binaries whose
    headless surface-fix + headed screen-clamp make a maximized window coherent
    (``outer == screen``). Below it, maximizing headless while the CDP viewport
    stays at 1280x720 yields ``outerWidth < innerWidth`` — an impossible-window
    bot tell — so the flag must NOT be added. Shares
    ``HEADLESS_NO_VIEWPORT_MIN_VERSION``; kept as its own name so the two can
    diverge later. Python, JS and .NET mirror this gate.
    """
    return binary_supports_headless_no_viewport(
        license_key, browser_version, release_channel
    )
