#!/usr/bin/env python3
"""Lineaje AI Policy Scanner — GitHub Actions edition.

Scans already-checked-out source code against Lineaje AI security policies
and prints results as structured JSON to stdout. Designed to run on a
GitHub-managed Ubuntu runner where the repository is pre-checked-out.

Usage::

    python scripts/gha_repo_scan.py --source-path repo --repo owner/repo --branch branch-name --mcp-server-url lineaje-mcp-server-url

Output (stdout, JSON)::

    {
      "status": "violations_found | compliant | error",
      "scan_metadata": {
        "repo": "owner/repo",
        "branch": "main",
        "head_sha": "abc1234",
        "scanned_at": "2026-05-10T10:00:00Z",
        "files_scanned": 150,
        "batches": 2,
        "failed_batches": 0
      },
      "report": "...(markdown policy report)...",
      "violations": [...],
      "aibom": [...],
      "scan_errors": []
    }

Required environment variable::

    LINEAJE_PAT_TOKEN  — Lineaje refresh token (exchanged for short-lived access tokens
                          via renew-access-token; override the endpoint with
                          LINEAJE_RENEW_ACCESS_TOKEN_URL)

Exit codes::

    0 — scan completed (check "status" field)
    1 — runtime error
    2 — configuration error (missing LINEAJE_PAT_TOKEN, missing repo/branch)
"""

from __future__ import annotations

import argparse
import asyncio
import atexit
import base64
import fnmatch
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://mcp.v2.prod.veedna.com/mcp"
SCANNER_BUILD = "2026-08-22-working-protocol-merged-v1"

MAX_SCAN_WORKERS = 4
REMEDIATION_BRANCH_PREFIX = "remediation/unifai-gha"
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120

# LINEAJE_PAT_TOKEN is a refresh token here — exchanged via renew-access-token
# for a short-lived MCP bearer. Override the full URL with LINEAJE_RENEW_ACCESS_TOKEN_URL
# (e.g. for commercialdev) if this prod default doesn't match your environment.
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://lineaje-identity-service.v2.prod.veedna.com"
    "/lineajeidentity/api/v1/auth/native/renew-access-token"
)

_ARCHIVE_EXCLUDE = {
    ".git", ".gitignore", ".gitattributes", ".gitmodules", ".hg", ".svn",
    ".env", ".env.local", ".env.development", ".env.production",
    "__pycache__", ".pytest_cache", "venv", ".venv", ".venv-scan", "env", ".tox",
    "htmlcov", ".coverage", ".mypy_cache", ".ruff_cache",
    "node_modules", ".yarn", ".pnp",
    "dist", "build", ".next", ".nuxt", "out", "coverage", ".cache",
    "target", ".gradle", ".m2",
    "Pods", ".expo",
    ".idea", ".vscode",
    ".lineaje-aiepo-security",
    "migrations", "alembic",
}
_ARCHIVE_EXCLUDE_GLOBS = {
    "*.secret", "*.key", "*.pem", "*.env.*",
    "*.zip", "*.tar", "*.tar.gz", "*.jar", "*.war", "*.swp", "*.swo",
    "*.lock", "package-lock.json", "yarn.lock", "Pipfile.lock",
    "poetry.lock", "Gemfile.lock", "Cargo.lock", "composer.lock",
    "*.min.js", "*.min.css", "*.map",
    "*_pb2.py", "*.pb.go", "*.pb.cc", "*.pb.h",
    "*.snap",
}
_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
    ".pyc", ".pyo", ".o", ".a",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".db", ".sqlite", ".sqlite3",
}

_MANIFEST_FILE_NAMES: frozenset = frozenset({
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock",
    "environment.yml", "environment.yaml",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "build.sbt",
    "Gemfile", "Gemfile.lock",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "packages.config", "packages.lock.json", "nuget.config", "Directory.Packages.props",
    "composer.json", "composer.lock",
    "Package.swift", "Package.resolved",
    "pubspec.yaml", "pubspec.lock",
    "mix.exs", "mix.lock",
})
_MANIFEST_GLOB_PATTERNS: tuple = ("*.csproj", "*.fsproj", "*.vbproj", "*.gemspec")

# ===========================================================================
# Token helpers
# ===========================================================================

def _normalize_token(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().lstrip("﻿").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _normalize_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    u = str(url).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
        u = u[1:-1].strip()
    return u


def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
    text = raw_text.strip() if raw_text else ""
    try:
        parsed: Any = json.loads(raw_text)
    except json.JSONDecodeError:
        # Some endpoints return a bare JWT string
        parts = text.split(".")
        if context == "renew-access-token" and len(parts) == 3:
            return {"access_token": text}
        raise RuntimeError(f"{context}: response is not valid JSON") from None
    for _ in range(8):
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            s = parsed.strip()
            if not s:
                raise RuntimeError(f"{context}: empty JSON string where object expected")
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parts = s.split(".")
                if context == "renew-access-token" and len(parts) == 3:
                    return {"access_token": s}
                raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
            continue
        break
    raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


class RefreshTokenTokenManager:
    """Exchange LINEAJE_PAT_TOKEN (a refresh token) for short-lived MCP bearer tokens,
    auto-renewing before expiry."""

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
        self._renew_url = (
            _normalize_url(renew_access_token_url)
            or _normalize_url(os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL"))
            or _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
        ).rstrip("/")
        self._lock = threading.Lock()
        self._access_token = ""
        self._access_deadline = 0.0
        try:
            self._skew_sec = int(os.environ.get(
                "LINEAJE_TOKEN_REFRESH_SKEW_SEC", str(_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC)
            ))
        except ValueError:
            self._skew_sec = _DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC

    def get_access_token(self) -> str:
        with self._lock:
            return self._get_unlocked()

    def _get_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _renew(self) -> None:
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
        req = urllib.request.Request(
            url, data=b"null",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"renew-access-token HTTP {exc.code}: {body[:800]}") from exc
        at = (data.get("access_token") or "").strip()
        if not at:
            raise RuntimeError(f"Token response missing access_token: {data!r}")
        self._access_token = at
        rt = (data.get("refresh_token") or "").strip()
        if rt:
            self._refresh_token = rt
        exp = data.get("expires_in")
        try:
            exp_sec = int(exp) if exp is not None else 3600
        except (TypeError, ValueError):
            exp_sec = 3600
        self._access_deadline = time.time() + max(60, exp_sec)
        logger.debug("Access token renewed; expires in %ds", exp_sec)


def _looks_like_jwt_blob(value: str) -> bool:
    s = value.strip()
    if s.count(".") != 2:
        return False
    hdr, payload, sig = s.split(".")
    if len(hdr) < 10 or len(payload) < 10 or len(sig) < 10:
        return False
    seg = re.compile(r"^[A-Za-z0-9_-]+$")
    return bool(seg.match(hdr) and seg.match(payload) and seg.match(sig))


_STANDARD_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def _looks_like_already_usable_bearer(value: str) -> bool:
    """True if *value* cannot possibly be the opaque, standard-Base64 refresh token
    that ``renew-access-token`` expects — i.e. it should be used directly as the MCP
    bearer instead of exchanged.

    Covers both shapes seen in practice:
      - a classic 3-part JWT (``_looks_like_jwt_blob``)
      - any other token containing base64url-only characters (``-``/``_``) that make
        it invalid *standard* Base64 — exchanging one of these fails server-side with
        e.g. ``"Illegal base64 character 5f"`` (``_``), since the identity service
        tries to base64-decode ``refreshToken`` using the standard alphabet and chokes
        on the very first non-standard character.
    """
    s = value.strip()
    if not s:
        return False
    if _looks_like_jwt_blob(s):
        return True
    return not bool(_STANDARD_BASE64_RE.match(s))


def build_bearer_getter() -> Callable[[], str]:
    """Return a callable that yields the MCP bearer, from LINEAJE_PAT_TOKEN.

    LINEAJE_PAT_TOKEN holds one of two different things depending on how it was minted:
    - A native **refresh token** (opaque, standard-Base64 string) — exchanged via
      renew-access-token to obtain a short-lived access token before use.
    - An already-short-lived **access token** (JWT, or any base64url-shaped token) —
      usable directly. Sending one of these to renew-access-token's ``refreshToken``
      param fails server-side ("Illegal base64 character 5f" etc.), since the identity
      service tries to base64-decode it with the *standard* alphabet and chokes on
      base64url's ``-``/``_`` or JWTs' internal ``.`` separators.
    """
    pat = _normalize_token(os.environ.get("LINEAJE_PAT_TOKEN", ""))
    if not pat:
        raise RuntimeError("LINEAJE_PAT_TOKEN is not set")
    if _looks_like_already_usable_bearer(pat):
        logger.info("LINEAJE_PAT_TOKEN is already a usable access token — using directly as bearer")
        return lambda: pat
    mgr = RefreshTokenTokenManager(pat)
    return mgr.get_access_token

# ===========================================================================
# HEAD SHA resolution
# ===========================================================================

def _resolve_head_sha_from_source(source_path: str) -> str:
    """Best-effort fallback: read HEAD's commit SHA straight from the git repo
    at *source_path* when neither ``--head-sha`` nor ``$GITHUB_SHA`` was given.

    Mirrors ``repo_scan.py``'s ``resolve_head_sha`` — since ``--source-path``
    is already a checked-out git repo, there's no need to ask the caller for
    a value git already knows. Returns "" (not raised) on any failure, so
    the normal "missing config" error still fires with a clear message.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_path, capture_output=True, text=True, timeout=10, check=True,
        )
        sha = result.stdout.strip()
        if sha:
            logger.info(
                "head_sha not provided — resolved from git HEAD at %s: %s",
                source_path, sha[:7],
            )
        return sha
    except Exception as exc:
        logger.debug("Could not resolve HEAD SHA from %s: %s", source_path, exc)
        return ""


# ===========================================================================
# Self-clone (--clone)
# ===========================================================================

def clone_repository(
    repo_slug: str,
    branch: str,
    clone_dir: str,
    scm_token: str,
    timeout: int = 300,
    max_retries: int = 2,
) -> None:
    """Clone *repo_slug* (``owner/repo``) at *branch* into *clone_dir*.

    Opt-in via ``--clone`` — this script normally assumes ``--source-path`` is
    already a checkout (its original GHA-runner design: ``actions/checkout``
    runs first). ``--clone`` lets it fetch the code itself instead, using an
    ``x-access-token``-authenticated HTTPS URL, same auth pattern already
    proven in ``veracode_repo_scan.py``'s ``clone_repository``.
    """
    auth_url = f"https://x-access-token:{scm_token}@github.com/{repo_slug}.git"
    logger.info("Cloning %s (branch=%s) ...", repo_slug, branch)
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--branch", branch, auth_url, clone_dir]
    last_exc: Exception = RuntimeError("Clone did not run")
    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            logger.warning("Retrying clone (attempt %d/%d) ...", attempt, max_retries)
            shutil.rmtree(clone_dir, ignore_errors=True)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
            logger.info("Clone successful: %s", clone_dir)
            return
        except subprocess.TimeoutExpired as exc:
            logger.error("Clone timed out after %ds (attempt %d/%d)", timeout, attempt, max_retries)
            last_exc = exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").replace(scm_token, "***")
            logger.error("Clone failed for %s: %s", repo_slug, stderr[:300])
            raise
    raise last_exc


# ===========================================================================
# File collection
# ===========================================================================

def _is_manifest_file(filename: str) -> bool:
    if filename in _MANIFEST_FILE_NAMES:
        return True
    return any(fnmatch.fnmatch(filename, pat) for pat in _MANIFEST_GLOB_PATTERNS)


def collect_repo_files(local_path: str) -> List[str]:
    file_list: List[str] = []
    for root, dirs, filenames in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in _ARCHIVE_EXCLUDE
            and not fnmatch.fnmatch(d, ".venv-*")
            and not fnmatch.fnmatch(d, "venv-*")
        ]
        for fname in filenames:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, local_path)
            ext = pathlib.Path(fname).suffix.lower()
            if ext in _BINARY_EXTENSIONS:
                continue
            if any(fnmatch.fnmatch(rel_path, g) for g in _ARCHIVE_EXCLUDE_GLOBS):
                continue
            if any(p in _ARCHIVE_EXCLUDE for p in pathlib.Path(rel_path).parts):
                continue
            file_list.append(rel_path.replace("\\", "/"))
    return file_list

# ===========================================================================
# Archive creation
# ===========================================================================

def _norm_archive_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def create_batch_archive(
    source_dir: str,
    archive_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: int = 0,
    run_id: str = "",
    manifest_files: Optional[List[str]] = None,
) -> str:
    archive_path = os.path.join(archive_dir, f"repo_scan_batch_{batch_index}.zip")
    extra_manifests = [m for m in (manifest_files or []) if m not in file_subset]
    all_files = list(file_subset) + extra_manifests
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in all_files:
            full_path = os.path.join(source_dir, rel_path)
            if os.path.isfile(full_path):
                zf.write(full_path, rel_path)
        metadata = {
            "scan_source": "gha_repo_scan",
            "repo": source_code_repo,
            "branch": branch,
            "head_sha": head_sha,
            "scan_type": "full_repository",
            "batch_index": batch_index,
            "batch_file_count": len(file_subset),
            "manifest_file_count": len(extra_manifests),
        }
        zf.writestr("user_metadata.json", json.dumps(metadata, indent=2))
    size_kb = os.path.getsize(archive_path) // 1024
    logger.info(
        "Batch archive #%d: %d files + %d manifests, %d KB",
        batch_index, len(file_subset), len(extra_manifests), size_kb,
    )
    return archive_path


def _batch_size(total_files: int) -> int:
    raw = (os.environ.get("UNIFAI_FILE_BATCH_SIZE") or "").strip()
    if not raw:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    try:
        size = int(raw)
    except ValueError:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    if size <= 0:
        return max(1, total_files)
    return size

# ===========================================================================
# MCP scan (SDK path only)
# ===========================================================================

def _upload_to_s3(presigned_url: str, archive_path: str) -> None:
    size = os.path.getsize(archive_path)
    logger.info("Uploading %d KB to S3 ...", size // 1024)
    with open(archive_path, "rb") as f:
        req = urllib.request.Request(
            presigned_url, data=f.read(), method="PUT",
            headers={"Content-Type": "application/zip"},
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"S3 upload failed: HTTP {resp.status}")
    logger.info("S3 upload complete")


def _parse_tool_result(result: Any) -> dict:
    """Parse Lineaje MCP tool output using the known-working response path.

    The working scanner reads ``result.content[0].text`` and JSON-decodes it.
    Keep that as the source of truth. We only add conservative unwrapping and
    fail-closed diagnostics so malformed/error responses cannot turn into a
    false zero-violation result.
    """
    if not hasattr(result, "content") or not result.content:
        return {
            "_parse_error": "MCP tool returned empty content",
            "raw": "",
        }

    raw = (
        result.content[0].text
        if hasattr(result.content[0], "text")
        else str(result.content[0])
    )
    raw_text = str(raw).strip()

    # Match the working implementation first.
    try:
        parsed: Any = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError):
        # A Markdown error report is a real scan failure, not "0 violations".
        lowered = raw_text.lower()
        if (
            "## error" in lowered
            or "**error**" in lowered
            or "analysis failed:" in lowered
        ):
            return {
                "_parse_error": "MCP analysis returned an error report",
                "raw": raw_text,
            }

        return {
            "_parse_error": "MCP tool response was not JSON",
            "raw": raw_text,
        }

    # Some tool layers JSON-encode the payload more than once.
    for _ in range(6):
        if isinstance(parsed, str):
            candidate = parsed.strip()
            try:
                parsed = json.loads(candidate)
                continue
            except (json.JSONDecodeError, TypeError):
                lowered = candidate.lower()
                if (
                    "## error" in lowered
                    or "**error**" in lowered
                    or "analysis failed:" in lowered
                ):
                    return {
                        "_parse_error": "MCP analysis returned an error report",
                        "raw": candidate,
                    }
                return {
                    "_parse_error": "MCP JSON payload decoded to plain text",
                    "raw": candidate,
                }
        break

    # A few wrappers return {"result": <actual JSON object/string>}.
    # Unwrap only when result is the sole payload key; otherwise preserve the
    # server's response exactly.
    for _ in range(4):
        if not (isinstance(parsed, dict) and set(parsed.keys()) == {"result"}):
            break

        nested = parsed["result"]
        if isinstance(nested, dict):
            parsed = nested
            continue

        if isinstance(nested, str):
            candidate = nested.strip()
            try:
                decoded = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                lowered = candidate.lower()
                if (
                    "## error" in lowered
                    or "**error**" in lowered
                    or "analysis failed:" in lowered
                ):
                    return {
                        "_parse_error": "MCP analysis returned an error report",
                        "raw": candidate,
                    }
                return {
                    "_parse_error": "MCP result envelope contained plain text",
                    "raw": candidate,
                }

            parsed = decoded
            continue

        return {
            "_parse_error": (
                "MCP result envelope contained unsupported type "
                f"{type(nested).__name__}"
            ),
            "raw": str(nested),
        }

    if not isinstance(parsed, dict):
        return {
            "_parse_error": (
                "MCP JSON response was not an object "
                f"({type(parsed).__name__})"
            ),
            "raw": raw_text,
        }

    return parsed


def _run_mcp_scan_via_client(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
) -> Dict[str, Any]:
    """Run the Lineaje MCP flow using the known-working MCP v1 protocol.

    ``head_sha`` is intentionally NOT sent as a custom MCP HTTP header.
    It is already embedded in ``user_metadata.json`` inside the uploaded
    archive and is used later for remediation-branch creation.

    The GitHub Action should pin ``mcp==1.14.1``.
    """
    try:
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession
    except ImportError as exc:
        raise RuntimeError(
            "This scanner's verified transport requires mcp==1.14.1. "
            "Pin the GitHub Action dependency to: pip install \"mcp==1.14.1\""
        ) from exc

    async def _scan() -> Dict[str, Any]:
        upload_args: Dict[str, Any] = {
            "source_code_repo": source_code_repo,
            "branch_or_tag": branch,
            "files_to_scan": files_to_scan,
        }

        logger.info("Using verified MCP Python SDK v1 streamable HTTP client")

        # ------------------------------------------------------------------
        # Step 1: get upload URL
        # Match known-working behavior exactly: Authorization header only.
        # ------------------------------------------------------------------
        tok1 = bearer_getter()
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok1}"},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("MCP step 1/3: get_upload_url")

                upload_result = _parse_tool_result(
                    await session.call_tool(
                        "get_upload_url",
                        arguments=upload_args,
                    )
                )

                if "_parse_error" in upload_result:
                    raise RuntimeError(
                        f"get_upload_url response parse failed: "
                        f"{upload_result['_parse_error']}; "
                        f"raw={upload_result.get('raw', '')[:3000]}"
                    )

                if not upload_result.get("success"):
                    raise RuntimeError(
                        f"get_upload_url failed: "
                        f"{upload_result.get('error', upload_result)}"
                    )

                archive_id = upload_result.get("archive_id")
                presigned_url = upload_result.get("presigned_url")

                if not archive_id or not presigned_url:
                    raise RuntimeError(
                        "get_upload_url response missing archive_id or presigned_url"
                    )

        # ------------------------------------------------------------------
        # Step 2: upload the ZIP produced by create_batch_archive().
        # This is intentionally unchanged from the known-working scanner.
        # ------------------------------------------------------------------
        logger.info("MCP step 2/3: upload to S3")
        _upload_to_s3(presigned_url, archive_path)

        # ------------------------------------------------------------------
        # Step 3: analyze uploaded archive
        # Again: Authorization header only, matching the working scanner.
        # ------------------------------------------------------------------
        tok2 = bearer_getter()
        try:
            sse_timeout = int(
                os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800")
            )
        except ValueError:
            sse_timeout = 1800
        sse_timeout = max(1, sse_timeout)

        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}"},
            sse_read_timeout=sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                logger.info(
                    "MCP step 3/3: analyze_uploaded_archive (timeout=%ds)",
                    sse_timeout,
                )

                analyze_args = dict(upload_args)
                analyze_args["archive_id"] = archive_id

                result = _parse_tool_result(
                    await session2.call_tool(
                        "analyze_uploaded_archive",
                        arguments=analyze_args,
                    )
                )

                if "_parse_error" in result:
                    raise RuntimeError(
                        f"analyze_uploaded_archive response parse failed: "
                        f"{result['_parse_error']}; "
                        f"raw={result.get('raw', '')[:4000]}"
                    )

                # Fail closed on an explicitly unsuccessful/error response.
                if result.get("success") is False:
                    raise RuntimeError(
                        f"analyze_uploaded_archive failed: "
                        f"{result.get('error') or result.get('message') or result}"
                    )

                if str(result.get("status", "")).strip().lower() in {
                    "error",
                    "failed",
                    "failure",
                    "scan_error",
                    "scan_failed",
                }:
                    raise RuntimeError(
                        f"analyze_uploaded_archive returned status="
                        f"{result.get('status')}: "
                        f"{result.get('error') or result.get('message') or result}"
                    )

                return result

    return asyncio.run(_scan())


def run_mcp_scan(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
) -> Dict[str, Any]:
    logger.info(
        "MCP scan: %d files, repo=%s, branch=%s",
        len(files_to_scan),
        source_code_repo,
        branch,
    )
    return _run_mcp_scan_via_client(
        server_url,
        bearer_getter,
        source_code_repo,
        branch,
        files_to_scan,
        archive_path,
        head_sha=head_sha,
    )


# ===========================================================================
# Parallel batch scan
# ===========================================================================

def parallel_batch_scan(
    batches: List[List[str]],
    source_dir: str,
    temp_dir: str,
    source_code_repo: str,
    branch: str,
    head_sha: str,
    run_id: str,
    server_url: str,
    bearer_getter: Callable[[], str],
    manifest_files: Optional[List[str]] = None,
    max_workers: int = MAX_SCAN_WORKERS,
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, str]], int, List[str]]:
    all_remediation_actions: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    all_aibom: List[Dict[str, str]] = []
    aibom_seen: set = set()
    failed_batch_count = 0
    failure_details: List[str] = []
    lock = threading.Lock()

    def _scan_one(batch_idx: int, batch_files: List[str]) -> Tuple[int, Dict[str, Any]]:
        logger.info("Batch %d/%d: %d files", batch_idx, len(batches), len(batch_files))
        archive_path = create_batch_archive(
            source_dir, temp_dir, batch_files,
            source_code_repo, branch, head_sha, batch_idx, run_id=run_id,
            manifest_files=manifest_files,
        )
        result = run_mcp_scan(
            server_url, bearer_getter, source_code_repo, branch, batch_files, archive_path, head_sha=head_sha,
        )
        return batch_idx, result

    def _collect(batch_idx: int, mcp_result: Dict[str, Any]) -> None:
        if "_parse_error" in mcp_result:
            raise RuntimeError(
                f"Batch {batch_idx} MCP response parse failed: "
                f"{mcp_result['_parse_error']}"
            )

        # Preserve the known Lineaje response contract.
        batch_actions = mcp_result.get("remediation_actions", [])
        batch_report = mcp_result.get("report", "")
        batch_aibom = mcp_result.get("aibom", [])

        if not isinstance(batch_actions, list):
            raise RuntimeError(
                f"Batch {batch_idx} returned invalid remediation_actions type: "
                f"{type(batch_actions).__name__}"
            )
        if not isinstance(batch_aibom, list):
            raise RuntimeError(
                f"Batch {batch_idx} returned invalid aibom type: "
                f"{type(batch_aibom).__name__}"
            )

        logger.info(
            "Batch %d/%d done: status=%s violations=%d aibom=%d",
            batch_idx,
            len(batches),
            mcp_result.get("status", "unknown"),
            len(batch_actions),
            len(batch_aibom),
        )

        with lock:
            all_remediation_actions.extend(batch_actions)
            if batch_report:
                all_reports.append(batch_report)
            for entry in batch_aibom:
                if not isinstance(entry, dict):
                    continue
                key = (entry.get("name", ""), entry.get("source_file", ""))
                if key not in aibom_seen:
                    aibom_seen.add(key)
                    all_aibom.append(entry)

    workers = min(len(batches), max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_scan_one, idx, files): idx for idx, files in enumerate(batches, 1)}
        for future in as_completed(future_map):
            batch_idx = future_map[future]
            try:
                _, mcp_result = future.result()
                _collect(batch_idx, mcp_result)
            except BaseException as exc:
                failed_batch_count += 1
                # Unwrap ExceptionGroup / TaskGroup to surface the real cause
                cause = exc
                if hasattr(exc, "exceptions") and exc.exceptions:
                    cause = exc.exceptions[0]
                    if hasattr(cause, "exceptions") and cause.exceptions:
                        cause = cause.exceptions[0]
                detail = f"Batch {batch_idx}/{len(batches)} failed: {type(cause).__name__}: {cause}"
                logger.error("%s", detail)
                logger.debug("Full exception:", exc_info=exc)
                failure_details.append(detail)

    return all_remediation_actions, all_reports, all_aibom, failed_batch_count, failure_details

# ===========================================================================
# JSON output
# ===========================================================================

def build_json_output(
    *,
    status: str,
    repo: str,
    branch: str,
    head_sha: str,
    source_code_repo: str,
    files_scanned: int,
    batches: int,
    failed_batches: int,
    violations: List[Dict[str, Any]],
    aibom: Optional[List[Dict[str, str]]] = None,
    report: str = "",
    remediation_pr: Optional[int] = None,
    remediation_branch: str = "",
    failed_remediation_files: Optional[List[str]] = None,
    scan_errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "status": status,
        "scan_metadata": {
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "source_code_repo": source_code_repo,
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": files_scanned,
            "batches": batches,
            "failed_batches": failed_batches,
        },
        "report": report,
        "violations": violations,
        "aibom": aibom or [],
        "remediation_pr": remediation_pr,
        "remediation_branch": remediation_branch,
        "failed_remediation_files": failed_remediation_files or [],
        "scan_errors": scan_errors or [],
    }


def print_human_output(output: Dict[str, Any]) -> None:
    status = output.get("status", "unknown")
    violations = output.get("violations", [])
    scan_errors = output.get("scan_errors", [])
    metadata = output.get("scan_metadata", {})
    scanned_at = metadata.get("scanned_at", "")
    branch = metadata.get("branch", "")

    if status == "compliant":
        status_label = "✅ Compliant"
    elif status == "violations_found":
        status_label = "❌ Not Compliant"
    else:
        status_label = status

    print("# UnifAI Security Report")
    print()
    print(f"**Status:** {status_label}")
    if branch:
        print(f"**Branch:** `{branch}`")
    if scanned_at:
        print(f"**Scanned at:** {scanned_at}")

    if scan_errors:
        print("\n**Errors:**")
        for err in scan_errors:
            print(f"- {err}")
        print()

    if not violations:
        if status == "compliant":
            print("\nNo violations found.")
        return

    from collections import defaultdict
    by_file: Dict[str, List[str]] = defaultdict(list)
    for v in violations:
        file_ = v.get("file", "(unknown)")
        control = v.get("control", "(unknown)")
        by_file[file_].append(control)

    num_files = len(by_file)
    print(f"\n**{len(violations)} violation(s) across {num_files} file(s)**\n")

    print("| File | Policy Violations |")
    print("|------|-------------------|")

    for file_, controls in sorted(by_file.items()):
        numbered = "".join(f"{i}. {c}<br>" for i, c in enumerate(controls, 1))
        print(f"| `{file_}` | {numbered} |")


# ===========================================================================
# Patch application (ported from veracode_repo_scan.py, no external deps)
# ===========================================================================

def _normalize_for_patch_match(s: str) -> str:
    return re.sub(r"[ \t]+", " ", s)


def _apply_fix_entry(content: str, original: str, replacement: str) -> Tuple[str, bool]:
    if not original:
        return content, False

    if original in content:
        return content.replace(original, replacement, 1), True

    orig_stripped = original.strip()
    if orig_stripped and orig_stripped in content:
        return content.replace(orig_stripped, replacement, 1), True

    norm_orig = _normalize_for_patch_match(orig_stripped)
    norm_content = _normalize_for_patch_match(content)
    idx = norm_content.find(norm_orig)
    if idx != -1:
        orig_len = len(orig_stripped)
        real_idx = 0
        norm_walked = 0
        for ci, ch in enumerate(content):
            if norm_walked >= idx:
                real_idx = ci
                break
            norm_walked += len(_normalize_for_patch_match(ch))
        else:
            real_idx = len(content)
        sub = content[real_idx: real_idx + orig_len + 50]
        if orig_stripped in sub:
            actual_idx = content.find(orig_stripped, real_idx)
            if actual_idx != -1:
                return content[:actual_idx] + replacement + content[actual_idx + len(orig_stripped):], True

    orig_lines = [l for l in orig_stripped.splitlines() if l.strip()]
    if orig_lines:
        anchor = orig_lines[0].strip()
        if len(anchor) > 15:
            anchor_idx = content.find(anchor)
            if anchor_idx != -1:
                end_search = content.find(orig_lines[-1].strip(), anchor_idx) if len(orig_lines) > 1 else anchor_idx
                if end_search != -1:
                    end_idx = end_search + len(orig_lines[-1].strip())
                    found_block = content[anchor_idx:end_idx]
                    if len(found_block) < len(orig_stripped) * 2:
                        return content[:anchor_idx] + replacement + content[end_idx:], True

    return content, False


def _norm_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def _resolve_source_file(source_dir: str, filepath: str, file_list: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a violation filepath to (rel_path, content) from the live checkout."""
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_rel_path(raw)
    root = pathlib.Path(source_dir)

    candidate = root / raw
    if candidate.is_file():
        return norm_fp, candidate.read_text(errors="replace")

    # Try normalised path
    candidate2 = root / norm_fp
    if candidate2.is_file():
        return norm_fp, candidate2.read_text(errors="replace")

    # Basename fallback
    base = pathlib.Path(norm_fp).name
    matches = [f for f in file_list if pathlib.Path(f).name == base]
    if len(matches) == 1:
        full = root / matches[0]
        if full.is_file():
            return _norm_rel_path(matches[0]), full.read_text(errors="replace")

    logger.warning("Cannot resolve remediation file %r in source dir", raw)
    return None, None


def apply_pipeline_fix_code_to_clone(
    remediation_actions: List[Dict[str, Any]],
    source_dir: str,
    file_list: List[str],
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Apply fix_code patches from MCP remediation_actions to checked-out files.

    Returns (validated_fixes, failed_files, fix_table_rows).
    """
    validated_fixes: Dict[str, str] = {}
    failed_files: List[str] = []
    fix_table_rows: List[Dict[str, str]] = []

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for action in remediation_actions:
        fp = (action.get("file") or "").strip()
        if fp:
            by_file.setdefault(fp, []).append(action)

    for filepath, actions in by_file.items():
        has_fix_code = any(action.get("fix_code") for action in actions)
        if not has_fix_code:
            failed_files.append(filepath)
            continue

        rel_path, original_content = _resolve_source_file(source_dir, filepath, file_list)
        if rel_path is None or original_content is None:
            failed_files.append(filepath)
            continue

        content = original_content
        patch_applied = False
        for action in actions:
            for fix_entry in (action.get("fix_code") or []):
                original = fix_entry.get("original") or ""
                replacement = fix_entry.get("replacement", "")
                if not original.strip():
                    continue
                content, applied = _apply_fix_entry(content, original, replacement)
                if applied:
                    patch_applied = True
                else:
                    logger.debug(
                        "Patch not applied for %r — original snippet (%d chars) not found",
                        filepath, len(original),
                    )

        if patch_applied and content != original_content:
            validated_fixes[rel_path] = content
            for action in actions:
                fix_table_rows.append({
                    "policy": action.get("control", ""),
                    "description": (action.get("instruction") or "")[:200],
                    "file": filepath,
                })
        else:
            logger.warning("No patch applied for %r — snippets did not match file content", filepath)
            failed_files.append(filepath)

    return validated_fixes, failed_files, fix_table_rows


# ===========================================================================
# Remediation PR creation
# ===========================================================================

def _create_fix_pr(
    github_token: str,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
) -> Tuple[Optional[int], str]:
    """Commit fix_code patches to a remediation branch and open (or refresh) a PR."""
    try:
        import sys as _sys
        import os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
        from scm_client import GitHubClient  # type: ignore
    except ImportError:
        logger.error("scm_client.py not found — cannot create remediation PR")
        return None, ""

    if not validated_fixes:
        return None, ""

    if not head_sha:
        # Without a real SHA, both the short->full SHA lookup and the branch-creation POST to
        # /git/refs are guaranteed to 422 (GitHub logs an empty-SHA commit lookup, then rejects
        # a ref pointing at "" for needing 40 chars). Fail here with the real cause instead.
        logger.error(
            "Cannot create remediation branch: head_sha is empty. "
            "Pass --head-sha or ensure $GITHUB_SHA is set in the environment."
        )
        return None, ""

    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)
    sha_short = head_sha[:7]
    timestamp = time.strftime("%m%d%H%M")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}-{safe_branch.replace('/', '-')}-{sha_short}-{timestamp}"

    scm = GitHubClient(token=github_token)

    # Resolve short SHA to full 40-char SHA (GitHub's /git/refs API requires it)
    if len(head_sha) < 40:
        try:
            commit_data = scm._request("GET", f"/repos/{repo}/commits/{head_sha}")
            head_sha = commit_data["sha"]
        except Exception as exc:
            logger.warning("Could not resolve short SHA %s: %s", head_sha, exc)

    try:
        logger.info("Creating remediation branch %s from %s", remediation_branch, sha_short)
        scm.create_branch(repo, remediation_branch, head_sha)
    except Exception as exc:
        logger.error("Failed to create/verify remediation branch: %s", exc)
        return None, remediation_branch

    committed: List[str] = []
    for filepath, content in validated_fixes.items():
        blob_sha: Optional[str] = None
        try:
            blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
        except Exception:
            pass
        policies = ", ".join({r["policy"] for r in fix_table if r["file"] == filepath}) or "policy violations"
        message = f"fix({filepath}): remediate {policies} [unifai-gha-scan]"
        try:
            scm.commit_file(repo, remediation_branch, filepath, content.encode("utf-8"), message, sha=blob_sha)
            committed.append(filepath)
            logger.info("Committed fix: %s", filepath)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", filepath, exc)

    if not committed:
        logger.warning("No files committed — skipping PR creation")
        return None, remediation_branch

    title = f"[unifai-bot] fix: AI policy remediation for {branch}@{sha_short}"

    files_list = "\n".join(f"- `{f}`" for f in committed)
    failed_list = ("\n".join(f"- `{f}`" for f in (failed_files or []))) or "_None_"
    pr_body_lines = [
        "## UniFAI AI Policy Remediation",
        "",
        f"Automated fixes for policy violations detected in `{branch}` at `{sha_short}`.",
        "",
        f"### Files remediated ({len(committed)})",
        "",
        files_list,
        "",
        f"### Files without fixes ({len(failed_files or [])})",
        "",
        failed_list,
    ]
    if report:
        MAX_REPORT_CHARS = 56_000  # leave room for rest of PR body; GitHub cap is 65536
        report_text = report.strip()
        if len(report_text) > MAX_REPORT_CHARS:
            report_text = report_text[:MAX_REPORT_CHARS] + "\n\n---\n\n*…Report truncated for GitHub PR body size limit. Retrieve the full text from CI logs.*"
        pr_body_lines += ["", "---", "", "<details><summary>Full scan report</summary>", "", report_text, "", "</details>"]
    pr_body = "\n".join(pr_body_lines)

    try:
        pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, pr_body)
        logger.info("Created remediation PR #%d", pr_number)
        return pr_number, remediation_branch
    except Exception as exc:
        logger.error("Failed to create remediation PR: %s", exc)
        return None, remediation_branch


# ===========================================================================
# Main scan orchestration
# ===========================================================================

def _execute_scan(args: argparse.Namespace) -> int:
    logger.info("Scanner build: %s", SCANNER_BUILD)
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    branch = args.branch or os.environ.get("GITHUB_REF_NAME", "")
    head_sha = args.head_sha or os.environ.get("GITHUB_SHA", "")
    source_path = os.path.abspath(args.source_path)
    server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL
    source_code_repo = f"https://github.com/{repo}.git" if repo else source_path
    logger.info("Effective MCP server URL: %s", server_url)
    do_clone = getattr(args, "clone", False)
    github_token = (
        getattr(args, "github_token", None)
        or os.environ.get("GH_TOKEN", "")
        or os.environ.get("GITHUB_TOKEN", "")
    )

    # Validate config
    required = [("GITHUB_REPOSITORY / --repo", repo), ("GITHUB_REF_NAME / --branch", branch)]
    if do_clone:
        # Cloning needs a token unconditionally — there's nothing to scan without it,
        # regardless of whether --create-fix-pr is also set.
        required.append(("GH_TOKEN / GITHUB_TOKEN / --github-token (required with --clone)", github_token))
    missing = [n for n, v in required if not v]
    if missing:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Missing required config: {', '.join(missing)}"],
        )
        print_human_output(output)
        return 2

    if do_clone:
        # --clone: fetch repo/branch ourselves instead of assuming --source-path is
        # already a checkout — lets this script run outside a real GHA job (e.g. from
        # a plain VM) without a separate manual clone step.
        clone_dir = tempfile.mkdtemp(prefix="gha-repo-scan-clone-")
        try:
            clone_repository(repo, branch, clone_dir, github_token)
        except Exception as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            output = build_json_output(
                status="error", repo=repo, branch=branch, head_sha=head_sha,
                source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
                violations=[], scan_errors=[f"Clone failed: {exc}"],
            )
            print_human_output(output)
            return 1
        atexit.register(shutil.rmtree, clone_dir, ignore_errors=True)
        source_path = clone_dir
        logger.info("Cloned %s@%s into %s — scanning this checkout", repo, branch, clone_dir)

    if not head_sha:
        # Neither --head-sha nor $GITHUB_SHA (the latter is only set inside a real GHA
        # job) — fall back to reading it straight off the checkout being scanned
        # (the fresh clone above, when --clone was used).
        head_sha = _resolve_head_sha_from_source(source_path)

    if getattr(args, "create_fix_pr", False) and not head_sha:
        # head_sha is only load-bearing when we're about to create a remediation branch off it —
        # an empty value there produces a confusing cascade of GitHub API 422s, not a clear error.
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
            scan_errors=["Missing required config: GITHUB_SHA / --head-sha (required with --create-fix-pr)"],
        )
        print_human_output(output)
        return 2

    try:
        bearer_getter = build_bearer_getter()
        # Eagerly exchange LINEAJE_PAT_TOKEN for an access token now, so a bad/expired
        # refresh token fails fast here instead of after a full scan.
        access_token = bearer_getter()
        logger.info("Auth OK — renew-access-token exchange succeeded (token len=%d)", len(access_token))
    except Exception as exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Auth failed: {exc}"],
        )
        print_human_output(output)
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    scan_start = time.perf_counter()

    logger.info("Scanning source path: %s (repo=%s branch=%s sha=%s)", source_path, repo, branch, head_sha[:7] if head_sha else "?")

    # Step 1: Collect files
    file_list = collect_repo_files(source_path)
    if not file_list:
        logger.info("No scannable files found")
        output = build_json_output(
            status="compliant", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
        )
        print_human_output(output)
        return 0

    manifest_files = [f for f in file_list if _is_manifest_file(os.path.basename(f))]
    code_files = [f for f in file_list if not _is_manifest_file(os.path.basename(f))]
    scan_files = code_files if code_files else file_list
    batch_size = _batch_size(len(scan_files))
    batches = [scan_files[i: i + batch_size] for i in range(0, len(scan_files), batch_size)]
    logger.info(
        "Files: %d total (%d code, %d manifest) -> %d batch(es) of <=%d",
        len(file_list), len(code_files), len(manifest_files), len(batches), batch_size,
    )

    # Step 2: MCP scan
    with tempfile.TemporaryDirectory(prefix="gha-repo-scan-") as temp_dir:
        all_violations, all_reports, all_aibom, failed_batches_count, failure_details = parallel_batch_scan(
            batches=batches,
            source_dir=source_path,
            temp_dir=temp_dir,
            source_code_repo=source_code_repo,
            branch=branch,
            head_sha=head_sha,
            run_id=run_id,
            server_url=server_url,
            bearer_getter=bearer_getter,
            manifest_files=manifest_files or None,
        )

    elapsed = time.perf_counter() - scan_start
    logger.info(
        "Scan complete in %.1fs: %d violation(s), %d AIBOM entry/ies, %d failed batch(es)",
        elapsed, len(all_violations), len(all_aibom), failed_batches_count,
    )

    combined_report = "\n\n---\n\n".join(r for r in all_reports if r)

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details,
        )
        print_human_output(output)
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    # Step 3: Remediation — apply fix_code patches and create PR
    remediation_pr_number: Optional[int] = None
    remediation_branch = ""
    failed_rem_files: List[str] = []

    # github_token already resolved near the top of this function (also used for --clone).
    if all_violations and github_token and getattr(args, "create_fix_pr", False):
        logger.info(
            "STEP 3: Applying fix_code patches for %d violation(s)", len(all_violations)
        )
        try:
            validated_fixes, failed_rem_files, fix_table = apply_pipeline_fix_code_to_clone(
                all_violations, source_path, file_list
            )
            logger.info(
                "Patches applied: %d file(s); no fix_code: %d file(s)",
                len(validated_fixes), len(failed_rem_files),
            )
            if validated_fixes:
                remediation_pr_number, remediation_branch = _create_fix_pr(
                    github_token, repo, branch, head_sha,
                    validated_fixes, fix_table,
                    report=combined_report, failed_files=failed_rem_files,
                )
            else:
                logger.warning("No patches could be applied — skipping PR creation")
        except Exception as exc:
            logger.error("Remediation step failed: %s", exc)
    elif all_violations:
        logger.info("Skipping remediation — GITHUB_TOKEN / --github-token not set")

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        remediation_pr=remediation_pr_number,
        remediation_branch=remediation_branch,
        failed_remediation_files=failed_rem_files,
        scan_errors=failure_details,
    )
    print_human_output(output)
    return 0

# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lineaje AI Policy Scanner — GitHub Actions edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--source-path", default=".",
        help="Path to the checked-out source code (default: current directory). "
             "Ignored when --clone is set — the fresh clone is scanned instead.",
    )
    parser.add_argument(
        "--clone", action="store_true",
        help="Clone --repo/--branch into a temp dir using --github-token before scanning, "
             "instead of assuming --source-path is already a checkout (default: false). "
             "Lets this script run outside a real GHA job (e.g. a plain VM) without a "
             "separate manual clone step. Requires --github-token (or $GH_TOKEN / "
             "$GITHUB_TOKEN) regardless of --create-fix-pr.",
    )
    parser.add_argument(
        "--repo", default="",
        help="Repository owner/repo slug (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--branch", default="",
        help="Branch name (default: $GITHUB_REF_NAME)",
    )
    parser.add_argument(
        "--head-sha", default="",
        help="Commit SHA (default: $GITHUB_SHA)",
    )
    parser.add_argument(
        "--mcp-server-url", default="",
        help=f"MCP server URL (default: {MCP_SERVER_URL})",
    )
    parser.add_argument(
        "--github-token", default="",
        help="GitHub token for creating remediation PRs (default: $GH_TOKEN then $GITHUB_TOKEN). "
             "If not set, violations are reported but no PR is created.",
    )
    parser.add_argument(
        "--create-fix-pr", default=False, action="store_true",
        help="Create a remediation PR with fix_code patches (default: false).",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Always show INFO from this logger regardless of --debug
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print_human_output(err)
        return 1


if __name__ == "__main__":
    sys.exit(main())
