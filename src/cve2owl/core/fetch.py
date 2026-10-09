import json
import os
import shutil
import subprocess
import sys
import urllib.request
from collections.abc import Callable
from email.utils import formatdate, parsedate_to_datetime
from http import HTTPStatus
from pathlib import Path
from urllib.error import HTTPError

from .jsonio import JSONValue
from .log import logger as log

TIMEOUT_SECONDS = 120
HEADERS = {"User-Agent": "cve2owl"}


def git_sync(url: str, repo_dir: Path, ref: str | None = None) -> None:
    if (repo_dir / ".git").exists():
        log.info("Updating %s...", repo_dir)
        _git(repo_dir, "fetch", *_QUIET, "--tags", "origin")
    else:
        log.info("Cloning %s into %s...", url, repo_dir)
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        _git(None, "clone", *_QUIET, "--filter=blob:none", "--no-checkout", url, str(repo_dir))
    _git(repo_dir, "checkout", "--quiet", "--detach", ref or "origin/HEAD")


# cvelistV5 has hourly tags: listing each new one would bury the log. Progress only on a terminal.
_QUIET = ["--quiet", "--progress"] if sys.stderr.isatty() else ["--quiet"]


def _git(repo_dir: Path | None, *args: str) -> None:
    cwd_args = ["-C", str(repo_dir)] if repo_dir else []
    subprocess.run(["git", *cwd_args, *args], check=True)  # noqa: S603, S607


def download(url: str, dest: Path, *, force: bool = False) -> bool:
    request = urllib.request.Request(url, headers=HEADERS)
    if dest.exists() and not force:
        request.add_header("If-Modified-Since", formatdate(dest.stat().st_mtime, usegmt=True))

    log.info("Downloading %s...", url)
    part = dest.with_name(dest.name + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            with part.open("wb") as f:
                shutil.copyfileobj(response, f)
            last_modified = response.headers.get("Last-Modified")
    except HTTPError as e:
        if e.code == HTTPStatus.NOT_MODIFIED:
            log.info("  %s is up to date", dest)
            return False
        raise

    part.replace(dest)

    if last_modified:
        timestamp = parsedate_to_datetime(last_modified).timestamp()
        os.utime(dest, (timestamp, timestamp))
    return True


def get_json(url: str) -> JSONValue:
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def replace_dir(dest: Path, build: Callable[[Path], None]) -> None:
    tmp = dest.with_name(dest.name + ".tmp")
    old = dest.with_name(dest.name + ".old")
    for leftover in (tmp, old):
        if leftover.exists():
            shutil.rmtree(leftover)
    tmp.mkdir(parents=True)
    build(tmp)
    if dest.exists():
        dest.replace(old)
    tmp.replace(dest)
    if old.exists():
        log.info("Removing the previous %s...", dest)
        shutil.rmtree(old)
