import re
import tempfile
from pathlib import Path

import git


def is_git_url(source: str) -> bool:
    return bool(re.match(r"(https?://|git@)", source))


def fetch_repo(source: str, clone_dir: str | None = None) -> Path:
    if is_git_url(source):
        target = Path(clone_dir) if clone_dir else Path(tempfile.mkdtemp(prefix="sv-"))
        git.Repo.clone_from(source, str(target), depth=1)
        return target

    path = Path(source)
    if not path.exists():
        raise ValueError(f"Local path does not exist: {source}")
    return path
