import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class SignatureLoader:
    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or _PROJECT_ROOT / "data"

    def load(self, filename: str) -> dict:
        path = self.data_dir / filename
        if not path.exists():
            logger.debug("Signature file %s not found, skipping", path)
            return {}
        try:
            return yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError:
            logger.warning("Failed to parse %s", path)
            return {}

    def load_signatures(self, filename: str) -> list[dict]:
        data = self.load(filename)
        return data.get("signatures", [])

    def load_authors(self, filename: str) -> list[dict]:
        data = self.load(filename)
        return data.get("authors", [])

    def load_hashes(self, filename: str) -> list[dict]:
        data = self.load(filename)
        return data.get("hashes", [])

    def load_campaigns(self, filename: str) -> list[dict]:
        data = self.load(filename)
        return data.get("campaigns", [])
