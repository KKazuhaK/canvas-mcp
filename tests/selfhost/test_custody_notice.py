"""Text changes require a reviewed hash update and a notice-version decision."""

import hashlib
import json
from pathlib import Path

import pytest

from canvas_mcp.core.selfhost.custody import CUSTODY_NOTICE_VERSION

ROOT = Path(__file__).resolve().parents[2]
PINS = {
    1: {
        "en": "1637f80788930c2b606ed8f4ddfe830da59d09a2b9fbf3e5e8edb6b005e01c26",
        "zh": "cd10e7cbbe5553db3e5fa019a3c1bdb6c32069b1a8c7bdcc31ff44e760dad39c",
    },
}


@pytest.mark.parametrize("lang", ["en", "zh"])
def test_notice_text_pins_require_review_of_substantive_changes(lang):
    body = json.loads((ROOT / "web" / "src" / "locales" / lang / "account.json").read_text(encoding="utf-8"))
    notice = body["custody"][f"v{CUSTODY_NOTICE_VERSION}"]
    assert hashlib.sha256(notice.encode("utf-8")).hexdigest() == PINS[CUSTODY_NOTICE_VERSION][lang]
