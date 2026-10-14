"""The repository is English-only; Chinese appears only as i18n translation content.

Everything git tracks (code, comments, docs, env examples, compose and proxy
examples, scripts, tests, commit-facing text) must be English. Chinese is allowed
only where it is the translation itself or a test that asserts on that translation,
and every allowance below is explicit and has a one-line reason. When this test
fails, translate the listed ``file:line`` to English, or (for new translation
content) add it to the matching allowlist entry with a reason.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# CJK ideographs and extensions A, CJK symbols and punctuation, full-width forms.
# Written as escapes so this file itself contains no CJK characters.
CJK = re.compile(r"[\u3400-\u9fff\u3000-\u303f\uff00-\uffef]")

# The one place an English locale file may name Chinese: the language's own name.
ZH_ENDONYM = "\u4e2d\u6587"

# (2) Whole directories that are Chinese translation content.
TRANSLATION_PREFIXES = (
    "web/src/locales/zh/",  # the React UI's Chinese string tables
)

# (3) Files that may contain only the endonym of Chinese and nothing else Chinese.
ENDONYM_ONLY_FILES = (
    "web/src/locales/en/common.json",  # language switcher label for Chinese
)

# (4) Email message string tables, separate from their delivery implementation.
TRANSLATION_FILES = {
    "src/canvas_mcp/core/selfhost/email_translations.py": "English and Chinese reminder email string tables only",
}

# (5) Tests that assert the Chinese rendering of the translations above.
ZH_RENDERING_TESTS = {
    "web/src/components/admin/EnrollmentExpiry.test.tsx": "asserts the Chinese automatic expiry date and state translations",
    "web/src/components/CustodyNotice.test.tsx": "asserts the Chinese custody notice translation",
    "web/src/i18n/i18n.test.ts": "asserts the Chinese strings the i18n setup loads",
    "web/src/router/documentTitle.test.tsx": "asserts the Chinese document title",
    "web/src/router/routing.test.tsx": "asserts the Chinese UI after switching language",
}

# (6) Upstream test data that deliberately contains non-ASCII text.
UPSTREAM_TEST_DATA = {
    "tests/core/test_course_resolver.py": "full-width digits as an identifier-parsing input",
    "tests/security/test_input_validation.py": "a Chinese string as an input-validation sample",
    "tests/security/test_sandbox_nonroot_user.py": "a non-ASCII string passed through the sandbox",
}

# (7) Binary files are skipped by extension, or by a NUL byte in the content.
BINARY_SUFFIXES = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".zip", ".gz",
        ".tgz", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".mov", ".sqlite3",
        ".db", ".pyc", ".whl",
    }
)  # fmt: skip

WHOLE_FILE_ALLOWED = set(TRANSLATION_FILES) | set(ZH_RENDERING_TESTS) | set(UPSTREAM_TEST_DATA)


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO,
        capture_output=True,
        check=True,
    )
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def _read_text(relative: str) -> str | None:
    """The file's text, or None for binary (or non-UTF-8) content and missing files."""
    path = REPO / relative
    if path.suffix.lower() in BINARY_SUFFIXES or not path.is_file():
        return None
    data = path.read_bytes()
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _cjk_lines(text: str) -> list[int]:
    return [
        number for number, line in enumerate(text.splitlines(), 1) if CJK.search(line)
    ]


def _is_translation_prefix(relative: str) -> bool:
    return relative.startswith(TRANSLATION_PREFIXES)


def find_violations() -> list[str]:
    found: list[str] = []
    for relative in _tracked_files():
        text = _read_text(relative)
        if text is None or not CJK.search(text):
            continue
        if _is_translation_prefix(relative) or relative in WHOLE_FILE_ALLOWED:
            continue
        if relative in ENDONYM_ONLY_FILES:
            for number, line in enumerate(text.splitlines(), 1):
                if CJK.search(line.replace(ZH_ENDONYM, "")):
                    found.append(f"{relative}:{number}: {line.strip()}")
            continue
        lines = text.splitlines()
        found.extend(
            f"{relative}:{number}: {lines[number - 1].strip()}"
            for number in _cjk_lines(text)
        )
    return found


def test_tracked_text_files_are_english_outside_the_i18n_allowlist():
    violations = find_violations()
    assert not violations, (
        "Chinese text outside the i18n allowlist (translate it to English, or add real "
        "translation content to the allowlist in tests/test_english_only.py with a reason):\n"
        + "\n".join(violations)
    )


@pytest.mark.parametrize("relative", sorted(WHOLE_FILE_ALLOWED))
def test_every_whole_file_allowance_still_contains_chinese(relative):
    """A stale allowance hides future violations: drop it when the Chinese is gone."""
    text = _read_text(relative)
    assert text is not None, f"{relative} is missing or binary"
    assert CJK.search(text), (
        f"{relative} no longer contains Chinese; remove it from the allowlist"
    )


def test_allowlisted_translation_content_and_endonym_files_exist():
    tracked = set(_tracked_files())
    assert any(name.startswith(TRANSLATION_PREFIXES) for name in tracked)
    for relative in ENDONYM_ONLY_FILES:
        assert relative in tracked, f"{relative} is not tracked"
    for relative in ENDONYM_ONLY_FILES:
        text = _read_text(relative)
        assert text is not None and ZH_ENDONYM in text
