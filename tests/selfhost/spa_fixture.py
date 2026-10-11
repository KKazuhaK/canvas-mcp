"""A minimal built React bundle for isolated server tests."""

from __future__ import annotations

import pathlib

INDEX = (
    '<!doctype html><html lang="en"><head><meta charset="UTF-8">'
    '<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">'
    '<link rel="icon" type="image/svg+xml" href="/account/favicon.svg">'
    "<title>Canvas account</title>"
    '<script type="module" crossorigin src="/account/assets/index-abc123.js"></script>'
    '<link rel="modulepreload" crossorigin href="/account/assets/vendor-def456.js">'
    '<link rel="stylesheet" crossorigin href="/account/assets/index-abc123.css">'
    '</head><body><div id="root"></div></body></html>'
)

FILES = {
    "index-abc123.js": b"console.log('app');\n",
    "vendor-def456.js": b"export const v = 1;\n",
    "index-abc123.css": b"body{margin:0}\n",
    "font-1a2b.woff2": b"wOF2....",
}


def make_dist(
    root: pathlib.Path, *, index: str = INDEX, files: dict[str, bytes] | None = None
) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(index, encoding="utf-8")
    (root / "favicon.svg").write_text(
        "<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8"
    )
    assets = root / "assets"
    assets.mkdir(exist_ok=True)
    for name, body in (FILES if files is None else files).items():
        (assets / name).write_bytes(body)
    return root
