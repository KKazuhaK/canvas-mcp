"""Text extraction from course documents (core/document_text.py).

The PDF/PPTX/DOCX fixtures are built in-process (a hand-written PDF, and
python-pptx / python-docx writers), so every expected string below is known
independently of the extractor under test.
"""

import builtins
import io
import os
import random
import zipfile

import pytest

from canvas_mcp.core import document_text as dt


def _installed(module: str) -> bool:
    try:
        __import__(module)
    except ImportError:
        return False
    return True


# The parsers come from the optional "documents" extra, which CI installs.
needs_pypdf = pytest.mark.skipif(not _installed("pypdf"), reason="pypdf not installed")
needs_pptx = pytest.mark.skipif(not _installed("pptx"), reason="python-pptx not installed")
needs_docx = pytest.mark.skipif(not _installed("docx"), reason="python-docx not installed")


class TestDetectKind:
    @pytest.mark.parametrize(
        ("content_type", "filename", "expected"),
        [
            ("application/pdf", "slides.pdf", dt.KIND_PDF),
            (
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "week3.pptx",
                dt.KIND_PPTX,
            ),
            (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "syllabus.docx",
                dt.KIND_DOCX,
            ),
            ("text/html; charset=utf-8", "page.html", dt.KIND_HTML),
            ("text/plain", "notes.txt", dt.KIND_TEXT),
            ("text/csv", "grades.csv", dt.KIND_TEXT),
            ("application/json", "data.json", dt.KIND_TEXT),
            # Canvas often stores Markdown and slides with a generic type.
            ("application/octet-stream", "README.MD", dt.KIND_TEXT),
            ("application/octet-stream", "Lecture 4.PDF", dt.KIND_PDF),
            ("unknown", "deck.pptx", dt.KIND_PPTX),
        ],
    )
    def test_supported(self, content_type, filename, expected):
        assert dt.detect_kind(content_type, filename) == expected

    @pytest.mark.parametrize(
        ("content_type", "filename"),
        [
            ("application/vnd.ms-powerpoint", "old.ppt"),
            ("application/msword", "old.doc"),
            ("image/png", "diagram.png"),
            ("video/mp4", "lecture.mp4"),
            (None, None),
        ],
    )
    def test_unsupported(self, content_type, filename):
        assert dt.detect_kind(content_type, filename) is None


@needs_pypdf
class TestPdf:
    def test_pages_in_order_with_numbers(self, make_pdf):
        doc = dt.extract_text(make_pdf(["Alpha page", "Beta page", "Gamma page"]), dt.KIND_PDF)
        assert doc.unit == "page"
        assert doc.total_units == 3
        assert [(s.number, s.text) for s in doc.sections] == [
            (1, "Alpha page"),
            (2, "Beta page"),
            (3, "Gamma page"),
        ]
        assert doc.stopped_early is False

    def test_page_range_is_inclusive_and_clamped(self, make_pdf):
        doc = dt.extract_text(
            make_pdf(["One", "Two", "Three", "Four"]), dt.KIND_PDF, start=2, end=99
        )
        assert [s.number for s in doc.sections] == [2, 3, 4]
        assert doc.sections[0].text == "Two"

    def test_start_past_end_of_document_is_an_error(self, make_pdf):
        with pytest.raises(dt.DocumentTextError, match="past the last page"):
            dt.extract_text(make_pdf(["One", "Two"]), dt.KIND_PDF, start=5)

    def test_scanned_pdf_gets_an_ocr_note(self, make_pdf):
        doc = dt.extract_text(make_pdf(["", ""]), dt.KIND_PDF)
        assert all(s.text == "" for s in doc.sections)
        assert any("OCR" in note for note in doc.notes)

    def test_partly_blank_pdf_counts_blank_pages(self, make_pdf):
        doc = dt.extract_text(make_pdf(["Text", ""]), dt.KIND_PDF)
        assert any("1 page(s) had no extractable text" in n for n in doc.notes)

    def test_budget_stops_extraction_early(self, make_pdf):
        doc = dt.extract_text(
            make_pdf(["A" * 30, "B" * 30, "C" * 30]), dt.KIND_PDF, budget=40
        )
        assert [s.number for s in doc.sections] == [1, 2]
        assert doc.stopped_early is True

    def test_no_budget_by_default_extracts_every_page(self, make_pdf):
        # The default used to be a 40,000-character budget.
        pages = ["P" * 2000] * 30
        doc = dt.extract_text(make_pdf(pages), dt.KIND_PDF)
        assert [s.number for s in doc.sections] == list(range(1, 31))
        assert doc.stopped_early is False

    def test_corrupt_pdf_is_a_clean_error(self):
        with pytest.raises(dt.DocumentTextError, match="Could not parse the PDF"):
            dt.extract_text(b"%PDF-1.4 this is not really a pdf", dt.KIND_PDF)


@needs_pptx
class TestPptx:
    def test_titles_body_tables_and_notes(self, make_pptx):
        doc = dt.extract_text(make_pptx(), dt.KIND_PPTX)
        assert doc.unit == "slide"
        assert doc.total_units == 3
        first = doc.sections[0]
        assert first.number == 1
        assert first.text.splitlines() == [
            "Title: Intro to Graphs",
            "Vertices and edges",
            "BFS | O(V+E)",
            "Speaker notes: Mention the midterm",
        ]
        assert doc.sections[1].text == "Title: Shortest Paths"

    def test_slide_range(self, make_pptx):
        doc = dt.extract_text(make_pptx(), dt.KIND_PPTX, start=2, end=2)
        assert [(s.number, s.text) for s in doc.sections] == [(2, "Title: Shortest Paths")]

    def test_not_a_zip_is_a_clean_error(self):
        with pytest.raises(dt.DocumentTextError, match="not a valid"):
            dt.extract_text(b"definitely not a zip", dt.KIND_PPTX)

    def test_zip_bomb_is_refused_before_parsing(self, monkeypatch):
        monkeypatch.setattr(dt, "MAX_UNCOMPRESSED_BYTES", 1000)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("ppt/slides/slide1.xml", "0" * 50_000)
        with pytest.raises(dt.DocumentTextError, match="refusing to parse"):
            dt.extract_text(buffer.getvalue(), dt.KIND_PPTX)


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


class TestZipGuard:
    """Inflation limits checked from the ZIP directory, before any parser runs."""

    def test_limits_are_tight_relative_to_the_download_cap(self):
        mb = 1024 * 1024
        assert dt.MAX_UNCOMPRESSED_BYTES <= 100 * mb
        assert dt.MAX_XML_UNCOMPRESSED_BYTES <= 20 * mb
        assert dt.MAX_COMPRESSION_RATIO <= 100

    @pytest.mark.parametrize("kind", [dt.KIND_DOCX, dt.KIND_PPTX])
    def test_high_ratio_xml_part_is_refused(self, kind):
        # A few hundred KB of zip that inflates to megabytes of tiny elements:
        # the shape that drove python-docx to ~3.4 GB for a 0.6 MB upload.
        data = _zip({"word/document.xml": b"<w:p/>" * 1_000_000})
        assert len(data) < 100_000
        with pytest.raises(dt.DocumentTextError, match="compression bomb"):
            dt._check_zip_container(data, kind)

    def test_xml_total_over_cap_is_refused_even_at_a_normal_ratio(self, monkeypatch):
        monkeypatch.setattr(dt, "MAX_XML_UNCOMPRESSED_BYTES", 50_000)
        rng = random.Random(7)
        slide = "".join(rng.choice("abcdefgh <>/") for _ in range(30_000)).encode()
        data = _zip({f"ppt/slides/slide{n}.xml": slide for n in range(1, 3)})
        with pytest.raises(dt.DocumentTextError, match="XML expands to more than"):
            dt._check_zip_container(data, dt.KIND_PPTX)

    def test_media_does_not_count_against_the_xml_cap(self, monkeypatch):
        monkeypatch.setattr(dt, "MAX_XML_UNCOMPRESSED_BYTES", 50_000)
        image = os.urandom(200_000)  # incompressible, like a JPEG
        data = _zip({"ppt/media/image1.jpeg": image, "ppt/slides/slide1.xml": b"<p:sld/>"})
        dt._check_zip_container(data, dt.KIND_PPTX)  # no exception

    def test_total_over_cap_is_refused(self, monkeypatch):
        monkeypatch.setattr(dt, "MAX_UNCOMPRESSED_BYTES", 100_000)
        data = _zip({"ppt/media/video.mp4": os.urandom(150_000)})
        with pytest.raises(dt.DocumentTextError, match="expands to more than"):
            dt._check_zip_container(data, dt.KIND_PPTX)

    @needs_docx
    def test_bomb_is_refused_before_the_parser_runs(self, monkeypatch):
        import docx

        def must_not_parse(*args, **kwargs):
            raise AssertionError("parser ran on a refused file")

        monkeypatch.setattr(docx, "Document", must_not_parse)
        data = _zip({
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w:p/>" * 1_000_000,
        })
        with pytest.raises(dt.DocumentTextError, match="compression bomb"):
            dt.extract_text(data, dt.KIND_DOCX)

    def test_real_documents_pass(self, make_docx, make_pptx):
        dt._check_zip_container(make_docx(), dt.KIND_DOCX)
        dt._check_zip_container(make_pptx(), dt.KIND_PPTX)


@needs_docx
class TestDocx:
    def test_headings_paragraphs_and_tables_in_order(self, make_docx):
        doc = dt.extract_text(make_docx(), dt.KIND_DOCX)
        assert doc.unit is None
        assert doc.sections[0].text.splitlines() == [
            "# Course Policies",
            "Late work loses 10% per day.",
            "Week 1 | Introduction",
            "Office hours are on Fridays.",
        ]

    def test_page_range_is_ignored_with_a_note(self, make_docx):
        doc = dt.extract_text(make_docx(), dt.KIND_DOCX, start=3)
        assert "Late work" in doc.sections[0].text
        assert any("page range was ignored" in n for n in doc.notes)


class TestPlainFormats:
    def test_html_drops_scripts_and_styles_and_unescapes(self):
        markup = (
            b"<html><head><style>p{color:red}</style></head><body>"
            b"<h1>Week 2</h1><p>Read &amp; summarize</p>"
            b"<script>steal()</script><ul><li>Item one</li><li>Item two</li></ul>"
            b"</body></html>"
        )
        text = dt.extract_text(markup, dt.KIND_HTML).sections[0].text
        assert "steal" not in text and "color" not in text
        lines = [line for line in text.splitlines() if line]
        assert lines == ["Week 2", "Read & summarize", "Item one", "Item two"]

    def test_utf8_bom_is_stripped(self):
        text = dt.extract_text("﻿café".encode(), dt.KIND_TEXT).sections[0].text
        assert text == "café"

    def test_non_utf8_falls_back_to_cp1252(self):
        text = dt.extract_text("naïve “quote”".encode("cp1252"), dt.KIND_TEXT).sections[0].text
        assert text == "naïve “quote”"

    def test_json_is_pretty_printed(self):
        text = dt.extract_text(
            b'{"week":1,"topics":["a"]}', dt.KIND_TEXT, filename="plan.json"
        ).sections[0].text
        assert text == '{\n  "week": 1,\n  "topics": [\n    "a"\n  ]\n}'

    def test_invalid_json_is_returned_as_written(self):
        text = dt.extract_text(b"{not json", dt.KIND_TEXT, filename="x.json").sections[0].text
        assert text == "{not json"


class TestMissingDependencies:
    @pytest.mark.parametrize(
        ("kind", "module", "package", "data"),
        [
            (dt.KIND_PDF, "pypdf", "pypdf", b"%PDF"),
            (dt.KIND_PPTX, "pptx", "python-pptx", b""),
            (dt.KIND_DOCX, "docx", "python-docx", b""),
        ],
    )
    def test_missing_parser_names_the_package_and_extra(
        self, monkeypatch, kind, module, package, data
    ):
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == module or name.startswith(module + "."):
                raise ImportError(f"No module named {name!r}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)
        with pytest.raises(dt.MissingDependencyError) as excinfo:
            dt.extract_text(data, kind)
        message = str(excinfo.value)
        assert package in message
        assert "canvas-mcp[documents]" in message
