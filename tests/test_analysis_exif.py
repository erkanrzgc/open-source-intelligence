"""Tests for the EXIF metadata extractor."""

from __future__ import annotations

import io
import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.analysis import exif
from modules.analysis.exif import _dms_to_decimal, parse_exif_dict
from modules.analysis.models import ExifReport

# ── DMS → decimal ───────────────────────────────────────────────────


def test_dms_to_decimal_north_is_positive() -> None:
    # 48° 51' 30" N → ~48.858333
    assert _dms_to_decimal((48, 51, 30), "N") == pytest.approx(48.85833, abs=1e-4)


def test_dms_to_decimal_south_is_negative() -> None:
    assert _dms_to_decimal((33, 52, 4), "S") == pytest.approx(-33.86778, abs=1e-4)


def test_dms_to_decimal_west_is_negative() -> None:
    assert _dms_to_decimal((118, 14, 37), "W") == pytest.approx(-118.24361, abs=1e-4)


def test_dms_to_decimal_handles_rational_pairs() -> None:
    # PIL gives some EXIF values as (num, den) rational tuples.
    assert _dms_to_decimal(((48, 1), (51, 1), (30, 1)), "N") == pytest.approx(
        48.85833, abs=1e-4
    )


def test_dms_to_decimal_returns_none_on_garbage() -> None:
    assert _dms_to_decimal(None, "N") is None
    assert _dms_to_decimal((1, 2), "N") is None  # too few components
    assert _dms_to_decimal((1, 2, 3), "") is None  # missing reference


# ── parse_exif_dict ─────────────────────────────────────────────────


def test_parse_exif_empty_dict_returns_blank_report() -> None:
    report = parse_exif_dict(main={}, gps=None, source="x.jpg")
    assert isinstance(report, ExifReport)
    assert report.source == "x.jpg"
    assert report.has_gps() is False
    assert report.camera_make is None
    assert report.taken_at is None


def test_parse_exif_extracts_camera_and_software() -> None:
    main = {
        271: "Canon",
        272: "EOS 5D Mark IV",
        305: "Adobe Photoshop CS6 (Windows)",
        315: "Jane Doe",
        42036: "EF24-70mm f/2.8L II USM",
        42033: "0123456789",
    }
    report = parse_exif_dict(main=main, gps=None)
    assert report.camera_make == "Canon"
    assert report.camera_model == "EOS 5D Mark IV"
    assert report.software == "Adobe Photoshop CS6 (Windows)"
    assert report.author == "Jane Doe"
    assert report.lens_model == "EF24-70mm f/2.8L II USM"
    assert report.serial_number == "0123456789"


def test_parse_exif_prefers_datetime_original_over_datetime() -> None:
    main = {306: "2024:01:01 00:00:00", 36867: "2023:07:15 14:32:10"}
    report = parse_exif_dict(main=main, gps=None)
    assert report.taken_at == "2023:07:15 14:32:10"


def test_parse_exif_falls_back_to_datetime_when_original_missing() -> None:
    main = {306: "2024:01:01 00:00:00"}
    report = parse_exif_dict(main=main, gps=None)
    assert report.taken_at == "2024:01:01 00:00:00"


def test_parse_exif_decodes_xpauthor_utf16_bytes() -> None:
    # Windows tools store author as UTF-16 LE bytes in tag 40093.
    main = {40093: "Alice".encode("utf-16-le")}
    report = parse_exif_dict(main=main, gps=None)
    assert report.author == "Alice"


def test_parse_exif_extracts_gps() -> None:
    gps = {
        1: "N",  # GPSLatitudeRef
        2: ((48, 1), (51, 1), (30, 1)),
        3: "E",
        4: ((2, 1), (17, 1), (40, 1)),  # roughly Eiffel Tower
        5: 0,  # above sea level
        6: (35, 1),
    }
    report = parse_exif_dict(main={}, gps=gps)
    assert report.has_gps()
    assert report.gps_lat == pytest.approx(48.85833, abs=1e-4)
    assert report.gps_lon == pytest.approx(2.29444, abs=1e-4)
    assert report.gps_altitude == pytest.approx(35.0, abs=1e-4)


def test_parse_exif_gps_below_sea_level_is_negative_altitude() -> None:
    gps = {1: "N", 2: ((1, 1), (0, 1), (0, 1)),
           3: "E", 4: ((1, 1), (0, 1), (0, 1)),
           5: 1, 6: (10, 1)}
    report = parse_exif_dict(main={}, gps=gps)
    assert report.gps_altitude == pytest.approx(-10.0, abs=1e-4)


def test_parse_exif_keeps_unrecognized_tags_in_raw() -> None:
    main = {271: "Canon", 99999: "weird-vendor-tag", 8298: "© 2024 Example Co"}
    report = parse_exif_dict(main=main, gps=None)
    # Promoted tags do NOT appear in raw_tags
    assert "Make" not in report.raw_tags
    # Unknown tag keys are stringified
    assert report.raw_tags  # non-empty
    # Bytes values are decoded best-effort
    for v in report.raw_tags.values():
        assert isinstance(v, str | int | float)


def test_parse_exif_drops_empty_string_values() -> None:
    main = {271: "", 272: "  ", 305: "Lightroom"}
    report = parse_exif_dict(main=main, gps=None)
    assert report.camera_make is None
    assert report.camera_model is None
    assert report.software == "Lightroom"


# ── Pillow extract_from_bytes ───────────────────────────────────────


def test_extract_from_bytes_returns_blank_when_pil_missing(monkeypatch) -> None:
    monkeypatch.setattr(exif, "_PIL_AVAILABLE", False)
    report = exif.extract_from_bytes(b"\xff\xd8\xff\xd9", source="x.jpg")
    assert report.source == "x.jpg"
    assert report.has_gps() is False
    assert report.camera_make is None


def test_extract_from_bytes_handles_no_exif_image() -> None:
    PIL = pytest.importorskip("PIL")  # noqa: F841 — confirm Pillow is installed
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (8, 8), color="red").save(buf, format="JPEG")
    report = exif.extract_from_bytes(buf.getvalue(), source="red.jpg")
    assert report.source == "red.jpg"
    assert report.camera_make is None
    assert report.has_gps() is False


def test_extract_from_bytes_reads_real_exif_tags() -> None:
    pytest.importorskip("PIL")
    from PIL import Image

    img = Image.new("RGB", (8, 8), color="blue")
    exif_block = img.getexif()
    exif_block[271] = "Nikon"
    exif_block[272] = "D750"
    exif_block[305] = "Lightroom Classic"
    exif_block[36867] = "2023:11:20 09:15:00"
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif_block.tobytes())
    report = exif.extract_from_bytes(buf.getvalue(), source="blue.jpg")
    assert report.camera_make == "Nikon"
    assert report.camera_model == "D750"
    assert report.software == "Lightroom Classic"
    assert report.taken_at == "2023:11:20 09:15:00"


def test_extract_from_bytes_returns_blank_for_garbage() -> None:
    pytest.importorskip("PIL")
    report = exif.extract_from_bytes(b"not an image at all", source="bad")
    assert report.source == "bad"
    assert report.camera_make is None


# ── URL fetch ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_extract_from_url_fetches_and_parses() -> None:
    pytest.importorskip("PIL")
    from PIL import Image

    img = Image.new("RGB", (8, 8), color="green")
    exif_block = img.getexif()
    exif_block[272] = "Pixel 7"
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif_block.tobytes())
    payload = buf.getvalue()

    url = "https://cdn.example.com/profile.jpg"
    with aioresponses() as m:
        m.get(re.compile(r"https://cdn\.example\.com/.*"), body=payload, content_type="image/jpeg")
        async with HTTPClient() as client:
            report = await exif.extract_from_url(client, url)
    assert report.source == url
    assert report.camera_model == "Pixel 7"


@pytest.mark.asyncio
async def test_extract_from_url_handles_404_gracefully() -> None:
    url = "https://cdn.example.com/missing.jpg"
    with aioresponses() as m:
        m.get(re.compile(r"https://cdn\.example\.com/.*"), status=404)
        async with HTTPClient() as client:
            report = await exif.extract_from_url(client, url)
    assert report.source == url
    assert report.camera_make is None
    assert report.has_gps() is False


@pytest.mark.asyncio
async def test_extract_from_url_handles_empty_body() -> None:
    url = "https://cdn.example.com/empty.jpg"
    with aioresponses() as m:
        m.get(re.compile(r"https://cdn\.example\.com/.*"), body=b"")
        async with HTTPClient() as client:
            report = await exif.extract_from_url(client, url)
    assert report.camera_make is None
