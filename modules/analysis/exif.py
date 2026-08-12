"""EXIF metadata extraction for OSINT.

EXIF blocks travel with most JPEG/TIFF/HEIC images and routinely leak
information their owners would not paste into a chat: the GPS where the
photo was taken, the device serial, who edited it last, and when. For
red-team work this turns a profile picture into geolocation, and turns a
"random" leaked screenshot into a device fingerprint.

Design split
------------
The expensive bits (Pillow, byte parsing) are isolated from the parsing
logic so that:

* :func:`parse_exif_dict` is a pure function — easy to unit-test against
  hand-built dicts without instantiating an image at all.
* :func:`extract_from_bytes` / :func:`extract_from_path` /
  :func:`extract_from_url` are thin Pillow wrappers that gracefully
  no-op when Pillow is not installed (we do not want this module to be
  a hard dependency for the rest of the pipeline).

Pillow is in the project's ``photo`` extras — without ``pip install
.[photo]`` the wrapper returns an empty :class:`ExifReport` instead of
crashing, so callers can always invoke this module safely.
"""

from __future__ import annotations

import io
from typing import Any

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.analysis.models import ExifReport

log = get_logger(__name__)

try:  # pragma: no cover — exercised in environments without Pillow
    from PIL import ExifTags, Image  # type: ignore[import-not-found]

    _PIL_AVAILABLE = True
except Exception:
    _PIL_AVAILABLE = False
    ExifTags = None  # type: ignore[assignment]
    Image = None  # type: ignore[assignment]

# EXIF tag IDs we promote to typed fields. Using integer literals so this
# module stays usable even without Pillow's ExifTags table at hand.
_TAG_MAKE = 271
_TAG_MODEL = 272
_TAG_SOFTWARE = 305
_TAG_DATETIME = 306
_TAG_ARTIST = 315
_TAG_COPYRIGHT = 33432
_TAG_DATETIME_ORIGINAL = 36867
_TAG_GPS_INFO = 34853
_TAG_XP_AUTHOR = 40093  # Windows-only, UTF-16 LE bytes
_TAG_BODY_SERIAL = 42033
_TAG_LENS_MODEL = 42036

# GPS sub-IFD tag IDs (PIL.ExifTags.GPSTAGS values).
_GPS_LAT_REF = 1
_GPS_LAT = 2
_GPS_LON_REF = 3
_GPS_LON = 4
_GPS_ALT_REF = 5  # 0 = above sea level, 1 = below
_GPS_ALT = 6

_PROMOTED_TAGS: frozenset[int] = frozenset(
    {
        _TAG_MAKE, _TAG_MODEL, _TAG_SOFTWARE, _TAG_DATETIME, _TAG_ARTIST,
        _TAG_COPYRIGHT, _TAG_DATETIME_ORIGINAL, _TAG_GPS_INFO,
        _TAG_XP_AUTHOR, _TAG_BODY_SERIAL, _TAG_LENS_MODEL,
    }
)


# ── helpers ─────────────────────────────────────────────────────────


def _to_float(value: Any) -> float | None:
    """Coerce EXIF rationals / IFDRational / numeric to float, else ``None``."""
    if value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, tuple) and len(value) == 2:
        num, den = value
        try:
            den_f = float(den)
            if den_f == 0:
                return None
            return float(num) / den_f
        except (TypeError, ValueError):
            return None
    # Pillow's IFDRational implements __float__
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dms_to_decimal(
    dms: Any, ref: str | None
) -> float | None:
    """Convert ``(deg, min, sec)`` + reference letter to signed decimal degrees.

    Returns ``None`` if the input shape is wrong or the reference is
    blank — EXIF without a hemisphere reference is ambiguous and we
    refuse to guess.
    """
    if dms is None or not ref:
        return None
    if not isinstance(dms, tuple | list) or len(dms) != 3:
        return None
    d = _to_float(dms[0])
    m = _to_float(dms[1])
    s = _to_float(dms[2])
    if d is None or m is None or s is None:
        return None
    decimal = d + m / 60.0 + s / 3600.0
    if ref.upper() in ("S", "W"):
        decimal = -decimal
    return decimal


def _decode_str(value: Any) -> str | None:
    """Best-effort decode of EXIF string-shaped values to ``str``."""
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        return s or None
    if isinstance(value, bytes):
        # Windows XPAuthor and friends are UTF-16 LE. Try that first,
        # fall back to latin-1 which never raises.
        for enc in ("utf-16-le", "utf-8", "latin-1"):
            try:
                decoded = value.decode(enc).rstrip("\x00").strip()
                if decoded:
                    return decoded
            except UnicodeDecodeError:
                continue
        return None
    return None


def _serialize_raw(value: Any) -> Any:
    """Reduce arbitrary EXIF values to JSON-friendly primitives for raw_tags."""
    if isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, bytes):
        return _decode_str(value) or value.hex()[:80]
    if isinstance(value, tuple | list):
        f = _to_float(value)
        if f is not None:
            return f
        return str(value)[:120]
    return str(value)[:120]


def _tag_label(tag_id: int) -> str:
    """Use Pillow's tag-name table when available, fall back to the integer."""
    if _PIL_AVAILABLE and ExifTags is not None:
        name = ExifTags.TAGS.get(tag_id)
        if name:
            return name
    return f"Tag_{tag_id}"


# ── pure parser ─────────────────────────────────────────────────────


def parse_exif_dict(
    *,
    main: dict[int, Any],
    gps: dict[int, Any] | None = None,
    source: str = "",
) -> ExifReport:
    """Turn raw EXIF dictionaries into a typed :class:`ExifReport`.

    ``main`` is the top-level IFD as ``{tag_id: value}``. ``gps`` is the
    GPSInfo sub-IFD; pass ``None`` when the image has no GPS block.
    """
    taken_at = _decode_str(main.get(_TAG_DATETIME_ORIGINAL)) or _decode_str(
        main.get(_TAG_DATETIME)
    )
    author = (
        _decode_str(main.get(_TAG_ARTIST))
        or _decode_str(main.get(_TAG_XP_AUTHOR))
        or _decode_str(main.get(_TAG_COPYRIGHT))
    )

    gps_lat: float | None = None
    gps_lon: float | None = None
    gps_alt: float | None = None
    if gps:
        gps_lat = _dms_to_decimal(gps.get(_GPS_LAT), _decode_str(gps.get(_GPS_LAT_REF)))
        gps_lon = _dms_to_decimal(gps.get(_GPS_LON), _decode_str(gps.get(_GPS_LON_REF)))
        alt_value = _to_float(gps.get(_GPS_ALT))
        if alt_value is not None:
            ref = gps.get(_GPS_ALT_REF, 0)
            try:
                if int(ref) == 1:
                    alt_value = -alt_value
            except (TypeError, ValueError):
                pass
            gps_alt = alt_value

    raw_tags: dict[str, Any] = {}
    for tag_id, value in main.items():
        if tag_id in _PROMOTED_TAGS:
            continue
        try:
            label = _tag_label(int(tag_id))
        except (TypeError, ValueError):
            label = f"Tag_{tag_id}"
        raw_tags[label] = _serialize_raw(value)

    return ExifReport(
        source=source,
        gps_lat=gps_lat,
        gps_lon=gps_lon,
        gps_altitude=gps_alt,
        taken_at=taken_at,
        camera_make=_decode_str(main.get(_TAG_MAKE)),
        camera_model=_decode_str(main.get(_TAG_MODEL)),
        lens_model=_decode_str(main.get(_TAG_LENS_MODEL)),
        software=_decode_str(main.get(_TAG_SOFTWARE)),
        author=author,
        serial_number=_decode_str(main.get(_TAG_BODY_SERIAL)),
        raw_tags=raw_tags,
    )


# ── Pillow wrappers ─────────────────────────────────────────────────


def _empty(source: str) -> ExifReport:
    return ExifReport(source=source)


def extract_from_bytes(data: bytes, *, source: str = "") -> ExifReport:
    """Parse the EXIF block of an in-memory image payload.

    Returns an empty report (no GPS, no camera fields) when Pillow is
    missing, the bytes are not a valid image, or the image carries no
    EXIF block at all.
    """
    if not _PIL_AVAILABLE or not data:
        return _empty(source)

    try:
        with Image.open(io.BytesIO(data)) as img:  # type: ignore[union-attr]
            exif_obj = img.getexif()
            if not exif_obj:
                return _empty(source)
            main = dict(exif_obj.items())
            gps_dict: dict[int, Any] | None = None
            try:
                gps_ifd = exif_obj.get_ifd(_TAG_GPS_INFO)
                if gps_ifd:
                    gps_dict = dict(gps_ifd)
            except Exception as exc:
                log.debug("exif: gps ifd parse failed: %s", exc)
    except Exception as exc:
        log.debug("exif: cannot open bytes from %s: %s", source, exc)
        return _empty(source)

    return parse_exif_dict(main=main, gps=gps_dict, source=source)


def extract_from_path(path: str) -> ExifReport:
    """Read an image from disk and extract its EXIF block."""
    if not _PIL_AVAILABLE:
        return _empty(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        log.debug("exif: cannot read %s: %s", path, exc)
        return _empty(path)
    return extract_from_bytes(data, source=path)


async def extract_from_url(client: HTTPClient, url: str) -> ExifReport:
    """Fetch an image over HTTP and extract its EXIF block."""
    if not url:
        return _empty(url)
    status, data, _ = await client.get_bytes(url)
    if status != 200 or not data:
        return _empty(url)
    return extract_from_bytes(data, source=url)
