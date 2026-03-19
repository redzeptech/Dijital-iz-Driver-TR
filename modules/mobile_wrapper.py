"""
Mobil Adli Biliş — SQLite Expert (Android .db / .sqlite3, iOS .sqlite / AddressBook)

Bu modül şu yetenekleri hedefler:

1) **SQLite Expert:** Yedek ağacındaki ilişkisel veritabanlarını salt-okunur açar; şema keşfi,
   tablo/kolon eşleme ve güvenli (URI mode=ro) bağlantılar.

2) **WhatsApp — msgstore.db / chatstorage:** ``parse_whatsapp_database`` / ``parse_msgstore_database``
   ile ``messages`` (ve benzeri) tablolardan mesaj gövdesi, sohbet/gönderen kimliği (JID), zaman damgası
   ve ``from_me`` bayrağını ayıklar.

3) **Konum izleme:** ``contacts2.db`` / iOS rehberi; ``calls`` / arama kayıtları veritabanları;
   Google Maps / gmm_storage önbellek SQLite'ları; EXIF GPS; rehber ve geçmiş URL metinlerinden
   türetilen koordinatlar (``derive_*``).

4) **Data carving:** ``PRAGMA freelist_count`` / sayfa meta verisi + dosya içi ham bayt taraması —
   SQLite boş / free-list ile ilişkilendirilebilecek bölgelerde kalan JID ve metin fragmanları
   (silinmiş satır adayı, tam rekonstrüksiyon değildir).

**Atıf:** Magnet AXIOM'un mobil artefaktı disk/RAM/ağ zaman çizelgesi ve kullanıcı öyküsüyle
eşleştirme disiplini — teknik olarak DİZ ``mobile_findings.json`` çıktısı üzerinden
``cloud_wrapper`` / ``correlator`` ile köprülenebilir.

Notlar:
- Şifreli .ab / tam iOS yedek şifre çözümü bu sürümde yok; çıkarılmış veya çözülmüş dosya
  ağacı veya doğrudan .db yolları beklenir.
- Kurtarma, silinen hücrelerin tam yeniden yapılandırması değil; free list + unallocated adayı
  tarama ile triage üretir.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.module_manager import BaseModule

logger = logging.getLogger(__name__)

RESULTS_DEFAULT = _ROOT / "data" / "results"

IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".tif", ".tiff", ".heic", ".png", ".webp")
CONTACTS_NAME_HINTS = ("contacts2.db", "contacts.db", "addressbook.sqlitedb")
BROWSER_NAME_HINTS = ("history", "places.mozilla", "places.sqlite", "history.db")
WHATSAPP_NAME_HINTS = ("msgstore.db", "wa.db", "chatstorage.sqlite")

# WhatsApp Android: tipik JID ve grup son ekleri
JID_PATTERN = re.compile(
    rb"[\x20-\x7e]{0,4}(\d{6,20}@[sg]\.whatsapp\.net|status@broadcast|[^\x00]{1,64}@g\.us)[\x00-\x1f]?"
)
# Metin fragmanı için (UTF-8 güvenli bölgeler)
TEXT_CHUNK_RE = re.compile(rb"[\x20-\x7e\xC0-\xF4][\x20-\x7e\xC0-\xF4\s]{10,240}")

# Rehber notları / adres alanlarında düz metin koordinat (41.0, 29.0)
COORD_PAIR_IN_TEXT_RE = re.compile(
    r"(?P<lat>-?\d{1,2}\.\d{4,})\s*,\s*(?P<lon>-?\d{1,3}\.\d{4,})"
)
# Google Maps URL: @lat,lon veya q=lat,lon
GMAPS_URL_COORD_RE = re.compile(
    r"(?:@|--)(?P<lat>-?\d{1,2}\.\d+)\s*,\s*(?P<lon>-?\d{1,3}\.\d+)",
    re.I,
)
GMAPS_Q_RE = re.compile(r"[?&]q=(?P<lat>-?\d{1,2}\.\d+)\s*,\s*(?P<lon>-?\d{1,3}\.\d+)", re.I)


def _safe_connect_ro(path: Path) -> sqlite3.Connection | None:
    try:
        uri = f"file:{path.as_posix()}?mode=ro"
        return sqlite3.connect(uri, uri=True, timeout=2.0)
    except sqlite3.Error as e:
        logger.debug("SQLite acilamadi %s: %s", path, e)
        return None


def _list_tables(conn: sqlite3.Connection) -> list[str]:
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
        )
        return [r[0] for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def _table_columns(conn: sqlite3.Connection, table: str) -> dict[str, str]:
    try:
        cur = conn.execute(f'PRAGMA table_info("{table}")')
        return {row[1]: row[2] for row in cur.fetchall()}
    except sqlite3.Error:
        return {}


def _pick_column(cols: dict[str, str], *candidates: str) -> str | None:
    low = {k.lower(): k for k in cols}
    for c in candidates:
        if c.lower() in low:
            return low[c.lower()]
    return None


def _ts_to_iso_ms(value: Any) -> str:
    if value is None:
        return ""
    try:
        v = int(value)
        if v > 1_000_000_000_000:  # ms
            v //= 1000
        if v > 1_000_000_000:
            from datetime import datetime, timezone

            return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        pass
    return str(value)


def discover_sqlite_files(root: Path, max_files: int = 400) -> list[Path]:
    out: list[Path] = []
    if root.is_file():
        if root.suffix.lower() in (".db", ".sqlite", ".sqlite3") or "manifest" in root.name.lower():
            return [root]
        return []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            if p.stat().st_size < 1024:
                continue
            out.append(p)
            if len(out) >= max_files:
                break
    return sorted(set(out))


def _is_sqlite_file(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size >= 100 and path.read_bytes()[:15].startswith(b"SQLite format 3")
    except OSError:
        return False


def _norm_name(p: Path) -> str:
    return p.name.lower().split("\\")[-1].split("/")[-1]


def discover_filesystem_parser_targets(root: Path, max_sqlites: int = 800, max_walk: int = 120_000) -> dict[str, list[Path]]:
    """
    İmaj/yedek ağacında rehber, WhatsApp, tarayıcı ve harita önbelleği SQLite'larını hedefler.
    """
    buckets: dict[str, list[Path]] = {
        "contacts": [],
        "whatsapp": [],
        "sms": [],
        "browser_history": [],
        "map_cache": [],
        "other_sqlite": [],
    }
    seen: set[Path] = set()
    n = 0

    def consider(p: Path) -> None:
        nonlocal n
        if p in seen or not p.is_file():
            return
        seen.add(p)
        n += 1
        low = _norm_name(p)
        path_s = str(p).lower()

        if not _is_sqlite_file(p) and low not in ("history",) and not low.endswith((".db", ".sqlite", ".sqlite3")):
            return
        if low in ("history",) or (_is_sqlite_file(p) and low == "history"):
            if "chrome" in path_s or "chromium" in path_s or "com.android.chrome" in path_s:
                buckets["browser_history"].append(p)
            elif "safari" in path_s or low == "history.db":
                buckets["browser_history"].append(p)
            elif _is_sqlite_file(p):
                buckets["browser_history"].append(p)
            return

        if not _is_sqlite_file(p):
            return

        if any(h in low for h in ("contacts2", "contacts.db", "addressbook", "contactcore")):
            buckets["contacts"].append(p)
            return
        if low == "mmssms.db" or "mmssms.db" in path_s or "/mmssms" in path_s.replace("\\", "/"):
            buckets["sms"].append(p)
            return
        if any(h in low for h in WHATSAPP_NAME_HINTS) or "com.whatsapp" in path_s or "whatsapp" in path_s:
            buckets["whatsapp"].append(p)
            return
        if low in ("places.sqlite", "places.sqlite-wal") or "places.sqlite" in low:
            buckets["browser_history"].append(p)
            return
        if low == "history.db" or (low == "history" and _is_sqlite_file(p)):
            buckets["browser_history"].append(p)
            return

        if any(
            x in path_s
            for x in (
                "com.google.android.apps.maps",
                "com.google.android.gms",
                "gmm_storage",
                "da_destination",
                "maps.db",
            )
        ) or any(k in low for k in ("destination", "gmm", "tilepreview", "map_cache")):
            buckets["map_cache"].append(p)
            return

        buckets["other_sqlite"].append(p)

    if root.is_file():
        consider(root)
        return buckets

    for p in root.rglob("*"):
        if n >= max_walk:
            break
        consider(p)
        if sum(len(v) for v in buckets.values()) > max_sqlites * 2:
            break

    for k in buckets:
        buckets[k] = sorted(set(buckets[k]))[: max_sqlites // 4 or 50]
    return buckets


def chrome_microseconds_to_iso(us: Any) -> str:
    """Chrome last_visit_time: Windows FILETIME benzeri (1601'den mikrosaniye)."""
    try:
        v = int(us)
        sec = v / 1_000_000.0 - 11644473600
        return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return str(us) if us is not None else ""


def parse_contacts_database(db_path: Path) -> list[dict[str, Any]]:
    """Android contacts2.db / iOS AddressBook — isim + veri1 (telefon/e-posta)."""
    conn = _safe_connect_ro(db_path)
    if not conn:
        return []
    rows: list[dict[str, Any]] = []
    try:
        tables = _list_tables(conn)
        if "raw_contacts" in tables and "data" in tables:
            try:
                cur = conn.execute(
                    """
                    SELECT rc.display_name, rc.account_type, rc.account_name,
                           d.data1, d.data2, d.data3, d.mimetype_id
                    FROM data d
                    LEFT JOIN raw_contacts rc ON d.raw_contact_id = rc._id
                    LIMIT 25000
                    """
                )
                for r in cur.fetchall():
                    rows.append(
                        {
                            "source_db": str(db_path),
                            "display_name": str(r[0] or ""),
                            "account_type": str(r[1] or ""),
                            "account_name": str(r[2] or ""),
                            "value_primary": str(r[3] or ""),
                            "value_secondary": str(r[4] or ""),
                            "mimetype_id": r[6],
                        }
                    )
            except sqlite3.Error:
                pass
        if not rows and "ABPerson" in tables:
            # iOS adres defteri (basit)
            try:
                cur = conn.execute('SELECT ROWID, First, Last, Organization FROM "ABPerson" LIMIT 5000')
                for r in cur.fetchall():
                    rows.append(
                        {
                            "source_db": str(db_path),
                            "display_name": f"{r[1] or ''} {r[2] or ''}".strip() or str(r[3] or ""),
                            "value_primary": "",
                            "account_type": "ios_ABPerson",
                        }
                    )
            except sqlite3.Error:
                pass
    finally:
        conn.close()
    return rows


def derive_locations_from_contact_rows(contacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Rehber metin alanlarında (not, adres, birleşik display) düz yazılmış lat,lon çiftleri.
    Google Haritalar ile manuel paylaşılan koordinat izleri için tamamlayıcı kanıt.
    """
    locs: list[dict[str, Any]] = []
    seen: set[tuple[str, float, float]] = set()
    for c in contacts:
        blob = f"{c.get('display_name', '')} {c.get('value_primary', '')}"
        for m in COORD_PAIR_IN_TEXT_RE.finditer(blob):
            try:
                la, lo = float(m.group("lat")), float(m.group("lon"))
            except ValueError:
                continue
            if not (-90 <= la <= 90 and -180 <= lo <= 180):
                continue
            key = (str(c.get("source_db", "")), round(la, 5), round(lo, 5))
            if key in seen:
                continue
            seen.add(key)
            locs.append(
                {
                    "source_db": str(c.get("source_db", "")),
                    "latitude": la,
                    "longitude": lo,
                    "source_type": "contacts_gps_text",
                    "timestamp_iso": "",
                    "table": "contacts_derived",
                }
            )
    return locs


def derive_locations_from_browser_maps_urls(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Tarayıcı geçmişindeki maps.google / q= koordinatları — Harita geçmişi tamamlayıcısı."""
    locs: list[dict[str, Any]] = []
    seen: set[tuple[str, float, float]] = set()
    for h in history:
        url = str(h.get("url") or "")
        low = url.lower()
        if "google." not in low and "maps" not in low and "goo.gl/maps" not in low:
            continue
        for rx in (GMAPS_URL_COORD_RE, GMAPS_Q_RE):
            for m in rx.finditer(url):
                try:
                    la, lo = float(m.group("lat")), float(m.group("lon"))
                except ValueError:
                    continue
                if not (-90 <= la <= 90 and -180 <= lo <= 180):
                    continue
                key = (str(h.get("source_db", "")), round(la, 5), round(lo, 5))
                if key in seen:
                    continue
                seen.add(key)
                locs.append(
                    {
                        "source_db": str(h.get("source_db", "")),
                        "latitude": la,
                        "longitude": lo,
                        "source_type": "google_maps_url_history",
                        "timestamp_iso": str(h.get("timestamp_iso") or ""),
                        "table": "browser_urls",
                        "title_hint": str(h.get("title") or "")[:200],
                    }
                )
    return locs


def parse_browser_history_database(db_path: Path) -> list[dict[str, Any]]:
    """Chromium urls / visits, Safari history_items, genel urls tablosu."""
    conn = _safe_connect_ro(db_path)
    if not conn:
        return []
    out: list[dict[str, Any]] = []
    low = db_path.name.lower()
    try:
        tables = _list_tables(conn)

        if "urls" in tables and "visits" in tables:
            try:
                cur = conn.execute(
                    """
                    SELECT u.url, u.title, u.visit_count, v.visit_time
                    FROM visits v JOIN urls u ON v.url = u.id
                    ORDER BY v.visit_time DESC
                    LIMIT 15000
                    """
                )
                for r in cur.fetchall():
                    out.append(
                        {
                            "source_db": str(db_path),
                            "browser_family": "chromium",
                            "url": str(r[0] or "")[:2000],
                            "title": str(r[1] or "")[:500],
                            "visit_count": r[2],
                            "timestamp_iso": chrome_microseconds_to_iso(r[3]),
                        }
                    )
            except sqlite3.Error:
                cur = conn.execute(
                    'SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 8000'
                )
                for r in cur.fetchall():
                    out.append(
                        {
                            "source_db": str(db_path),
                            "browser_family": "chromium",
                            "url": str(r[0] or "")[:2000],
                            "title": str(r[1] or "")[:500],
                            "visit_count": r[2],
                            "timestamp_iso": chrome_microseconds_to_iso(r[3]),
                        }
                    )

        if "history_items" in tables and not out:
            try:
                cur = conn.execute('PRAGMA table_info("history_items")')
                lc = {row[1].lower(): row[1] for row in cur.fetchall()}
                url_k = lc.get("url") or lc.get("urlstring")
                if url_k:
                    title_k = lc.get("title")
                    time_k = (
                        lc.get("visit_time_server")
                        or lc.get("lastvisitedtime")
                        or lc.get("visit_time")
                        or lc.get("last_visit_time")
                    )
                    sel = [f'"{url_k}"']
                    if title_k:
                        sel.append(f'"{title_k}"')
                    else:
                        sel.append("NULL AS col_title")
                    if time_k:
                        sel.append(f'"{time_k}"')
                    sql = f'SELECT {", ".join(sel)} FROM history_items LIMIT 8000'
                    cur = conn.execute(sql)
                    for row in cur.fetchall():
                        ts = ""
                        if len(row) > 2 and row[2] is not None:
                            ts = _ts_to_iso_ms(row[2])
                        out.append(
                            {
                                "source_db": str(db_path),
                                "browser_family": "webkit_safari",
                                "url": str(row[0] or "")[:2000],
                                "title": str(row[1] or "")[:500] if len(row) > 1 and row[1] else "",
                                "timestamp_iso": ts,
                            }
                        )
            except sqlite3.Error:
                pass

        if not out and "urls" in tables:
            cur = conn.execute("SELECT url, title FROM urls LIMIT 5000")
            for r in cur.fetchall():
                out.append(
                    {
                        "source_db": str(db_path),
                        "browser_family": "generic",
                        "url": str(r[0] or "")[:2000],
                        "title": str(r[1] or "")[:500],
                        "timestamp_iso": "",
                    }
                )
    except sqlite3.Error as e:
        logger.debug("Browser DB %s: %s", db_path, e)
    finally:
        conn.close()

    if not out and "web data" in low:
        # Chrome Web Data — oturumlar için minimal
        try:
            conn = _safe_connect_ro(db_path)
            if conn:
                t = _list_tables(conn)
                if "autofill" in [x.lower() for x in t]:
                    cur = conn.execute("SELECT name, value FROM autofill LIMIT 1000")
                    for r in cur.fetchall():
                        out.append(
                            {
                                "source_db": str(db_path),
                                "browser_family": "chromium_autofill",
                                "url": "",
                                "title": f"{r[0]}: {str(r[1])[:200]}",
                                "timestamp_iso": "",
                            }
                        )
                conn.close()
        except sqlite3.Error:
            pass

    return out


def _exif_gps_from_image(path: Path) -> dict[str, Any] | None:
    try:
        from PIL import Image
        from PIL.ExifTags import GPSTAGS, TAGS
    except ImportError:
        return None
    try:
        img = Image.open(path)
        exif = img.getexif()
        if not exif:
            return None
        gps_ifd = None
        for tag, val in exif.items():
            if TAGS.get(tag) == "GPSInfo" and isinstance(val, dict):
                gps_ifd = val
                break
        if not gps_ifd:
            return None

        def rat_to_float(r: Any) -> float | None:
            try:
                if hasattr(r, "numerator"):
                    return float(r.numerator) / float(r.denominator or 1)
                if isinstance(r, tuple) and len(r) == 2:
                    return float(r[0]) / float(r[1] or 1)
            except (TypeError, ZeroDivisionError, ValueError):
                return None
            return None

        def dms_to_deg(values: Any, ref: str) -> float | None:
            if not values or len(values) < 3:
                return None
            d = rat_to_float(values[0]) or 0.0
            m = rat_to_float(values[1]) or 0.0
            s = rat_to_float(values[2]) or 0.0
            deg = d + m / 60.0 + s / 3600.0
            if ref in ("S", "W"):
                deg = -deg
            return deg

        lat_vals: Any = None
        lon_vals: Any = None
        lat_ref = "N"
        lon_ref = "E"
        for gtag, raw in gps_ifd.items():
            name = GPSTAGS.get(gtag, gtag)
            if name == "GPSLatitude":
                lat_vals = raw
            elif name == "GPSLatitudeRef" and isinstance(raw, bytes):
                lat_ref = raw.decode("ascii", errors="ignore").upper()[:1] or "N"
                if lat_ref not in ("N", "S"):
                    lat_ref = "N"
            elif name == "GPSLongitude":
                lon_vals = raw
            elif name == "GPSLongitudeRef" and isinstance(raw, bytes):
                lon_ref = raw.decode("ascii", errors="ignore").upper()[:1] or "E"
                if lon_ref not in ("E", "W"):
                    lon_ref = "E"

        lat = dms_to_deg(lat_vals, lat_ref)
        lon = dms_to_deg(lon_vals, lon_ref)
        if lat is None or lon is None:
            return None
        dt = ""
        for tag, val in exif.items():
            if TAGS.get(tag) == "DateTimeOriginal" and val:
                dt = str(val)
                break
        return {
            "latitude": lat,
            "longitude": lon,
            "timestamp_iso": dt,
            "source_type": "exif",
            "source_path": str(path),
            "table": "EXIF",
        }
    except Exception as e:
        logger.debug("EXIF %s: %s", path, e)
        return None


def scan_exif_locations_in_tree(root: Path, max_images: int = 600) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if root.is_file():
        if root.suffix.lower() in IMAGE_EXTENSIONS:
            g = _exif_gps_from_image(root)
            return [g] if g else []
        return []
    n = 0
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in IMAGE_EXTENSIONS:
            continue
        if p.stat().st_size > 25_000_000:
            continue
        g = _exif_gps_from_image(p)
        if g:
            found.append(g)
            n += 1
        if n >= max_images:
            break
    return found


def parse_map_cache_database(db_path: Path) -> list[dict[str, Any]]:
    """Google Maps / gmm_storage olası tablolar — konum benzeri kolonlar."""
    conn = _safe_connect_ro(db_path)
    if not conn:
        return []
    rows: list[dict[str, Any]] = []
    try:
        tables = _list_tables(conn)
        for tbl in tables:
            tlow = tbl.lower()
            if not any(
                x in tlow
                for x in (
                    "location",
                    "destin",
                    "place",
                    "tile",
                    "latlng",
                    "coordinate",
                    "geo",
                    "da_",
                    "snapshot",
                )
            ):
                continue
            cols = {k.lower(): k for k in _table_columns(conn, tbl)}
            lat_k = lon_k = None
            for cand in ("latitude", "lat", "y0", "mylatitude"):
                if cand in cols:
                    lat_k = cols[cand]
                    break
            for cand in ("longitude", "lng", "lon", "x0", "mylongitude"):
                if cand in cols:
                    lon_k = cols[cand]
                    break
            if not lat_k or not lon_k:
                continue
            try:
                cur = conn.execute(f'SELECT "{lat_k}", "{lon_k}" FROM "{tbl}" LIMIT 3000')
                for r in cur.fetchall():
                    try:
                        la, lo = float(r[0]), float(r[1])
                    except (TypeError, ValueError):
                        continue
                    if not (-90 <= la <= 90 and -180 <= lo <= 180):
                        continue
                    rows.append(
                        {
                            "source_db": str(db_path),
                            "table": tbl,
                            "latitude": la,
                            "longitude": lo,
                            "source_type": "map_cache",
                            "timestamp_iso": "",
                        }
                    )
            except sqlite3.Error:
                continue
    finally:
        conn.close()
    return rows


def resolve_itunes_files(manifest_db: Path, backup_root: Path | None) -> dict[str, str]:
    """
    iTunes/iOS Manifest.db: fileID -> relativePath eşlemesi (basit).
    backup_root: yedek kökünde dosyalar SHA1 hash isimleriyle durur.
    """
    mapping: dict[str, str] = {}
    if not manifest_db.exists():
        return mapping
    conn = _safe_connect_ro(manifest_db)
    if not conn:
        return mapping
    try:
        cur = conn.execute(
            "SELECT fileID, relativePath, domain FROM Files WHERE relativePath IS NOT NULL"
        )
        for fid, rel, _dom in cur.fetchall():
            if fid and rel:
                mapping[str(fid)] = str(rel)
    except sqlite3.Error:
        try:
            cur = conn.execute("SELECT fileID, relativePath FROM Files")
            for fid, rel in cur.fetchall():
                if fid and rel:
                    mapping[str(fid)] = str(rel)
        except sqlite3.Error as e:
            logger.debug("Manifest okunamadi: %s", e)
    finally:
        conn.close()
    if backup_root and backup_root.is_dir():
        resolved: dict[str, str] = {}
        for fid, rel in mapping.items():
            cand = backup_root / fid[:2] / fid
            if cand.exists():
                resolved[str(cand)] = rel
        return resolved
    return {rel: rel for rel in mapping.values()}


def parse_whatsapp_database(db_path: Path) -> list[dict[str, Any]]:
    conn = _safe_connect_ro(db_path)
    if not conn:
        return []
    messages: list[dict[str, Any]] = []
    try:
        tables = _list_tables(conn)
        msg_table = None
        for name in ("messages", "message", "Messages"):
            if name in tables:
                msg_table = name
                break
        if not msg_table:
            for t in tables:
                if "message" in t.lower() and "thumb" not in t.lower():
                    msg_table = t
                    break
        if not msg_table:
            return []

        cols = _table_columns(conn, msg_table)
        col_jid = _pick_column(cols, "key_remote_jid", "remote_jid", "jid", "chat_row_id")
        col_body = _pick_column(cols, "data", "text_data", "body", "message", "data_payload")
        col_ts = _pick_column(
            cols,
            "timestamp",
            "received_timestamp",
            "receipt_server_timestamp",
            "createTime",
            "created_timestamp",
        )
        col_from_me = _pick_column(cols, "from_me", "key_from_me", "fromMe")

        if not col_body and not col_jid:
            return []

        selects = []
        if col_jid:
            selects.append(f'"{col_jid}" AS jid')
        else:
            selects.append("NULL AS jid")
        if col_body:
            selects.append(f'"{col_body}" AS body')
        else:
            selects.append("NULL AS body")
        if col_ts:
            selects.append(f'"{col_ts}" AS ts')
        else:
            selects.append("NULL AS ts")
        if col_from_me:
            selects.append(f'"{col_from_me}" AS from_me')
        else:
            selects.append("NULL AS from_me")

        sql = f'SELECT {", ".join(selects)} FROM "{msg_table}" LIMIT 50000'
        cur = conn.execute(sql)

        for row in cur.fetchall():
            jid, body, ts, from_me = row[0], row[1], row[2], row[3] if len(row) > 3 else None
            jid_s = str(jid) if jid is not None else ""
            messages.append(
                {
                    "source_db": str(db_path),
                    "jid": jid_s,
                    "sender_jid": jid_s,
                    "chat_jid": jid_s,
                    "body": str(body)[:4000] if body is not None else "",
                    "timestamp_iso": _ts_to_iso_ms(ts) if ts else "",
                    "from_me": bool(from_me) if from_me is not None else None,
                }
            )
    finally:
        conn.close()
    return messages


# msgstore.db / ChatStorage net adı (WhatsApp analizi giriş noktası)
parse_msgstore_database = parse_whatsapp_database


def parse_sms_database(db_path: Path) -> list[dict[str, Any]]:
    """
    Android `mmssms.db` — `sms` tablosu (body, address, date, type).
    type: 1 gelen, 2 giden (cihaza göre farklılık gösterebilir; UNKNOWN için None).
    """
    conn = _safe_connect_ro(db_path)
    if not conn:
        return []
    messages: list[dict[str, Any]] = []
    try:
        tables = _list_tables(conn)
        if "sms" not in tables:
            return []
        cols = _table_columns(conn, "sms")
        col_addr = _pick_column(cols, "address", "phone", "recipient_ids")
        col_body = _pick_column(cols, "body", "text")
        col_date = _pick_column(cols, "date", "date_sent")
        col_type = _pick_column(cols, "type")
        if not col_date:
            return []
        sel = [
            f'"{col_addr}" AS address' if col_addr else "NULL AS address",
            f'"{col_body}" AS body' if col_body else "NULL AS body",
            f'"{col_date}" AS sms_date',
            f'"{col_type}" AS msg_type' if col_type else "NULL AS msg_type",
        ]
        sql = f'SELECT {", ".join(sel)} FROM "sms" ORDER BY "{col_date}" ASC LIMIT 50000'
        cur = conn.execute(sql)
        for row in cur.fetchall():
            addr, body, ts_raw, typ_raw = row[0], row[1], row[2], row[3] if len(row) > 3 else None
            addr_s = str(addr) if addr is not None else ""
            body_s = str(body)[:4000] if body is not None else ""
            ts_iso = _ts_to_iso_ms(ts_raw)
            from_me: bool | None = None
            try:
                t_int = int(typ_raw)  # Android: 1=inbox 2=sent
                if t_int in (1, 2):
                    from_me = t_int == 2
            except (TypeError, ValueError):
                pass
            messages.append(
                {
                    "source_db": str(db_path),
                    "channel": "sms",
                    "address": addr_s,
                    "peer": addr_s,
                    "body": body_s,
                    "timestamp_iso": ts_iso,
                    "from_me": from_me,
                    "sms_type": typ_raw,
                }
            )
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return messages


def parse_android_call_log(db_path: Path) -> list[dict[str, Any]]:
    conn = _safe_connect_ro(db_path)
    if not conn:
        return []
    out: list[dict[str, Any]] = []
    try:
        tables = _list_tables(conn)
        tbl = None
        for name in ("calls", "Calls", "call"):
            if name in tables:
                tbl = name
                break
        if not tbl:
            for t in tables:
                if "call" in t.lower():
                    tbl = t
                    break
        if not tbl:
            return []

        cols = _table_columns(conn, tbl)
        c_num = _pick_column(cols, "number", "phone_number", "address", "normalized_number")
        c_date = _pick_column(cols, "date", "timestamp", "creation_time", "call_start_time")
        c_dur = _pick_column(cols, "duration", "call_duration")
        c_type = _pick_column(cols, "type", "call_type", "presentation")

        parts = []
        for expr, alias in (
            (c_num, "num"),
            (c_date, "call_date"),
            (c_dur, "duration"),
            (c_type, "call_type"),
        ):
            if expr:
                parts.append(f'"{expr}" AS {alias}')
        if not parts:
            return []

        sql = f'SELECT {", ".join(parts)} FROM "{tbl}" LIMIT 20000'
        cur = conn.execute(sql)
        for row in cur.fetchall():
            rec = {"source_db": str(db_path)}
            names = [p.split(" AS ")[-1].strip() for p in parts]
            for i, k in enumerate(names):
                rec[k] = row[i]
            if rec.get("call_date"):
                rec["call_date_iso"] = _ts_to_iso_ms(rec["call_date"])
            out.append(rec)
    finally:
        conn.close()
    return out


def parse_location_databases(db_path: Path) -> list[dict[str, Any]]:
    conn = _safe_connect_ro(db_path)
    if not conn:
        return []
    rows_out: list[dict[str, Any]] = []
    try:
        tables = _list_tables(conn)
        for tbl in tables:
            tlow = tbl.lower()
            if not any(
                x in tlow
                for x in (
                    "location",
                    "place",
                    "timeline",
                    "cell",
                    "position",
                    "geo",
                    "map",
                )
            ):
                continue
            cols = {k.lower(): k for k in _table_columns(conn, tbl)}
            lat_k = None
            lon_k = None
            for cand in ("latitude", "lat", "mylatitude", "double_latitude"):
                if cand in cols:
                    lat_k = cols[cand]
                    break
            for cand in ("longitude", "lng", "lon", "mylongitude", "double_longitude"):
                if cand in cols:
                    lon_k = cols[cand]
                    break
            if not lat_k or not lon_k:
                continue

            time_k = None
            for cand in ("timestamp", "time", "date", "creation_time", "last_time", "visited_time"):
                if cand in cols:
                    time_k = cols[cand]
                    break

            sel = [f'"{lat_k}" AS lat', f'"{lon_k}" AS lon']
            if time_k:
                sel.append(f'"{time_k}" AS ts')
            try:
                cur = conn.execute(f'SELECT {", ".join(sel)} FROM "{tbl}" LIMIT 5000')
                for r in cur.fetchall():
                    lat, lon = r[0], r[1]
                    try:
                        la, lo = float(lat), float(lon)
                    except (TypeError, ValueError):
                        continue
                    if not (-90 <= la <= 90 and -180 <= lo <= 180):
                        continue
                    rec: dict[str, Any] = {
                        "source_db": str(db_path),
                        "table": tbl,
                        "latitude": la,
                        "longitude": lo,
                        "source_type": "sqlite_location_db",
                    }
                    if len(r) > 2 and r[2] is not None:
                        rec["timestamp_iso"] = _ts_to_iso_ms(r[2])
                    rows_out.append(rec)
            except sqlite3.Error:
                continue
    finally:
        conn.close()
    return rows_out


def estimate_freelist_pages(db_path: Path) -> dict[str, Any]:
    """PRAGMA ile free-list istatistikleri (silinmiş içerik adayı sayfalar)."""
    conn = _safe_connect_ro(db_path)
    if not conn:
        return {"error": "db_open_failed"}
    info: dict[str, Any] = {"path": str(db_path)}
    try:
        cur = conn.execute("PRAGMA page_count")
        info["page_count"] = cur.fetchone()[0]
        cur = conn.execute("PRAGMA page_size")
        info["page_size"] = cur.fetchone()[0]
        cur = conn.execute("PRAGMA freelist_count")
        info["freelist_count"] = cur.fetchone()[0]
        try:
            cur = conn.execute("PRAGMA auto_vacuum")
            info["auto_vacuum"] = cur.fetchone()[0]
        except sqlite3.Error:
            pass
    except sqlite3.Error as e:
        info["error"] = str(e)
    finally:
        conn.close()
    return info


def carve_deleted_whatsapp_candidates(
    db_path: Path,
    max_hits: int = 200,
    window: int = 384,
) -> list[dict[str, Any]]:
    """
    SQLite içinde silinmiş satır adayları — birleşik strateji:

    1) SQLite **free list** istatistiği (PRAGMA freelist_count / page_count) — boşa çıkan
       sayfalarda eski içerik kalıntıları adayı.
    2) Dosyayı ham bayt olarak tarar: WhatsApp JID kalıpları (free-list / unallocated bölgeler).
    3) Aktif tabloda görülmeyen offset'lerde metin fragmanı özetleri (triage).

    Bu Magnet / Oxygen seviyesinde tam parse değildir; savcıya sunulacak ön sıra (triage) üretir.
    """
    findings: list[dict[str, Any]] = []
    fl = estimate_freelist_pages(db_path)
    findings.append({"type": "freelist_summary", **fl})

    try:
        raw = db_path.read_bytes()
    except OSError as e:
        findings.append({"type": "error", "detail": str(e)})
        return findings

    # Aktif Veritabanından JID + gövde örneği (karşılaştırma için küçük örnek)
    active_jids: set[str] = set()
    for m in parse_whatsapp_database(db_path)[:300]:
        if m.get("jid"):
            active_jids.add(m["jid"][:80])

    seen_off: set[int] = set()
    for m in JID_PATTERN.finditer(raw):
        if len(findings) >= max_hits + 5:
            break
        start = max(0, m.start() - 32)
        end = min(len(raw), m.end() + window)
        chunk = raw[start:end]
        jid_txt = ""
        try:
            jid_txt = m.group(1).decode("utf-8", errors="replace")
        except Exception:
            jid_txt = repr(m.group(1))[:120]

        text_guess = ""
        for tc in TEXT_CHUNK_RE.finditer(chunk):
            try:
                s = tc.group(0).decode("utf-8", errors="replace").strip()
                if len(s) > 15:
                    text_guess = s[:500]
                    break
            except Exception:
                continue

        off = m.start()
        if off in seen_off:
            continue
        seen_off.add(off)

        conf = "medium"
        if jid_txt and jid_txt not in active_jids and "@" in jid_txt:
            conf = "high"
        findings.append(
            {
                "type": "carved_jid_fragment",
                "offset": off,
                "jid_guess": jid_txt[:200],
                "text_preview": text_guess,
                "confidence": conf,
                "note": "Ham dosyada (free list / unallocated bölge adayı) bulundu",
            }
        )

    return findings[: max_hits + 3]


def classify_backup_path(path: Path) -> str:
    low = str(path).lower()
    if "whatsapp" in low or "com.whatsapp" in low:
        return "whatsapp_candidate"
    if "call" in low or "contacts" in low or "dialer" in low:
        return "calls_candidate"
    if "manifest.db" == path.name.lower():
        return "itunes_manifest"
    return "unknown"


def ingest_backup_directory(
    evidence_path: Path,
    manifest_lookup: Path | None = None,
    max_exif_images: int = 600,
) -> dict[str, Any]:
    """
    FileSystem parser: rehber, WhatsApp, History, harita önbellekleri + EXIF konumları.
    """
    whatsapp: list[dict[str, Any]] = []
    sms_messages: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    locations: list[dict[str, Any]] = []
    contacts: list[dict[str, Any]] = []
    browser_history: list[dict[str, Any]] = []
    carved_all: list[dict[str, Any]] = []
    meta_errors: list[str] = []

    if manifest_lookup and manifest_lookup.exists():
        resolve_itunes_files(manifest_lookup, evidence_path if evidence_path.is_dir() else None)

    targets = discover_filesystem_parser_targets(evidence_path)
    scanned: set[str] = set()

    def mark(p: Path) -> None:
        scanned.add(str(p.resolve()))

    try:
        for p in targets["contacts"]:
            mark(p)
            contacts.extend(parse_contacts_database(p))
        locations.extend(derive_locations_from_contact_rows(contacts))

        for p in targets["browser_history"]:
            mark(p)
            browser_history.extend(parse_browser_history_database(p))
        locations.extend(derive_locations_from_browser_maps_urls(browser_history))

        for p in targets["map_cache"]:
            mark(p)
            locations.extend(parse_map_cache_database(p))
            locations.extend(parse_location_databases(p))

        for p in targets["sms"]:
            mark(p)
            sms_messages.extend(parse_sms_database(p))

        for p in targets["whatsapp"]:
            mark(p)
            w = parse_whatsapp_database(p)
            whatsapp.extend(w)
            carved = carve_deleted_whatsapp_candidates(p)
            for c in carved:
                c["source_db"] = str(p)
            carved_all.extend(carved)

        # Kalan SQLite: arama kaydı + konum + sezgisel WhatsApp
        for dbp in targets["other_sqlite"]:
            if str(dbp.resolve()) in scanned:
                continue
            low = dbp.as_posix().lower()
            try:
                if any(x in low for x in ("calllog", "dialer", "calls.db")):
                    calls.extend(parse_android_call_log(dbp))
                locations.extend(parse_location_databases(dbp))
                conn = _safe_connect_ro(dbp)
                if conn:
                    tables = _list_tables(conn)
                    conn.close()
                    ts = " ".join(tables).lower()
                    if "messages" in ts and "whatsapp" not in low:
                        w = parse_whatsapp_database(dbp)
                        if w:
                            whatsapp.extend(w)
                            carved_all.extend(
                                [{**x, "source_db": str(dbp)} for x in carve_deleted_whatsapp_candidates(dbp)]
                            )
                    if "calls" in ts:
                        calls.extend(parse_android_call_log(dbp))
                    if "sms" in tables and ("mmssms" in low or "telephony" in low):
                        sms_messages.extend(parse_sms_database(dbp))
            except OSError as e:
                meta_errors.append(f"{dbp}: {e}")

        # EXIF GPS (galeri / DCIM / Fotoğraflar)
        try:
            locations.extend(scan_exif_locations_in_tree(evidence_path, max_images=max_exif_images))
        except OSError as e:
            meta_errors.append(f"EXIF tarama: {e}")
    except OSError as e:
        meta_errors.append(str(e))

    all_sqlite_count = sum(len(targets[k]) for k in targets)

    return {
        "whatsapp_messages": whatsapp,
        "sms_messages": sms_messages,
        "contacts": contacts,
        "browser_history": browser_history,
        "call_logs": calls,
        "locations": locations,
        "carving_findings": carved_all,
        "sqlite_files_scanned": all_sqlite_count,
        "filesystem_targets": {k: len(v) for k, v in targets.items()},
        "errors": meta_errors,
    }


class MobileForensicsModule(BaseModule):
    """
    SQLite Expert — Android/iOS yedekleri; WhatsApp msgstore; rehber/arama/harita konumu;
    free-list temelli carving (Magnet AXIOM ile uyumlu çıktı hedefi).
    """

    name = "mobile"
    description = (
        "SQLite Expert + msgstore + konum (rehber, arama, Maps, EXIF) + free-list carving"
    )
    required_tools = []

    def execute(
        self,
        evidence_path: Path,
        output_dir: Path,
        itunes_manifest: Path | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = Path(evidence_path)

        if not evidence_path.exists():
            return {
                "success": False,
                "error": f"Kanıt yolu yok: {evidence_path}",
            }

        bundle = ingest_backup_directory(
            evidence_path,
            manifest_lookup=itunes_manifest,
            max_exif_images=int(kwargs.get("max_exif_images", 600)),
        )

        out_path = output_dir / "mobile_findings.json"
        payload = {
            "success": True,
            "evidence_path": str(evidence_path),
            "stats": {
                "whatsapp_rows": len(bundle["whatsapp_messages"]),
                "sms_rows": len(bundle["sms_messages"]),
                "contacts_rows": len(bundle["contacts"]),
                "browser_history_rows": len(bundle["browser_history"]),
                "call_log_rows": len(bundle["call_logs"]),
                "location_rows": len(bundle["locations"]),
                "carving_rows": len(bundle["carving_findings"]),
                "sqlite_files": bundle["sqlite_files_scanned"],
            },
            **bundle,
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        logger.info(
            "Mobil: rehber=%s tarayici=%s WA=%s SMS=%s konum=%s → %s",
            len(bundle["contacts"]),
            len(bundle["browser_history"]),
            len(bundle["whatsapp_messages"]),
            len(bundle["sms_messages"]),
            len(bundle["locations"]),
            out_path,
        )

        return {
            "success": True,
            "output_path": str(out_path),
            "mobile_findings_path": str(out_path),
            "stats": payload["stats"],
            **{
                k: bundle[k]
                for k in (
                    "whatsapp_messages",
                    "sms_messages",
                    "contacts",
                    "browser_history",
                    "call_logs",
                    "locations",
                    "carving_findings",
                )
            },
        }


def run_mobile_analysis(
    evidence_path: str | Path,
    output_dir: str | Path | None = None,
    itunes_manifest: str | Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    mod = MobileForensicsModule()
    out = Path(output_dir) if output_dir else RESULTS_DEFAULT
    return mod.execute(
        Path(evidence_path),
        out,
        itunes_manifest=Path(itunes_manifest) if itunes_manifest else None,
        **kwargs,
    )
