#!/usr/bin/env python3
"""
Monitor veida.is fishing-permit availability for given months (default: June & July)
and email yourself when a slot opens up.

Fetches the product-category page, parses the HTML table, and reports any row whose
month matches and whose status ("Staða") indicates stock is available
(i.e. "N á lager", as opposed to "Ekki á lager").

A small JSON state file means you're only emailed when something NEW becomes
available, not on every run.

NOTE ON COMPRESSION:
  The request advertises Brotli ("Accept-Encoding: ... br"). requests/urllib3 will
  only DECODE Brotli if the 'brotli' package is installed. If it isn't, resp.text is
  undecoded binary and parsing silently fails. Install it once with:
        pip install brotli
  (fetch_html() below also detects this case and raises a clear error.)

Required environment variables (Gmail example):
  SMTP_HOST   smtp.gmail.com        (default)
  SMTP_PORT   587                   (default)
  SMTP_USER   you@gmail.com
  SMTP_PASS   your 16-char Gmail App Password (NOT your normal password)
  EMAIL_FROM  you@gmail.com         (defaults to SMTP_USER)
  EMAIL_TO    you@gmail.com         (self-email: same address is fine)

Exit code is 0 normally, 2 if a fetch/parse error occurred (useful for CI alerting).
"""

import os
import re
import sys
import gzip
import zlib
import json
import smtplib
import unicodedata
from email.message import EmailMessage

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
URL = os.environ.get(
    "MONITOR_URL",
    "https://veida.is/voruflokkur/hlidarvatn-arblik/",
)

# Months to watch, as accent-stripped lowercase Icelandic names.
# júní -> "juni", júlí -> "juli", ágúst -> "agust", etc.
WATCH_MONTHS = {
    m.strip().lower()
    for m in os.environ.get("MONITOR_MONTHS", "juni,juli").split(",")
    if m.strip()
}

STATE_FILE = os.environ.get("MONITOR_STATE_FILE", "veida_state.json")

# Set MONITOR_DEBUG=1 to print what was actually received (encoding, length, snippet).
DEBUG = os.environ.get("MONITOR_DEBUG", "").strip() not in ("", "0", "false", "False")

# Set MONITOR_NO_EMAIL=1 to run detection + state-save WITHOUT sending email.
# Useful for testing that rows are matched and the JSON file is written.
NO_EMAIL = os.environ.get("MONITOR_NO_EMAIL", "").strip() not in ("", "0", "false", "False")

# Browser-identical headers. The Accept / User-Agent values are what get you past
# the WAF (the server returns 415 without them); keep them as-is.
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "is,en-US;q=0.9,en;q=0.8",
    # 'br' (Brotli) deliberately NOT advertised: requests only decodes Brotli when
    # the 'brotli' package is installed, and an undecoded br response is the usual
    # cause of binary-garbage output. gzip/deflate are always decodable by the
    # standard library. (fetch_html still recovers br if a server forces it and
    # brotli happens to be importable.) This change does NOT affect the 415 — that
    # was the Accept / User-Agent headers, not Accept-Encoding.
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

MONTHS = (
    "januar", "februar", "mars", "april", "mai", "juni",
    "juli", "agust", "september", "oktober", "november", "desember",
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def strip_accents(text: str) -> str:
    """Lowercase and remove diacritics: 'Júlí' -> 'juli', 'Ágúst' -> 'agust'."""
    nfkd = unicodedata.normalize("NFKD", text)
    no_marks = "".join(c for c in nfkd if not unicodedata.combining(c))
    # Icelandic-specific letters that NFKD doesn't decompose:
    no_marks = (
        no_marks.replace("ð", "d").replace("Ð", "d")
        .replace("þ", "th").replace("Þ", "th")
        .replace("æ", "ae").replace("Æ", "ae")
    )
    return no_marks.lower().strip()


def fetch_html(url: str) -> str:
    resp = requests.get(url, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    text = resp.text

    if DEBUG:
        print(f"[debug] status={resp.status_code} "
              f"content-encoding={resp.headers.get('Content-Encoding')!r} "
              f"len={len(text)}", file=sys.stderr)
        print(f"[debug] first 200 chars: {text[:200]!r}", file=sys.stderr)

    # Fast path: requests already handed us decoded HTML.
    if _looks_like_html(text):
        return text

    # Otherwise the body is still compressed (requests couldn't decode the
    # Content-Encoding). Decompress the raw bytes ourselves.
    enc = resp.headers.get("Content-Encoding") or ""
    decoded = _manual_decompress(resp.content, enc)
    if decoded is not None:
        recovered = decoded.decode(resp.encoding or "utf-8", "replace")
        if _looks_like_html(recovered):
            if DEBUG:
                print(f"[debug] manually decompressed via Content-Encoding="
                      f"{enc!r}", file=sys.stderr)
            return recovered

    # Still no usable HTML — explain precisely what's wrong.
    hint = ""
    if "br" in enc.lower():
        try:
            import brotli  # noqa: F401
        except ImportError:
            hint = (" The response is Brotli-encoded but the 'brotli' package "
                    "isn't importable in THIS Python environment. Either run "
                    "`pip install brotli` for the same interpreter that runs this "
                    "script, or keep Accept-Encoding as 'gzip, deflate'.")
    raise RuntimeError(
        f"Response isn't decodable HTML (Content-Encoding={enc or 'none'!r}, "
        f"{len(resp.content)} raw bytes).{hint}"
    )


# Multi-character HTML tokens — unlike a lone '<', these effectively never occur
# in random/compressed binary, so they reliably distinguish HTML from garbage.
_HTML_MARKERS = (
    "<!doctype", "<html", "<head", "<body", "<table",
    "<div", "<meta", "<span", "<script", "<a ",
)


def _looks_like_html(s: str) -> bool:
    head = s[:8192].lower()
    return any(tok in head for tok in _HTML_MARKERS)


def _manual_decompress(raw: bytes, content_encoding: str):
    """
    Decompress raw bytes, trying the declared Content-Encoding first, then every
    other method as a fallback (servers sometimes send an encoding they didn't
    advertise, or label it wrong). Returns bytes, or None if nothing worked.
    """
    enc = (content_encoding or "").lower()
    order = [m for m in ("br", "gzip", "deflate") if m in enc]
    order += [m for m in ("br", "gzip", "deflate") if m not in order]

    for method in order:
        try:
            if method == "br":
                try:
                    import brotli
                except ImportError:
                    continue
                return brotli.decompress(raw)
            if method == "gzip":
                return gzip.decompress(raw)
            if method == "deflate":
                try:
                    return zlib.decompress(raw)               # zlib-wrapped
                except zlib.error:
                    return zlib.decompress(raw, -zlib.MAX_WBITS)  # raw deflate
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- #
# Row extraction
# --------------------------------------------------------------------------- #
def _availability(status: str):
    """('1 á lager') -> (available=True, count=1); ('Ekki á lager') -> (False, 0)."""
    status_norm = strip_accents(status)
    available = ("lager" in status_norm) and ("ekki" not in status_norm)
    m = re.search(r"(\d+)", status_norm)
    count = int(m.group(1)) if (m and available) else 0
    return available, count


def _detect_month(*sources) -> str | None:
    """Find the first month name in any of the given text blobs (e.g. name, slug)."""
    blob = strip_accents(" ".join(s for s in sources if s))
    for candidate in MONTHS:
        if candidate in blob:
            return candidate
    return None


def parse_rows(html: str):
    """
    Return a list of dicts, one per product row:
        {name, url, price, status, available, count, month}

    Primary strategy: locate the table by its 'Vara'/'Staða' headers and read
    columns by index. If that fails for any reason, fall back to scanning every
    row that links to a /vara/ product page (robust to column reordering or a
    layout change).
    """
    soup = BeautifulSoup(html, "html.parser")

    # ---- primary: header-mapped table ------------------------------------- #
    target = None
    for table in soup.find_all("table"):
        header_cells = table.find_all(["th", "td"], limit=20)
        header_text = strip_accents(
            " ".join(c.get_text(" ", strip=True) for c in header_cells)
        )
        if "stada" in header_text and "vara" in header_text:
            target = table
            break

    if target is not None:
        rows = _parse_table_by_header(target)
        if rows:
            return rows

    # ---- fallback: anchor-based scan -------------------------------------- #
    rows = _parse_by_product_links(soup)
    if rows:
        if DEBUG:
            print("[debug] used anchor-based fallback parser", file=sys.stderr)
        return rows

    # ---- nothing worked: fail loudly and informatively -------------------- #
    snippet = soup.get_text(" ", strip=True)[:300]
    raise RuntimeError(
        "Could not locate any product rows. "
        f"Found {len(soup.find_all('table'))} table(s); "
        f"page text starts: {snippet!r}"
    )


def _parse_table_by_header(target):
    header_row = target.find("tr")
    headers = [
        strip_accents(th.get_text(" ", strip=True))
        for th in header_row.find_all(["th", "td"])
    ]

    def col(*candidates):
        for cand in candidates:
            for i, h in enumerate(headers):
                if cand in h:
                    return i
        return None

    idx_vara = col("vara")
    idx_verd = col("verd")
    idx_stada = col("stada")
    idx_tag = col("product_tag", "tag")   # clean ASCII month slug, if present
    idx_timabil = col("timabil")          # Icelandic month name column

    if idx_vara is None:
        return []

    rows = []
    body = target.find("tbody") or target
    for tr in body.find_all("tr"):
        cells = tr.find_all("td")
        if not cells or idx_vara >= len(cells):
            continue  # header or empty row

        vara_cell = cells[idx_vara]
        name = vara_cell.get_text(" ", strip=True)
        if not name:
            continue
        link = vara_cell.find("a")
        prod_url = link["href"] if link and link.has_attr("href") else URL

        def cell_text(idx):
            return cells[idx].get_text(" ", strip=True) if idx is not None and idx < len(cells) else ""

        status = cell_text(idx_stada)
        price = cell_text(idx_verd)
        available, count = _availability(status)

        month = _detect_month(cell_text(idx_tag), cell_text(idx_timabil), name, prod_url)

        rows.append({
            "name": name, "url": prod_url, "price": price, "status": status,
            "available": available, "count": count, "month": month,
        })
    return rows


def _parse_by_product_links(soup):
    """Layout-agnostic: any <tr> containing a link to /vara/ is a product row."""
    rows = []
    seen = set()
    for tr in soup.find_all("tr"):
        link = tr.find("a", href=re.compile(r"/vara/"))
        if not link:
            continue
        prod_url = link.get("href", URL)
        if prod_url in seen:
            continue
        seen.add(prod_url)

        name = link.get_text(" ", strip=True)
        row_text = tr.get_text(" ", strip=True)

        # Status: the cell mentioning "lager"; price: the cell mentioning "kr".
        status, price = "", ""
        for td in tr.find_all("td"):
            txt = td.get_text(" ", strip=True)
            low = strip_accents(txt)
            if "lager" in low and not status:
                status = txt
            elif "kr" in low and not price:
                price = txt

        available, count = _availability(status)
        month = _detect_month(prod_url, name, row_text)

        rows.append({
            "name": name, "url": prod_url, "price": price, "status": status,
            "available": available, "count": count, "month": month,
        })
    return rows


def matching_available(rows):
    """Rows that are available AND in one of the watched months."""
    return [r for r in rows if r["available"] and r["month"] in WATCH_MONTHS]


# --------------------------------------------------------------------------- #
# State (dedupe so we only alert on newly-available slots)
# --------------------------------------------------------------------------- #
def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f).get("available", []))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def save_state(keys):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"available": sorted(keys)}, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# Email notification
# --------------------------------------------------------------------------- #
def send_email(new_rows):
    lines = ["Veidileyfi laust! (a fishing permit is available)\n"]
    for r in new_rows:
        lines.append(f"- {r['name']} - {r['status']} - {r['price']}\n  {r['url']}")
    lines.append("\nBook here: " + URL)
    body = "\n".join(lines)

    user = os.environ["SMTP_USER"]
    msg = EmailMessage()
    msg["Subject"] = f"Veidileyfi laust i Hlidarvatni ({len(new_rows)})"
    msg["From"] = os.environ.get("EMAIL_FROM", user)
    msg["To"] = os.environ.get("EMAIL_TO", user)   # self-email by default
    msg.set_content(body)

    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.starttls()
        s.login(user, os.environ["SMTP_PASS"])
        s.send_message(msg)

    print(f"[notify] emailed {msg['To']}: {len(new_rows)} new item(s)", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    try:
        html = fetch_html(URL)
        rows = parse_rows(html)
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        return 2

    available = matching_available(rows)
    current_keys = {r["url"] for r in available}
    previous_keys = load_state()
    new_keys = current_keys - previous_keys

    watched = ", ".join(sorted(WATCH_MONTHS))
    print(f"[info] checked {len(rows)} rows; "
          f"{len(available)} available in [{watched}]; "
          f"{len(new_keys)} newly available", file=sys.stderr)

    if new_keys:
        new_rows = [r for r in available if r["url"] in new_keys]
        if NO_EMAIL:
            print(f"[info] MONITOR_NO_EMAIL set - not sending; would notify about "
                  f"{len(new_rows)} item(s)", file=sys.stderr)
        else:
            try:
                send_email(new_rows)
            except Exception as e:
                # Email failed. Do NOT record these as seen, so the next run
                # retries them. State is left untouched on purpose.
                print(f"[error] email failed - state NOT updated so it retries "
                      f"next run: {e}", file=sys.stderr)
                return 2

    save_state(current_keys)
    return 0


if __name__ == "__main__":
    sys.exit(main())
