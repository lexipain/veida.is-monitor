#!/usr/bin/env python3
"""
Monitor veida.is fishing-permit availability for given months (default: June & July)
and email yourself when a slot opens up.

Fetches the product-category page, parses the HTML table, and reports any row whose
month matches and whose status ("Staða") indicates stock is available
(i.e. "N á lager", as opposed to "Ekki á lager").

A small JSON state file means you're only emailed when something NEW becomes
available, not on every run.

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

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 veida-monitor/1.0"
)

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
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


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
    return resp.text


def parse_rows(html: str):
    """
    Return a list of dicts, one per product row:
        {name, url, price, status, available, count, month}
    Works against the standard <table> by reading its header cells, so it does not
    depend on plugin-specific CSS classes.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Find the table that has a "Staða" (status) header.
    target = None
    for table in soup.find_all("table"):
        header_cells = table.find_all(["th", "td"], limit=20)
        header_text = strip_accents(" ".join(c.get_text(" ", strip=True) for c in header_cells))
        if "stada" in header_text and "vara" in header_text:
            target = table
            break
    if target is None:
        raise RuntimeError("Could not locate the products table (no 'Staða'/'Vara' header found).")

    # Build column-name -> index map from the header row.
    header_row = target.find("tr")
    headers = [strip_accents(th.get_text(" ", strip=True)) for th in header_row.find_all(["th", "td"])]

    def col(*candidates):
        for cand in candidates:
            for i, h in enumerate(headers):
                if cand in h:
                    return i
        return None

    idx_vara = col("vara")
    idx_verd = col("verd")
    idx_stada = col("stada")
    idx_tag = col("product_tag", "tag")        # clean ASCII month slug, if present
    idx_timabil = col("timabil")               # Icelandic month name column

    rows = []
    body = target.find("tbody") or target
    for tr in body.find_all("tr"):
        cells = tr.find_all("td")
        if not cells or idx_vara is None or idx_vara >= len(cells):
            continue  # header or empty row

        vara_cell = cells[idx_vara]
        name = vara_cell.get_text(" ", strip=True)
        if not name:
            continue
        link = vara_cell.find("a")
        prod_url = link["href"] if link and link.has_attr("href") else URL

        status = cells[idx_stada].get_text(" ", strip=True) if idx_stada is not None and idx_stada < len(cells) else ""
        price = cells[idx_verd].get_text(" ", strip=True) if idx_verd is not None and idx_verd < len(cells) else ""

        # Availability: "N á lager" => available; "Ekki á lager" => sold out.
        status_norm = strip_accents(status)
        available = ("lager" in status_norm) and ("ekki" not in status_norm)
        m = re.search(r"(\d+)", status_norm)
        count = int(m.group(1)) if (m and available) else 0

        # Month detection: prefer the clean tag slug, then Tímabil, then the name.
        month_sources = []
        if idx_tag is not None and idx_tag < len(cells):
            month_sources.append(cells[idx_tag].get_text(" ", strip=True))
        if idx_timabil is not None and idx_timabil < len(cells):
            month_sources.append(cells[idx_timabil].get_text(" ", strip=True))
        month_sources.append(name)
        month_blob = strip_accents(" ".join(month_sources))

        month = None
        for candidate in ("januar", "februar", "mars", "april", "mai", "juni",
                           "juli", "agust", "september", "oktober", "november", "desember"):
            if candidate in month_blob:
                month = candidate
                break

        rows.append({
            "name": name,
            "url": prod_url,
            "price": price,
            "status": status,
            "available": available,
            "count": count,
            "month": month,
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
        send_email(new_rows)

    save_state(current_keys)
    return 0


if __name__ == "__main__":
    sys.exit(main())
