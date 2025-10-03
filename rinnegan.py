#!/usr/bin/env python3

from __future__ import annotations

import html
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

import requests

# ---------------- Configuration ----------------
BASE_RAW = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
PLATFORM_FILES = {
    "HackerOne": f"{BASE_RAW}/hackerone_data.json",
    "Bugcrowd": f"{BASE_RAW}/bugcrowd_data.json",
    "Intigriti": f"{BASE_RAW}/intigriti_data.json",
    "YesWeHack": f"{BASE_RAW}/yeswehack_data.json",
    "Federacy": f"{BASE_RAW}/federacy_data.json",
    "DomainsTXT": f"{BASE_RAW}/domains.txt",
    "WildcardsTXT": f"{BASE_RAW}/wildcards.txt",
}
DEFAULT_PLATFORMS = ["HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "Federacy"]

# NOTE: Keeping same tokens/IDs as in your original file (you can override via env vars)
TELEGRAM_TOKEN = "TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID = "-TELEGRAM_CHAT_ID"
TELEGRAM_THREAD_ID = None

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PREV_SNAPSHOT = DATA_DIR / "prev.json"
TIMEOUT = 15
MAX_RETRIES = 3
RETRY_BACKOFF = 2
TELEGRAM_MAX_LEN = 4000
SLEEP_INTERVAL = 3600  # seconds between automatic runs

# Message grouping & send rate
PROJECTS_PER_MESSAGE = 8  # how many program-blocks per Telegram message
SEND_PAUSE_SECONDS = 1    # pause between sending messages (helps avoid 429)

# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("rinnegan")

# ---------------- Helpers ----------------

def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_prev() -> Dict[str, Any]:
    if not PREV_SNAPSHOT.exists():
        return {}
    try:
        with PREV_SNAPSHOT.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        logger.exception("Could not load previous snapshot, starting fresh")
        return {}


def save_prev(data: Dict[str, Any]) -> None:
    try:
        serializable = {str(k): v for k, v in data.items()} if isinstance(data, dict) else data
        with PREV_SNAPSHOT.open("w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)
    except Exception:
        logger.exception("Failed to save snapshot")


def fetch_text(url: str, session: Optional[requests.Session] = None) -> Optional[str]:
    s = session or requests.Session()
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.debug("GET %s (attempt %d)", url, attempt)
            r = s.get(url, timeout=TIMEOUT)
            r.raise_for_status()
            return r.text
        except Exception as e:
            last_exc = e
            wait = RETRY_BACKOFF ** attempt
            logger.warning("Fetch attempt %d failed for %s: %s — retrying in %ds", attempt, url, e, wait)
            time.sleep(wait)
    logger.warning("Giving up fetching %s: %s", url, last_exc)
    return None


def fetch_json(url: str, session: Optional[requests.Session] = None) -> Optional[Any]:
    text = fetch_text(url, session=session)
    if text is None:
        return None
    try:
        return json.loads(text)
    except Exception:
        logger.warning("Content at %s was not JSON", url)
        return None


def program_unique_key(p: Dict[str, Any]) -> str:
    url = p.get("url") or p.get("program_url") or p.get("link")
    if url:
        return str(url)
    name = p.get("name") or p.get("title") or "<unknown>"
    plat = (p.get("platform") or p.get("provider") or "").strip()
    return f"{plat}::{name}"


def normalize_platform(p: Optional[str]) -> str:
    if not p:
        return ""
    return p.strip()


# ---------- number / numeric helpers (used by HackerOne logic) ----------
def _parse_number_like(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        try:
            return int(v)
        except Exception:
            return None
    if isinstance(v, dict):
        if "value" in v:
            return _parse_number_like(v["value"])
        for key in ("min", "max", "amount", "value", "amount_cents"):
            if key in v:
                return _parse_number_like(v[key])
        for val in v.values():
            n = _parse_number_like(val)
            if n:
                return n
        return None
    if isinstance(v, str):
        s = v.strip()
        m = re.search(r"(\d{1,3}(?:[,\d]{0,})?(?:\.\d+)?)", s.replace(",", ""))
        if m:
            try:
                return int(float(m.group(1)))
            except Exception:
                return None
        return None
    return None


def _search_for_numeric_in_program(prog: Dict[str, Any]) -> Optional[int]:
    keys = ("max_payout", "min_payout", "max_bounty", "min_bounty", "max_reward", "min_reward", "bounty", "reward")
    for k in keys:
        if k in prog:
            n = _parse_number_like(prog[k])
            if n:
                return n
    for k in ("targets", "structured_scopes", "scope", "policies"):
        v = prog.get(k)
        if isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    for kk in ("reward", "bounty", "max_payout", "min_payout", "offers"):
                        if kk in item:
                            n = _parse_number_like(item[kk])
                            if n:
                                return n
                    for val in item.values():
                        n = _parse_number_like(val)
                        if n:
                            return n
    return None


def get_bounty(program: Dict[str, Any]) -> str:
    min_keys = ["min_bounty", "bounty_min", "min_reward", "min_payout", "minimum_reward", "min_payout_amount", "min_payout_value", "min"]
    max_keys = ["max_bounty", "bounty_max", "max_reward", "max_payout", "maximum_reward", "max_payout_amount", "max_payout_value", "max"]

    bounty_min = None
    bounty_max = None
    for k in min_keys:
        if program.get(k) is not None:
            bounty_min = _parse_number_like(program.get(k))
            break
    for k in max_keys:
        if program.get(k) is not None:
            bounty_max = _parse_number_like(program.get(k))
            break

    if bounty_min is None and isinstance(program.get("min_bounty"), dict):
        bounty_min = _parse_number_like(program.get("min_bounty"))
    if bounty_max is None and isinstance(program.get("max_bounty"), dict):
        bounty_max = _parse_number_like(program.get("max_bounty"))

    try:
        structured = program.get("structured_scopes") or []
        if isinstance(structured, (list, tuple)):
            for s in structured:
                if isinstance(s, dict):
                    if s.get("eligible_for_bounty") is True:
                        if not bounty_min and not bounty_max:
                            return "Yes (range unknown)"
                    if "reward" in s:
                        n = _parse_number_like(s.get("reward"))
                        if n:
                            return f"${n}"
                    if "max_reward" in s:
                        n = _parse_number_like(s.get("max_reward"))
                        if n:
                            bounty_max = bounty_max or n
                    if "min_reward" in s:
                        n = _parse_number_like(s.get("min_reward"))
                        if n:
                            bounty_min = bounty_min or n
    except Exception:
        pass

    try:
        if bounty_min and bounty_max:
            return f"${int(bounty_min)} – ${int(bounty_max)}"
        if bounty_min:
            return f"${int(bounty_min)}"
        if bounty_max:
            return f"up to ${int(bounty_max)}"
    except Exception:
        pass

    potential_fields = ["bounty", "reward", "bounty_range", "reward_range", "offers_bounties", "payout", "max_payout", "min_payout", "max_reward", "min_reward"]
    bounty_str = ""
    for c in potential_fields:
        if program.get(c) is None:
            continue
        v = program.get(c)
        if isinstance(v, bool):
            if v:
                bounty_str = "Yes (range unknown)"
                break
            continue
        if isinstance(v, (int, float)):
            bounty_str = f"${int(v)}"
            break
        if isinstance(v, dict):
            n = _parse_number_like(v)
            if n:
                bounty_str = f"${n}"
                break
            continue
        if isinstance(v, str):
            if re.search(r"\d", v):
                bounty_str = v.strip()
                break

    if bounty_str:
        return str(bounty_str)

    nested_val = _search_for_numeric_in_program(program)
    if nested_val:
        return f"${nested_val}"

    if program.get("offers_bounties") is True or program.get("has_bounty") is True or program.get("offers_awards") is True:
        return "Yes (range unknown)"

    return "—"


def _normalize_tags_list(tags: Any) -> List[str]:
    if isinstance(tags, str):
        return [t.strip().lower() for t in tags.split(",") if t.strip()]
    if isinstance(tags, (list, tuple)):
        return [str(t).lower() for t in tags]
    try:
        return [str(t).lower() for t in tags]
    except Exception:
        return []


def _targets_in_scope_list(p: Dict[str, Any]) -> List[Dict[str, Any]]:
    t = p.get("targets")
    if isinstance(t, dict):
        in_scope = t.get("in_scope") or t.get("inScope") or t.get("in-scope")
        if isinstance(in_scope, (list, tuple)):
            return [it for it in in_scope if isinstance(it, dict)]
        if isinstance(t.get("in_scope"), dict):
            return [t.get("in_scope")]
        flattened: List[Dict[str, Any]] = []
        for v in t.values():
            if isinstance(v, (list, tuple)):
                for it in v:
                    if isinstance(it, dict):
                        flattened.append(it)
        if flattened:
            return flattened
        return []
    if isinstance(p.get("in_scope"), (list, tuple)):
        return [it for it in p.get("in_scope") if isinstance(it, dict)]
    return []


def is_vdp(p: Dict[str, Any]) -> bool:
    tags = _normalize_tags_list(p.get("tags") or p.get("categories") or [])
    policy = str(p.get("policy") or p.get("program_type") or p.get("disclosure_policy") or "").lower()
    platform_field = str(p.get("platform") or p.get("provider") or "").lower()
    name = str(p.get("name") or "").lower()
    handle = str(p.get("handle") or "").lower()

    if any("vdp" in t or "vulnerability disclosure" in t or "coordinated disclosure" in t or "disclosure" in t for t in tags):
        return True
    if "vdp" in policy or "vulnerability disclosure" in policy or "coordinated disclosure" in policy:
        return True

    if platform_field.startswith("hackerone"):
        if handle.endswith("_vdp") or "_vdp" in handle or " vdp" in name or name.endswith(" vdp") or "vulnerability disclosure" in name:
            return True
        in_scope = _targets_in_scope_list(p)
        if in_scope:
            has_eligible_true = any(it.get("eligible_for_bounty") is True for it in in_scope)
            has_eligible_false = any(it.get("eligible_for_bounty") is False for it in in_scope)
            if has_eligible_false and not has_eligible_true:
                if p.get("offers_bounties") is False or p.get("offers_bounties") is None:
                    return True

    if platform_field.startswith("federacy"):
        if "offers_awards" in p:
            if p.get("offers_awards") is False:
                return True

    if any(x in policy for x in ("disclosure", "vdp", "coordinated")):
        return True

    if " vdp" in name or "(vdp)" in name:
        return True

    return False


def is_rdp(p: Dict[str, Any]) -> bool:
    bounty = get_bounty(p)
    if bounty and bounty != "—":
        if bounty.startswith("Yes") or bounty.startswith("$") or "up to" in bounty or re.search(r"\d", bounty):
            return True

    if p.get("offers_bounties") is True or p.get("has_bounty") is True or p.get("offers_awards") is True:
        return True

    in_scope = _targets_in_scope_list(p)
    for it in in_scope:
        if it.get("eligible_for_bounty") is True:
            return True
        if isinstance(it.get("eligible_for_bounty"), str) and it.get("eligible_for_bounty").lower() == "true":
            return True

    for k in ("max_payout", "max_bounty", "max_reward", "max"):
        if _parse_number_like(p.get(k)):
            return True
    for k in ("min_payout", "min_bounty", "min_reward", "min"):
        if _parse_number_like(p.get(k)):
            return True

    tags = _normalize_tags_list(p.get("tags") or p.get("categories") or [])
    if any("bounty" in t or "reward" in t for t in tags):
        return True

    platform_field = str(p.get("platform") or p.get("provider") or "").lower()
    if platform_field.startswith("federacy"):
        if p.get("offers_awards") is True:
            return True
        if p.get("offers_awards") is None and p.get("offers") is True:
            return True

    return False


# ---------------- Notifications ----------------

def escape_html(s: Any) -> str:
    return html.escape(str(s))


def pretty_bool_str(v: bool) -> str:
    return "✅ YES" if v else "❌ NO"


# Scope summarization helpers
_DOMAIN_RE = re.compile(
    r"(?:(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})", re.IGNORECASE
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_WILDCARD_INDICATOR = re.compile(r"(^|\W)\*(?:\.|-)?[A-Za-z0-9_\-]*", re.IGNORECASE)


def _extract_text_from_item(it: Any) -> str:
    if isinstance(it, str):
        return it.strip()
    if isinstance(it, dict):
        for key in ("target", "endpoint", "uri", "asset_identifier", "value", "url", "name", "description", "asset"):
            if key in it and it.get(key):
                try:
                    return str(it.get(key)).strip()
                except Exception:
                    continue
        try:
            parts = []
            for k in sorted(it.keys()):
                v = it.get(k)
                if v:
                    parts.append(str(v))
            return " ".join(parts)
        except Exception:
            try:
                return str(it)
            except Exception:
                return ""
    try:
        return str(it)
    except Exception:
        return ""


def summarize_scope(scope_raw: Any) -> Dict[str, int]:
    counts: Dict[str, int] = {
        "wildcard": 0,
        "domain": 0,
        "subdomain": 0,
        "path": 0,
        "ip": 0,
        "source_code": 0,
        "other": 0,
    }

    def process_item(it: Any) -> None:
        s = _extract_text_from_item(it)
        if not s:
            counts["other"] += 1
            return

        s_clean = s.strip()
        if _IP_RE.search(s_clean):
            counts["ip"] += 1
            return

        low = s_clean.lower()
        if any(sub in low for sub in ("github.com", "gitlab.com", "bitbucket.org", "sourceforge", "/blob/", "/tree/", "/raw/")) or re.search(r"\.(zip|tar\.gz|tgz|tar)$", low):
            counts["source_code"] += 1
            return

        if "*" in s_clean or _WILDCARD_INDICATOR.search(s_clean):
            if _DOMAIN_RE.search(s_clean):
                counts["wildcard"] += 1
                return
            counts["wildcard"] += 1
            return

        if isinstance(it, dict) and any(k for k in ("type", "asset_type", "kind") if it.get(k) and "wild" in str(it.get(k)).lower()):
            counts["wildcard"] += 1
            return

        if low.startswith(("http://", "https://")):
            try:
                path_part = re.sub(r"^https?://", "", s_clean, flags=re.IGNORECASE)
                if "/" in path_part:
                    domain_part, rest = path_part.split("/", 1)
                    if _DOMAIN_RE.search(domain_part):
                        counts["path"] += 1
                        return
                if _DOMAIN_RE.search(path_part):
                    dom = _DOMAIN_RE.search(path_part).group(0)
                    if dom.count(".") >= 2 or path_part.startswith("*.") or path_part.startswith("www."):
                        counts["subdomain"] += 1
                        return
                    counts["domain"] += 1
                    return
            except Exception:
                pass

        domain_match = _DOMAIN_RE.search(s_clean)
        if domain_match and len(s_clean.split()) == 1:
            dom = domain_match.group(0)
            if s_clean.startswith("*."):
                counts["wildcard"] += 1
                return
            if dom.count(".") >= 2 and not s_clean.startswith("www."):
                counts["subdomain"] += 1
                return
            counts["domain"] += 1
            return

        if "/" in s_clean and _DOMAIN_RE.search(s_clean):
            counts["path"] += 1
            return

        if "." in s_clean and len(s_clean) < 100 and _DOMAIN_RE.search(s_clean):
            counts["domain"] += 1
            return

        if len(s_clean) > 120 or " " in s_clean:
            counts["other"] += 1
            return

        if _DOMAIN_RE.search(s_clean):
            counts["domain"] += 1
            return

        counts["other"] += 1

    if not scope_raw:
        return counts

    if isinstance(scope_raw, dict):
        if "in_scope" in scope_raw and isinstance(scope_raw["in_scope"], (list, tuple)):
            for it in scope_raw["in_scope"]:
                process_item(it)
            return counts
        for k, v in scope_raw.items():
            if isinstance(v, (list, tuple)):
                for it in v:
                    process_item(it)
            else:
                process_item(v)
        return counts

    if isinstance(scope_raw, (list, tuple)):
        for it in scope_raw:
            process_item(it)
        return counts

    process_item(scope_raw)
    return counts


def build_project_block(p: Dict[str, Any]) -> str:
    """
    Return an HTML-formatted block for one project.

    IMPORTANT: Prefer already-computed summary fields (vdp, rdp, bounty) when present.
    If not present, fall back to running heuristics on raw JSON stored in "_raw".
    """
    name = escape_html(p.get("name") or "(no name)")
    url = p.get("url") or ""
    platform = escape_html(p.get("platform") or "unknown")

    # prefer precomputed flags from summary if available
    # raw_data used as fallback for heuristic functions
    raw_data = p.get("_raw") or p

    # VDP: prefer summary value (bool) if present
    if "vdp" in p:
        vdp_bool = bool(p.get("vdp"))
    else:
        vdp_bool = is_vdp(raw_data)

    # RDP: prefer summary value if present, else heuristic; note: caller may have enforced "if not vdp => rdp"
    if "rdp" in p:
        rdp_bool = bool(p.get("rdp"))
    else:
        rdp_bool = is_rdp(raw_data)

    # Bounty: prefer summary "bounty" if present (already formatted), else compute from raw
    if "bounty" in p and p.get("bounty") is not None:
        bounty = p.get("bounty")
    else:
        bounty = get_bounty(raw_data) or "—"

    # special header handling for scope-added change_type
    change_type = p.get("change_type")
    if change_type == "scope_added":
        added_n = p.get("scope_added_count", 0)
        header = f"🔁 <b>New Scope Added</b> — 🎯 <b>{name}</b>"
    else:
        header = f"🎯 <b>{name}</b>"
    if url:
        header = header.replace(f"<b>{name}</b>", f"<b><a href=\"{escape_html(url)}\">{name}</a></b>")

    lines = [header]
    lines.append(f"🔗 <b>Platform:</b> {platform}")
    lines.append(f"💰 <b>Bounty:</b> {escape_html(bounty) if bounty and bounty != '—' else '—'}")
    lines.append(f"🛡️ <b>VDP:</b> {pretty_bool_str(vdp_bool)}")
    lines.append(f"🔐 <b>RDP:</b> {pretty_bool_str(rdp_bool)}")

    # if scope_added, show a line summarizing how many items were added
    if change_type == "scope_added":
        added_n = p.get("scope_added_count", 0)
        added_preview = ""
        items = p.get("scope_added_items") or []
        if items:
            # show up to 3 items as preview
            preview_items = items[:3]
            added_preview = " — " + ", ".join(escape_html(x) for x in preview_items) + (", …" if len(items) > 3 else "")
        lines.append(f"🔁 <b>Change:</b> New scope items: {added_n}{added_preview}")

    # Scope summarization (same as before)
    scope_candidate = None
    for key in ("scope", "targets", "in_scope", "inScope", "targets"):
        if p.get(key) is not None:
            scope_candidate = p.get(key)
            break
    if not scope_candidate and isinstance(p.get("targets"), dict):
        t = p["targets"]
        if isinstance(t.get("in_scope"), (list, tuple)):
            scope_candidate = t.get("in_scope")
        elif isinstance(t.get("inScope"), (list, tuple)):
            scope_candidate = t.get("inScope")
        else:
            scope_candidate = p.get("targets")

    if isinstance(scope_candidate, dict) and ("in_scope" in scope_candidate or "inScope" in scope_candidate):
        candidate = scope_candidate.get("in_scope") or scope_candidate.get("inScope") or []
        scope_counts = summarize_scope(candidate)
    else:
        scope_counts = summarize_scope(scope_candidate)

    scope_parts = [f"{k} {v}" for k, v in scope_counts.items() if v]
    scope_summary = ", ".join(scope_parts) if scope_parts else "—"
    lines.append(f"📂 <b>Scope:</b> {scope_summary}")

    block = "\n".join(lines)
    block += "\n" + "<code>━━━━━━━━━━━━━━━━━━━━━━</code>"
    return block


def build_platform_count_message(new_programs: List[Dict[str, Any]]) -> str:
    if not new_programs:
        return "No new programs detected."

    # Count separately new programs vs scope additions
    plat_new_counts: Dict[str, int] = {}
    plat_scope_counts: Dict[str, int] = {}
    for p in new_programs:
        plat = p.get("platform") or p.get("provider") or "Unknown"
        if p.get("change_type") == "scope_added":
            plat_scope_counts[plat] = plat_scope_counts.get(plat, 0) + 1
        else:
            plat_new_counts[plat] = plat_new_counts.get(plat, 0) + 1

    emoji_map = {
        "HackerOne": "🕷",
        "Bugcrowd": "🐞",
        "Intigriti": "🪲",
        "YesWeHack": "🪳",
        "Federacy": "🐝",
    }

    lines: List[str] = []
    # If there are new programs, show that header
    if any(plat_new_counts.values()):
        lines.append(f"⚡ <b>New Program Detected</b> ⚡\n")
        for plat, cnt in sorted(plat_new_counts.items(), key=lambda x: (-x[1], x[0])):
            em = emoji_map.get(plat, "▫️")
            lines.append(f"{em} <b>{escape_html(plat)}:</b> {cnt}")
        lines.append("")  # separation

    # If there are scope additions, show separate header
    if any(plat_scope_counts.values()):
        lines.append(f"🔁 <b>New Scope Added</b> (existing programs updated)\n")
        for plat, cnt in sorted(plat_scope_counts.items(), key=lambda x: (-x[1], x[0])):
            em = emoji_map.get(plat, "▫️")
            lines.append(f"{em} <b>{escape_html(plat)}:</b> {cnt}")

    return "\n".join(lines)


def build_telegram_messages(new_programs: List[Dict[str, Any]], per_message: int = PROJECTS_PER_MESSAGE) -> List[str]:
    if not new_programs:
        return ["No new programs detected."]

    header = f""
    continuation_header = f""

    blocks = [build_project_block(p) for p in new_programs]

    messages: List[str] = []
    for i in range(0, len(blocks), per_message):
        chunk_blocks = blocks[i:i+per_message]
        prefix = header if i == 0 else continuation_header
        msg = prefix + "\n\n".join(chunk_blocks)
        if len(msg) > TELEGRAM_MAX_LEN:
            while chunk_blocks and len(prefix + "\n\n".join(chunk_blocks)) > TELEGRAM_MAX_LEN:
                chunk_blocks.pop()
            msg = prefix + "\n\n".join(chunk_blocks) if chunk_blocks else (prefix + "<em>content truncated</em>")
        messages.append(msg)
    return messages


def send_telegram_with_backoff(text: str, token: Optional[str] = None, chat_id: Optional[str] = None,
                               thread_id: Optional[int] = None, max_attempts: int = 6) -> bool:
    token = token or TELEGRAM_TOKEN
    chat_id = chat_id or TELEGRAM_CHAT_ID
    thread = thread_id if thread_id is not None else TELEGRAM_THREAD_ID

    if not token or not chat_id:
        logger.info("Telegram not configured. Skipping.")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload: Dict[str, Any] = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if thread is not None:
        try:
            payload["message_thread_id"] = int(thread)
        except Exception:
            logger.debug("Invalid thread id, skipping")

    attempt = 0
    backoff = 1
    while attempt < max_attempts:
        attempt += 1
        try:
            r = requests.post(url, json=payload, timeout=TIMEOUT)
            if r.status_code == 200:
                logger.info("Sent Telegram message (len=%d)", len(text))
                return True
            if r.status_code == 429:
                retry_after = None
                try:
                    retry_after = int(r.headers.get("Retry-After")) if r.headers.get("Retry-After") else None
                except Exception:
                    retry_after = None
                wait = retry_after if retry_after is not None else backoff
                logger.warning("Telegram returned 429; sleeping %ds before retry (attempt %d/%d)", wait, attempt, max_attempts)
                time.sleep(wait)
                backoff *= 2
                continue
            logger.error("Telegram send failed with status %d: %s", r.status_code, r.text[:200])
            return False
        except requests.RequestException:
            logger.exception("Exception while sending Telegram message; backing off %ds", backoff)
            time.sleep(backoff)
            backoff *= 2
    logger.error("Exceeded max attempts sending Telegram message")
    return False


def send_messages_with_rate_limit(messages: List[str], platform_count_message: Optional[str] = None,
                                  pause: float = SEND_PAUSE_SECONDS) -> bool:
    ok = True
    if platform_count_message:
        logger.debug("Sending platform count message")
        sent = send_telegram_with_backoff(platform_count_message, token=None, chat_id=None, thread_id=TELEGRAM_THREAD_ID)
        if not sent:
            logger.warning("Failed to send platform count message")
            ok = False
        time.sleep(pause)

    for i, m in enumerate(messages, 1):
        logger.debug("Sending message %d/%d (approx len=%d)", i, len(messages), len(m))
        sent = send_telegram_with_backoff(m, token=None, chat_id=None, thread_id=TELEGRAM_THREAD_ID)
        if not sent:
            logger.warning("Failed to send message %d/%d", i, len(messages))
            ok = False
        time.sleep(pause)
    return ok


def send_discord_message(webhook: str, content: str) -> bool:
    try:
        payload = {"content": content}
        r = requests.post(webhook, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        logger.info("Sent Discord webhook")
        return True
    except Exception:
        logger.exception("Failed to send Discord webhook")
        return False


# ---------------- Core fetch/merge logic ----------------

def fetch_all_programs() -> List[Dict[str, Any]]:
    session = requests.Session()
    all_programs: List[Dict[str, Any]] = []

    for plat, url in PLATFORM_FILES.items():
        logger.debug("Fetching source for %s: %s", plat, url)
        if url.endswith('.txt'):
            text = fetch_text(url, session=session)
            if not text:
                logger.info("Skipping text source %s (no content)", url)
                continue
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            for ln in lines:
                entry = {
                    "name": ln,
                    "url": ln if ln.startswith('http') else "",
                    "platform": plat,
                    "tags": [],
                    "types": [],
                }
                all_programs.append(entry)
            logger.info("Parsed %d entries from %s", len(lines), plat)
            continue

        data = fetch_json(url, session=session)
        if data is None:
            logger.info("Source %s not available or non-JSON, skipping: %s", plat, url)
            continue

        entries: List[Any] = []
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            if "programs" in data and isinstance(data["programs"], list):
                entries = data["programs"]
            else:
                entries = [v for v in data.values() if isinstance(v, dict)]

        count = 0
        for item in entries:
            if isinstance(item, dict):
                if not item.get("platform"):
                    item["platform"] = plat
                all_programs.append(item)
                count += 1
        logger.info("Fetched %d entries for %s", count, plat)

    return all_programs


def filter_programs(all_programs: List[Dict[str, Any]], platforms: List[str]) -> List[Dict[str, Any]]:
    wanted = [p.lower() for p in platforms]
    out: List[Dict[str, Any]] = []
    for p in all_programs:
        plat = normalize_platform(p.get("platform") or p.get("provider") or "").lower()
        if plat in wanted:
            out.append(p)
            continue
        tags = p.get("tags") or p.get("categories") or p.get("platform_tags") or []
        if isinstance(tags, str):
            tags = [t.strip().lower() for t in tags.split(",") if t.strip()]
        elif isinstance(tags, (list, tuple)):
            tags = [str(t).lower() for t in tags]
        else:
            try:
                tags = [str(t).lower() for t in tags]
            except Exception:
                tags = []
        if any(t in wanted for t in tags):
            out.append(p)
            continue
    return out


def get_vdp(p: Dict[str, Any]) -> bool:
    return is_vdp(p)


def get_rdp(p: Dict[str, Any]) -> bool:
    return is_rdp(p)


def extract_program_summary(prog: Dict[str, Any]) -> Dict[str, Any]:
    name = prog.get("name") or prog.get("title") or prog.get("program_name") or "<unknown>"
    url = prog.get("url") or prog.get("program_url") or prog.get("link") or ""
    platform = prog.get("platform") or prog.get("provider") or ""

    tags = prog.get("tags") or prog.get("categories") or prog.get("platform_tags") or []
    if isinstance(tags, str):
        tags_list = [t.strip() for t in tags.split(",") if t.strip()]
    elif isinstance(tags, (list, tuple)):
        tags_list = [str(t) for t in tags]
    else:
        try:
            tags_list = [str(t) for t in tags]
        except Exception:
            tags_list = []

    types = prog.get("types") or prog.get("program_type") or []
    if isinstance(types, str):
        types_list = [t.strip() for t in types.split(",") if t.strip()]
    elif isinstance(types, (list, tuple)):
        types_list = [str(t).strip() for t in types if t]
    else:
        try:
            types_list = [str(types)]
        except Exception:
            types_list = []

    policy = prog.get("policy") or prog.get("program_type") or None

    scope_candidate = None
    for key in ("scope", "targets", "in_scope", "inScope", "targets"):
        if prog.get(key) is not None:
            scope_candidate = prog.get(key)
            break

    if not scope_candidate and isinstance(prog.get("targets"), dict):
        t = prog["targets"]
        if isinstance(t.get("in_scope"), (list, tuple)):
            scope_candidate = t.get("in_scope")
        elif isinstance(t.get("inScope"), (list, tuple)):
            scope_candidate = t.get("inScope")
        else:
            scope_candidate = prog.get("targets")

    if scope_candidate is None and isinstance(prog, dict):
        for k in ("targets", "scope", "in_scope", "structured_scopes"):
            v = prog.get(k)
            if isinstance(v, (list, tuple)):
                scope_candidate = v
                break
            if isinstance(v, dict) and ("in_scope" in v):
                scope_candidate = v.get("in_scope")
                break

    summary = {
        "name": name,
        "url": url,
        "platform": platform,
        "scope": scope_candidate or prog.get("targets") or prog.get("in_scope"),
        "tags": tags_list,
        "policy": policy,
        "types": types_list,
        "bounty": get_bounty(prog),
    }

    # determine vdp/rdp (prefer heuristics against raw prog)
    summary["vdp"] = get_vdp(prog)
    summary["rdp"] = get_rdp(prog)

    # enforce user's requested rule: if NOT VDP then RDP True
    summary["rdp"] = bool(summary["rdp"]) or (not bool(summary["vdp"]))

    # keep raw program for build_project_block fallback
    summary["_raw"] = prog
    return summary


# -------------- New helpers to detect scope diffs ----------------

def _get_scope_candidate_from_prog(prog: Dict[str, Any]) -> Any:
    # same logic as used elsewhere to pick scope candidate
    for key in ("scope", "targets", "in_scope", "inScope", "targets"):
        if prog.get(key) is not None:
            return prog.get(key)
    if isinstance(prog.get("targets"), dict):
        t = prog["targets"]
        if isinstance(t.get("in_scope"), (list, tuple)):
            return t.get("in_scope")
        if isinstance(t.get("inScope"), (list, tuple)):
            return t.get("inScope")
        return prog.get("targets")
    for k in ("targets", "scope", "in_scope", "structured_scopes"):
        v = prog.get(k)
        if isinstance(v, (list, tuple)):
            return v
        if isinstance(v, dict) and ("in_scope" in v):
            return v.get("in_scope")
    return None


def _scope_items_set_from_candidate(scope_candidate: Any) -> Set[str]:
    items: Set[str] = set()
    if scope_candidate is None:
        return items
    if isinstance(scope_candidate, dict):
        # try common keys
        if "in_scope" in scope_candidate and isinstance(scope_candidate["in_scope"], (list, tuple)):
            for it in scope_candidate["in_scope"]:
                s = _extract_text_from_item(it)
                if s:
                    items.add(s.strip().lower())
            return items
        for k, v in scope_candidate.items():
            if isinstance(v, (list, tuple)):
                for it in v:
                    s = _extract_text_from_item(it)
                    if s:
                        items.add(s.strip().lower())
            else:
                s = _extract_text_from_item(v)
                if s:
                    items.add(s.strip().lower())
        return items
    if isinstance(scope_candidate, (list, tuple)):
        for it in scope_candidate:
            s = _extract_text_from_item(it)
            if s:
                items.add(s.strip().lower())
        return items
    # fallback: single item
    s = _extract_text_from_item(scope_candidate)
    if s:
        items.add(s.strip().lower())
    return items


# ---------------- detect new programs + scope changes ----------------

def detect_new_programs(latest: List[Dict[str, Any]], prev_snapshot: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    latest_map: Dict[str, Dict[str, Any]] = {}
    for p in latest:
        key = program_unique_key(p)
        latest_map[key] = p

    prev_map = prev_snapshot.get("programs", {}) if prev_snapshot else {}

    new_keys = set(latest_map.keys()) - set(prev_map.keys())
    common_keys = set(latest_map.keys()) & set(prev_map.keys())

    new_programs: List[Dict[str, Any]] = []
    # first, add truly new programs (keys not previously present)
    for k in sorted(new_keys):
        new_programs.append(extract_program_summary(latest_map[k]))

    # next, detect scope additions for programs that existed before but gained new scope items
    for k in sorted(common_keys):
        prev_prog = prev_map.get(k) or {}
        latest_prog = latest_map.get(k) or {}
        prev_scope_candidate = _get_scope_candidate_from_prog(prev_prog)
        latest_scope_candidate = _get_scope_candidate_from_prog(latest_prog)
        prev_set = _scope_items_set_from_candidate(prev_scope_candidate)
        latest_set = _scope_items_set_from_candidate(latest_scope_candidate)
        # if latest has at least one item that prev didn't -> consider scope_added
        added_items = sorted(list(latest_set - prev_set))
        if added_items:
            summary = extract_program_summary(latest_prog)
            summary["change_type"] = "scope_added"
            summary["scope_added_count"] = len(added_items)
            summary["scope_added_items"] = added_items
            new_programs.append(summary)

    snapshot = {"fetched_at": int(time.time()), "programs": latest_map}
    return new_programs, snapshot


# ---------------- Single run + loop ----------------

def run_once(dry_run: bool = False, just_hackerone: bool = False) -> Tuple[bool, bool]:
    try:
        ensure_data_dir()
        prev = load_prev()

        logger.info("Fetching programs from configured sources...")
        all_programs = fetch_all_programs()
        logger.info("Total programs fetched: %d", len(all_programs))

        platforms = DEFAULT_PLATFORMS.copy()
        if just_hackerone:
            platforms = ["HackerOne"]
            logger.info("Running in --just-hackerone mode (only HackerOne programs will be considered)")

        filtered = filter_programs(all_programs, platforms)
        logger.info("Programs after filtering: %d", len(filtered))

        new_programs, snapshot = detect_new_programs(filtered, prev)
        if not new_programs:
            logger.info("No new programs detected.")
            save_prev(snapshot)
            return True, True

        platform_count_msg = build_platform_count_message(new_programs)
        program_messages = build_telegram_messages(new_programs, per_message=PROJECTS_PER_MESSAGE)

        if dry_run:
            print("--- PLATFORM COUNT MESSAGE ---")
            print(platform_count_msg)
            print()
            for i, m in enumerate(program_messages, 1):
                print(f"--- MESSAGE PART {i}/{len(program_messages)} ---")
                print(m)
                print()
            logger.info("Dry-run: notification not sent")
            save_prev(snapshot)
            return True, True

        ok = send_messages_with_rate_limit(program_messages, platform_count_message=platform_count_msg, pause=SEND_PAUSE_SECONDS)

        discord_ok = True
        webhook = os.getenv("DISCORD_WEBHOOK_URL")
        if webhook:
            try:
                discord_ok = send_discord_message(webhook, program_messages[0] if program_messages else "New programs detected")
            except Exception:
                discord_ok = False

        if not ok:
            logger.warning("Telegram delivery had errors; saving snapshot anyway to avoid duplicate alerts")
        else:
            logger.info("Notifications delivered")

        save_prev(snapshot)
        return ok, discord_ok

    except Exception:
        logger.exception("run_once failed")
        return False, False


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Rinnegan — bounty watcher")
    parser.add_argument("--dry-run", action="store_true", help="Print messages instead of sending")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--just-hackerone", action="store_true", help="Only include HackerOne programs (debug)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # ---- RUN ONCE AND EXIT ----
    ok, discord_ok = run_once(dry_run=args.dry_run, just_hackerone=args.just_hackerone)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
