from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

try:
    import streamlit as st
except Exception:  # pragma: no cover - optional outside dashboard runtime
    st = None


DEFAULT_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/data/"
    "known_exploited_vulnerabilities.csv"
)
DEFAULT_URLHAUS_URL = "https://urlhaus-api.abuse.ch/files/exports/recent.csv"
DEFAULT_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


@dataclass(slots=True)
class Settings:
    urlhaus_api_key: str | None
    threatfox_api_key: str | None
    alienvault_api_key: str | None
    urlhaus_feed_url: str = DEFAULT_URLHAUS_URL
    cisa_kev_url: str = DEFAULT_KEV_URL
    feodo_tracker_url: str = DEFAULT_FEODO_URL
    max_file_size_mb: int = 512
    chunk_size: int = 100_000
    output_dir: Path = Path("output")


def _get_streamlit_secret(name: str) -> str | None:
    if st is None:
        return None
    try:
        secrets = st.secrets
    except Exception:
        return None

    try:
        value = secrets.get(name)
    except Exception:
        value = None
    if value not in (None, ""):
        return str(value)

    try:
        env_section = secrets.get("env", {})
    except Exception:
        env_section = {}

    try:
        value = env_section.get(name)
    except Exception:
        value = None
    return str(value) if value not in (None, "") else None


def _get_setting(name: str, default: str | None = None) -> str | None:
    return os.getenv(name) or _get_streamlit_secret(name) or default


def _get_int_setting(name: str, default: int) -> int:
    value = _get_setting(name)
    return int(value) if value is not None else default


def load_settings() -> Settings:
    load_dotenv()
    return Settings(
        urlhaus_api_key=_get_setting("URLHAUS_API_KEY"),
        threatfox_api_key=_get_setting("THREATFOX_API_KEY"),
        alienvault_api_key=_get_setting("ALIENVAULT_API_KEY"),
        urlhaus_feed_url=_get_setting("URLHAUS_FEED_URL", DEFAULT_URLHAUS_URL) or DEFAULT_URLHAUS_URL,
        cisa_kev_url=_get_setting("CISA_KEV_URL", DEFAULT_KEV_URL) or DEFAULT_KEV_URL,
        feodo_tracker_url=_get_setting("FEODO_TRACKER_URL", DEFAULT_FEODO_URL) or DEFAULT_FEODO_URL,
        max_file_size_mb=_get_int_setting("MAX_FILE_SIZE_MB", 512),
        chunk_size=_get_int_setting("CSV_CHUNK_SIZE", 100_000),
        output_dir=Path(_get_setting("OUTPUT_DIR", "output") or "output"),
    )
