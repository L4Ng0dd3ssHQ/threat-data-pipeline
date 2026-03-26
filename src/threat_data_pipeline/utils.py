from __future__ import annotations

import io
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import pandas as pd


URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def detect_encoding(raw_bytes: bytes) -> str:
    if not raw_bytes:
        return "utf-8"
    try:
        raw_bytes.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "latin-1"


def normalize_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        return value
    parsed = urlparse(value.strip())
    if not parsed.scheme:
        parsed = urlparse(f"http://{value.strip()}")
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        fragment="",
    )
    path = normalized.path or "/"
    normalized = normalized._replace(path=path.rstrip("/") or "/")
    return urlunparse(normalized)


def looks_like_url(series: pd.Series) -> bool:
    non_null = series.dropna().astype(str)
    if non_null.empty:
        return False
    sample = non_null.head(50)
    return (sample.str.match(URL_RE)).mean() >= 0.6


def read_head_bytes(path: Path, size: int = 32_768) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def dataframe_to_records(df: pd.DataFrame, max_rows: int = 100) -> list[dict[str, object]]:
    if df.empty:
        return []
    return df.head(max_rows).where(pd.notnull(df), None).to_dict(orient="records")


def csv_buffer_to_dataframe(buffer: bytes, encoding: str, **kwargs: object) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(buffer), encoding=encoding, **kwargs)
