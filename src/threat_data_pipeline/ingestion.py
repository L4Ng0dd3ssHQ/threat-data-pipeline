from __future__ import annotations

import csv
import io
import logging
from pathlib import Path

import pandas as pd
import requests

from .config import Settings
from .models import IngestionArtifact
from .utils import csv_buffer_to_dataframe, detect_encoding


LOGGER = logging.getLogger(__name__)


class IngestionError(Exception):
    """Raised when ingestion fails."""


def _validate_csv_file(path: Path, settings: Settings) -> None:
    if not path.exists():
        raise IngestionError(f"Input file does not exist: {path}")
    if path.suffix.lower() != ".csv":
        raise IngestionError(f"Unsupported file type for {path.name}. Only CSV is accepted.")
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    size = path.stat().st_size
    if size > max_bytes:
        raise IngestionError(
            f"File {path.name} is {size / (1024 * 1024):.1f} MB and exceeds "
            f"the configured limit of {settings.max_file_size_mb} MB."
        )


def _read_csv_with_recovery(
    source_name: str,
    raw_bytes: bytes,
    origin: str,
    source_type: str,
    chunk_size: int,
    read_csv_kwargs: dict[str, object] | None = None,
) -> IngestionArtifact:
    encoding = detect_encoding(raw_bytes)
    errors: list[str] = []
    skipped_rows = 0
    read_csv_kwargs = read_csv_kwargs or {}

    def read_chunks(
        selected_encoding: str,
        engine: str = "c",
        extra_kwargs: dict[str, object] | None = None,
    ) -> pd.DataFrame:
        kwargs = {
            "encoding": selected_encoding,
            "chunksize": chunk_size,
            "on_bad_lines": "skip",
            **read_csv_kwargs,
        }
        if extra_kwargs:
            kwargs.update(extra_kwargs)
        if engine != "python":
            kwargs["low_memory"] = False
        chunks = pd.read_csv(
            io.BytesIO(raw_bytes),
            engine=engine,
            **kwargs,
        )
        return pd.concat(chunks, ignore_index=True)

    def read_strict(
        selected_encoding: str,
        engine: str = "c",
        extra_kwargs: dict[str, object] | None = None,
    ) -> pd.DataFrame:
        kwargs = {
            "on_bad_lines": "error",
            **read_csv_kwargs,
        }
        if extra_kwargs:
            kwargs.update(extra_kwargs)
        if engine != "python":
            kwargs["low_memory"] = False
        return csv_buffer_to_dataframe(
            raw_bytes,
            selected_encoding,
            engine=engine,
            **kwargs,
        )

    def recover_with_fallbacks(selected_encoding: str) -> pd.DataFrame:
        try:
            return read_chunks(selected_encoding, engine="c")
        except pd.errors.ParserError:
            errors.append("C parser failed; retried with Python parser for malformed CSV handling.")
        except csv.Error:
            errors.append("C parser failed on malformed quoting; retried with Python parser.")

        try:
            return read_chunks(selected_encoding, engine="python")
        except (pd.errors.ParserError, csv.Error):
            errors.append("Python parser failed on malformed quoting; retried with literal-quote mode.")
            return read_chunks(
                selected_encoding,
                engine="python",
                extra_kwargs={"quoting": csv.QUOTE_NONE},
            )

    try:
        dataframe = recover_with_fallbacks(encoding)
    except pd.errors.EmptyDataError:
        dataframe = pd.DataFrame()
        errors.append("Dataset is empty.")
    except UnicodeDecodeError as exc:
        if encoding.lower() != "latin-1":
            encoding = "latin-1"
            errors.append("UTF-8 decoding failed; retried with latin-1.")
            dataframe = recover_with_fallbacks(encoding)
        else:
            raise IngestionError(f"Encoding error while reading {source_name}: {exc}") from exc
    except csv.Error as exc:
        raise IngestionError(
            f"Malformed CSV for {source_name}: {exc}. "
            "The feed appears to contain unrecoverable quote corruption."
        ) from exc
    except Exception as exc:  # pragma: no cover
        raise IngestionError(f"Failed to ingest {source_name}: {exc}") from exc

    try:
        try:
            strict_df = read_strict(encoding, engine="c")
        except (pd.errors.ParserError, csv.Error):
            try:
                strict_df = read_strict(encoding, engine="python")
            except (pd.errors.ParserError, csv.Error):
                strict_df = read_strict(
                    encoding,
                    engine="python",
                    extra_kwargs={"quoting": csv.QUOTE_NONE},
                )
        skipped_rows = max(len(strict_df) - len(dataframe), 0)
    except Exception:
        errors.append("Malformed rows were skipped during parsing.")

    if dataframe.empty:
        errors.append("No records were loaded from the dataset.")

    LOGGER.info("Ingested %s rows from %s", len(dataframe), source_name)
    return IngestionArtifact(
        source_name=source_name,
        dataframe=dataframe,
        source_type=source_type,
        origin=origin,
        encoding=encoding,
        skipped_rows=skipped_rows,
        errors=errors,
    )


def ingest_local_csv(path: str | Path, settings: Settings, source_name: str | None = None) -> IngestionArtifact:
    file_path = Path(path)
    _validate_csv_file(file_path, settings)
    raw_bytes = file_path.read_bytes()
    return _read_csv_with_recovery(
        source_name=source_name or file_path.stem,
        raw_bytes=raw_bytes,
        origin=str(file_path.resolve()),
        source_type="file",
        chunk_size=settings.chunk_size,
    )


def _download_csv(url: str, params: dict[str, str] | None = None) -> bytes:
    response = requests.get(url, params=params, timeout=60)
    response.raise_for_status()
    return response.content


def ingest_urlhaus(settings: Settings) -> IngestionArtifact:
    if not settings.urlhaus_api_key:
        raise IngestionError(
            "URLHAUS_API_KEY is not set. Add it to .env before pulling URLHaus data."
        )
    raw_bytes = _download_csv(
        settings.urlhaus_feed_url,
        params={"auth-key": settings.urlhaus_api_key},
    )
    return _read_csv_with_recovery(
        source_name="urlhaus",
        raw_bytes=raw_bytes,
        origin=settings.urlhaus_feed_url,
        source_type="api",
        chunk_size=settings.chunk_size,
        read_csv_kwargs={"comment": "#"},
    )


def ingest_cisa_kev(settings: Settings) -> IngestionArtifact:
    raw_bytes = _download_csv(settings.cisa_kev_url)
    return _read_csv_with_recovery(
        source_name="cisa_kev",
        raw_bytes=raw_bytes,
        origin=settings.cisa_kev_url,
        source_type="url",
        chunk_size=settings.chunk_size,
    )

def ingest_threatfox(settings: Settings) -> IngestionArtifact:
    if not settings.threatfox_api_key:
        raise IngestionError(
            "THREATFOX_API_KEY is not set. Add it to .env before pulling ThreatFox data."
        )
    response = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "get_iocs", "days": 1},
        headers={"API-KEY": settings.threatfox_api_key},
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()
    records = data.get("data", [])
    dataframe = pd.DataFrame(records) if records else pd.DataFrame()
    LOGGER.info("Ingested %s rows from threatfox", len(dataframe))
    return IngestionArtifact(
        source_name="threatfox",
        dataframe=dataframe,
        source_type="api",
        origin="https://threatfox-api.abuse.ch/api/v1/",
        encoding="utf-8",
        skipped_rows=0,
        errors=[],
    )


def ingest_alienvault(settings: Settings) -> IngestionArtifact:
    if not settings.alienvault_api_key:
        raise IngestionError(
            "ALIENVAULT_API_KEY is not set. Add it to .env before pulling AlienVault OTX data."
        )
    response = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={"X-OTX-API-KEY": settings.alienvault_api_key},
        params={"limit": 20},
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()
    records = data.get("results", [])
    dataframe = pd.DataFrame(records) if records else pd.DataFrame()
    LOGGER.info("Ingested %s rows from alienvault", len(dataframe))
    return IngestionArtifact(
        source_name="alienvault",
        dataframe=dataframe,
        source_type="api",
        origin="https://otx.alienvault.com/api/v1/pulses/subscribed",
        encoding="utf-8",
        skipped_rows=0,
        errors=[],
    )

def ingest_feodo_tracker(settings: Settings) -> IngestionArtifact:
    raw_bytes = _download_csv(settings.feodo_tracker_url)
    return _read_csv_with_recovery(
        source_name="feodo_tracker",
        raw_bytes=raw_bytes,
        origin=settings.feodo_tracker_url,
        source_type="url",
        chunk_size=settings.chunk_size,
        read_csv_kwargs={"comment": "#"},
    )

def merge_artifacts(artifacts: list[IngestionArtifact]) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for artifact in artifacts:
        frame = artifact.dataframe.copy()
        frame["source_name"] = artifact.source_name
        frame["source_type"] = artifact.source_type
        frame["source_origin"] = artifact.origin
        frames.append(frame)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True, sort=False)
