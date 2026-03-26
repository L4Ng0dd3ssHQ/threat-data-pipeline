from __future__ import annotations

import pandas as pd

from threat_data_pipeline.ingestion import _read_csv_with_recovery
from threat_data_pipeline.cleaning import CleaningConfig, clean_dataframe
from threat_data_pipeline.utils import detect_encoding
from threat_data_pipeline.validation import detect_outliers, infer_schema


def test_infer_schema_detects_numeric_date_and_url() -> None:
    df = pd.DataFrame(
        {
            "score": [1, 2, 3],
            "reported": ["2025-01-01", "2025-01-02", "2025-01-03"],
            "ioc_url": ["https://a.test", "https://b.test", "https://c.test"],
            "tag": ["phishing", "malware", "phishing"],
        }
    )
    schema = infer_schema(df)
    assert schema["score"] == "numeric"
    assert schema["reported"] == "date"
    assert schema["ioc_url"] == "url"
    assert schema["tag"] == "categorical"


def test_clean_dataframe_handles_missing_values() -> None:
    df = pd.DataFrame(
        {
            "score": [1.0, None, 3.0],
            "tag": ["phishing", None, "malware"],
        }
    )
    schema = {"score": "numeric", "tag": "categorical"}
    cleaned, transformations = clean_dataframe(
        df,
        schema,
        CleaningConfig(numeric_strategy="median", categorical_strategy="unknown"),
    )
    assert cleaned["score"].isna().sum() == 0
    assert cleaned["tag"].isna().sum() == 0
    assert any("filled numeric nulls" in item for item in transformations)


def test_detect_outliers_flags_extreme_value() -> None:
    df = pd.DataFrame({"score": [10, 11, 12, 13, 1000]})
    schema = {"score": "numeric"}
    outliers = detect_outliers(df, schema, z_threshold=1.5)
    assert outliers["score"] == 1


def test_detect_encoding_falls_back_to_latin_1() -> None:
    raw = "url,tag\nhttp://example.com,caf\xe9\n".encode("latin-1")
    assert detect_encoding(raw) == "latin-1"


def test_read_csv_with_recovery_accepts_latin_1_bytes() -> None:
    raw = "url,tag\nhttp://example.com,caf\xe9\n".encode("latin-1")
    artifact = _read_csv_with_recovery(
        source_name="urlhaus",
        raw_bytes=raw,
        origin="memory",
        source_type="api",
        chunk_size=1000,
    )
    assert artifact.encoding == "latin-1"
    assert artifact.dataframe.loc[0, "tag"] == "caf\xe9"


def test_read_csv_with_recovery_handles_broken_quotes_with_comment_lines() -> None:
    raw = (
        b"# comment line\n"
        b"url,tag\n"
        b"http://example.com,phishing\n"
        b"\"broken line\n"
        b"http://second.test,malware\n"
    )
    artifact = _read_csv_with_recovery(
        source_name="urlhaus",
        raw_bytes=raw,
        origin="memory",
        source_type="api",
        chunk_size=1000,
        read_csv_kwargs={"comment": "#"},
    )
    assert len(artifact.dataframe) >= 1
    assert "parser" in " ".join(artifact.errors).lower() or "malformed" in " ".join(artifact.errors).lower()
