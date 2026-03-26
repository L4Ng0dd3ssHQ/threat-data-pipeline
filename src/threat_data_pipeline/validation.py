from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from .models import QualityReport
from .utils import looks_like_url


def infer_schema(df: pd.DataFrame) -> dict[str, str]:
    schema: dict[str, str] = {}
    for column in df.columns:
        series = df[column]
        non_null = series.dropna()
        if non_null.empty:
            schema[column] = "unknown"
            continue
        numeric = pd.to_numeric(non_null, errors="coerce")
        if numeric.notna().mean() >= 0.9:
            schema[column] = "numeric"
            continue
        if looks_like_url(series):
            schema[column] = "url"
            continue
        sample = non_null.astype(str).head(100)
        likely_date = sample.str.contains(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}", regex=True).mean()
        if likely_date >= 0.5:
            parsed_dates = pd.to_datetime(non_null, errors="coerce", utc=True)
            if parsed_dates.notna().mean() >= 0.8:
                schema[column] = "date"
                continue
        schema[column] = "categorical"
    return schema


def detect_outliers(df: pd.DataFrame, schema: dict[str, str], z_threshold: float = 3.0) -> dict[str, int]:
    outliers: dict[str, int] = {}
    for column, kind in schema.items():
        if kind != "numeric":
            continue
        numeric = pd.to_numeric(df[column], errors="coerce").dropna()
        if len(numeric) < 3 or numeric.std(ddof=0) == 0:
            outliers[column] = 0
            continue
        z_scores = ((numeric - numeric.mean()) / numeric.std(ddof=0)).abs()
        outliers[column] = int((z_scores > z_threshold).sum())
    return outliers


def detect_inconsistencies(df: pd.DataFrame, schema: dict[str, str]) -> dict[str, int]:
    inconsistencies: dict[str, int] = {}
    for column, kind in schema.items():
        series = df[column]
        if kind == "categorical":
            normalized = series.dropna().astype(str).str.strip()
            inconsistencies[column] = int((normalized != normalized.str.lower().str.title()).sum())
        elif kind == "date":
            parsed = pd.to_datetime(series, errors="coerce", utc=True)
            inconsistencies[column] = int(series.notna().sum() - parsed.notna().sum())
        elif kind == "url":
            inconsistencies[column] = int(
                series.dropna().astype(str).str.contains(r"\s", regex=True).sum()
            )
        else:
            inconsistencies[column] = 0
    return inconsistencies


def build_quality_report(df: pd.DataFrame, malformed_rows: int = 0) -> QualityReport:
    schema = infer_schema(df)
    missing_values = {column: int(df[column].isna().sum()) for column in df.columns}
    duplicate_rows = int(df.duplicated().sum()) if not df.empty else 0
    outliers = detect_outliers(df, schema)
    inconsistencies = detect_inconsistencies(df, schema)
    return QualityReport(
        schema=schema,
        total_rows=int(len(df)),
        total_columns=int(len(df.columns)),
        missing_values=missing_values,
        duplicate_rows=duplicate_rows,
        outliers=outliers,
        inconsistent_values=inconsistencies,
        malformed_rows=malformed_rows,
    )


def quality_report_to_frames(report: QualityReport) -> dict[str, pd.DataFrame]:
    return {
        "schema": pd.DataFrame(
            [{"column": key, "inferred_type": value} for key, value in report.schema.items()]
        ),
        "missing_values": pd.DataFrame(
            [{"column": key, "missing_count": value} for key, value in report.missing_values.items()]
        ),
        "outliers": pd.DataFrame(
            [{"column": key, "outlier_count": value} for key, value in report.outliers.items()]
        ),
        "inconsistencies": pd.DataFrame(
            [{"column": key, "inconsistent_count": value} for key, value in report.inconsistent_values.items()]
        ),
        "summary": pd.DataFrame(
            [
                {
                    "total_rows": report.total_rows,
                    "total_columns": report.total_columns,
                    "duplicate_rows": report.duplicate_rows,
                    "malformed_rows": report.malformed_rows,
                }
            ]
        ),
    }


def empty_safe_describe(df: pd.DataFrame) -> dict[str, Any]:
    if df.empty:
        return {"row_count": 0, "column_count": len(df.columns), "message": "Dataset is empty."}
    return df.describe(include="all").replace({np.nan: None}).to_dict()
