from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .utils import normalize_url


@dataclass(slots=True)
class CleaningConfig:
    numeric_strategy: str = "median"
    categorical_strategy: str = "mode"
    date_strategy: str = "drop_invalid"
    drop_duplicates: bool = True


def _fill_numeric(series: pd.Series, strategy: str) -> tuple[pd.Series, str]:
    numeric = pd.to_numeric(series, errors="coerce")
    if strategy == "zero":
        return numeric.fillna(0), "filled numeric nulls with zero"
    fill_value = numeric.median()
    return numeric.fillna(fill_value), f"filled numeric nulls with median={fill_value}"


def _fill_categorical(series: pd.Series, strategy: str) -> tuple[pd.Series, str]:
    normalized = series.astype("string").str.strip().str.lower()
    normalized = normalized.str.replace(r"[_-]+", " ", regex=True).str.replace(r"\s+", " ", regex=True)
    normalized = normalized.str.title()
    if strategy == "unknown":
        return normalized.fillna("Unknown"), "filled categorical nulls with 'Unknown'"
    mode = normalized.mode(dropna=True)
    fill_value = mode.iloc[0] if not mode.empty else "Unknown"
    return normalized.fillna(fill_value), f"filled categorical nulls with mode={fill_value}"


def clean_dataframe(
    df: pd.DataFrame,
    schema: dict[str, str],
    config: CleaningConfig | None = None,
) -> tuple[pd.DataFrame, list[str]]:
    config = config or CleaningConfig()
    cleaned = df.copy()
    transformation_log: list[str] = []

    for column, kind in schema.items():
        if kind == "numeric":
            cleaned[column], action = _fill_numeric(cleaned[column], config.numeric_strategy)
            transformation_log.append(f"{column}: {action}")
        elif kind == "categorical":
            cleaned[column], action = _fill_categorical(cleaned[column], config.categorical_strategy)
            transformation_log.append(f"{column}: normalized case and {action}")
        elif kind == "date":
            parsed = pd.to_datetime(cleaned[column], errors="coerce", utc=True)
            invalid_count = int(cleaned[column].notna().sum() - parsed.notna().sum())
            cleaned[column] = parsed.dt.strftime("%Y-%m-%d")
            transformation_log.append(
                f"{column}: standardized dates to YYYY-MM-DD and coerced {invalid_count} invalid values"
            )
        elif kind == "url":
            cleaned[column] = cleaned[column].astype("string").map(normalize_url)
            transformation_log.append(f"{column}: standardized URL scheme, host casing, and fragments")

    if config.drop_duplicates and not cleaned.empty:
        before = len(cleaned)
        cleaned = cleaned.drop_duplicates().reset_index(drop=True)
        transformation_log.append(f"dropped {before - len(cleaned)} duplicate rows")

    return cleaned, transformation_log
