from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd


@dataclass(slots=True)
class IngestionArtifact:
    source_name: str
    dataframe: pd.DataFrame
    source_type: str
    origin: str
    encoding: str
    skipped_rows: int = 0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class QualityReport:
    schema: dict[str, str]
    total_rows: int
    total_columns: int
    missing_values: dict[str, int]
    duplicate_rows: int
    outliers: dict[str, int]
    inconsistent_values: dict[str, int]
    malformed_rows: int


@dataclass(slots=True)
class AnalysisArtifact:
    cleaned: pd.DataFrame
    quality_report: QualityReport
    summary_statistics: dict[str, Any]
    correlations: pd.DataFrame
    segmentations: dict[str, pd.DataFrame]
    trends: dict[str, pd.DataFrame]
    anomalies: pd.DataFrame
    executive_summary: str
    recommendations: list[str]
    transformation_log: list[str]
    generated_files: dict[str, Path]
