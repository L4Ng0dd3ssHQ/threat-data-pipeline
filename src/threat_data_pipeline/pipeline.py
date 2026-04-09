from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .analysis import (
    build_segmentations,
    build_summary_statistics,
    build_trends,
    compute_correlations,
    derive_severity,
    find_matching_column,
    generate_executive_summary,
)
from .cleaning import CleaningConfig, clean_dataframe
from .config import Settings
from .ingestion import (
    IngestionArtifact,
    ingest_alienvault,
    ingest_cisa_kev,
    ingest_feodo_tracker,
    ingest_local_csv,
    ingest_threatfox,
    ingest_urlhaus,
    merge_artifacts,
)
from .models import AnalysisArtifact
from .validation import build_quality_report, infer_schema


@dataclass(slots=True)
class FilterConfig:
    start_date: str | None = None
    end_date: str | None = None
    threat_category: str | None = None
    status: str | None = None


def apply_filters(df, schema: dict[str, str], filters: FilterConfig | None):
    if filters is None or df.empty:
        return df, []

    filtered = df.copy()
    applied: list[str] = []

    if filters.start_date or filters.end_date:
        date_column = find_matching_column(
            [column for column, kind in schema.items() if kind == "date"],
            ["date_added", "date", "reported", "dateReported", "dateAdded", "dueDate"],
        )
        if date_column:
            parsed = pd.to_datetime(filtered[date_column], errors="coerce", utc=True)
            if filters.start_date:
                filtered = filtered[parsed >= pd.to_datetime(filters.start_date, utc=True)]
                applied.append(f"start_date>={filters.start_date}")
                parsed = pd.to_datetime(filtered[date_column], errors="coerce", utc=True)
            if filters.end_date:
                filtered = filtered[parsed <= pd.to_datetime(filters.end_date, utc=True)]
                applied.append(f"end_date<={filters.end_date}")

    if filters.threat_category:
        threat_column = find_matching_column(filtered.columns, ["threat", "threat_type", "tags", "tag"])
        if threat_column:
            filtered = filtered[
                filtered[threat_column].fillna("").astype(str).str.contains(filters.threat_category, case=False)
            ]
            applied.append(f"threat_category={filters.threat_category}")

    if filters.status:
        status_column = find_matching_column(filtered.columns, ["status", "url_status", "vulnStatus"])
        if status_column:
            normalized = filtered[status_column].fillna("").astype(str).str.strip().str.lower()
            filtered = filtered[
                normalized == filters.status.strip().lower()
            ]
            applied.append(f"status={filters.status}")

    return filtered.reset_index(drop=True), applied


def run_pipeline(
    settings: Settings,
    local_files: list[str] | None = None,
    include_urlhaus: bool = False,
    include_kev: bool = False,
    include_threatfox: bool = False,
    include_alienvault: bool = False,
    include_feodo_tracker: bool = False,
    output_dir: Path | None = None,
    cleaning_config: CleaningConfig | None = None,
    filter_config: FilterConfig | None = None,
) -> AnalysisArtifact:
    output_dir = output_dir or settings.output_dir
    artifacts: list[IngestionArtifact] = []

    for file_path in local_files or []:
        artifacts.append(ingest_local_csv(file_path, settings))
    if include_urlhaus:
        artifacts.append(ingest_urlhaus(settings))
    if include_kev:
        artifacts.append(ingest_cisa_kev(settings))
    if include_threatfox:
        artifacts.append(ingest_threatfox(settings))
    if include_alienvault:
        artifacts.append(ingest_alienvault(settings))
    if include_feodo_tracker:
        artifacts.append(ingest_feodo_tracker(settings))

    combined = merge_artifacts(artifacts)
    combined = derive_severity(combined)
    malformed_rows = sum(artifact.skipped_rows for artifact in artifacts)
    quality_report = build_quality_report(combined, malformed_rows=malformed_rows)
    schema = infer_schema(combined)
    cleaned, transformation_log = clean_dataframe(combined, schema, cleaning_config)
    cleaned, filter_log = apply_filters(cleaned, schema, filter_config)
    transformation_log.extend(f"filter applied: {item}" for item in filter_log)
    summary_statistics = build_summary_statistics(cleaned)
    correlations = compute_correlations(cleaned, schema)
    segmentations = build_segmentations(cleaned)
    trends, anomalies = build_trends(cleaned, schema)
    executive_summary, recommendations = generate_executive_summary(
        cleaned, segmentations, trends, anomalies
    )
    from .visualization import generate_charts

    generated_files = generate_charts(cleaned, segmentations, trends, anomalies, output_dir)

    artifact = AnalysisArtifact(
        cleaned=cleaned,
        quality_report=quality_report,
        summary_statistics=summary_statistics,
        correlations=correlations,
        segmentations=segmentations,
        trends=trends,
        anomalies=anomalies,
        executive_summary=executive_summary,
        recommendations=recommendations,
        transformation_log=transformation_log,
        generated_files=generated_files,
    )
    from .reporting import export_excel_report, export_pdf_report

    artifact.generated_files["excel_report"] = export_excel_report(artifact, output_dir)
    artifact.generated_files["pdf_report"] = export_pdf_report(artifact, output_dir)
    return artifact
