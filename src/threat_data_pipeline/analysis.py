from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd

from .validation import empty_safe_describe


def _find_column(columns: Iterable[str], candidates: list[str]) -> str | None:
    lowered = {column.lower(): column for column in columns}
    for candidate in candidates:
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]
    for column in columns:
        for candidate in candidates:
            if candidate.lower() in column.lower():
                return column
    return None


def find_matching_column(columns: Iterable[str], candidates: list[str]) -> str | None:
    return _find_column(columns, candidates)


def choose_primary_trend_column(trends: dict[str, pd.DataFrame]) -> str | None:
    if not trends:
        return None
    preferred_names = [
        "dateAdded",
        "date_added",
        "reported",
        "dateReported",
        "date",
        "firstseen",
        "first_seen",
        "date_added",
        "dateadded",
        "dateReported",
        "dateAdded",
    ]
    for name in preferred_names:
        for column in trends:
            if column.lower() == name.lower():
                return column
    for column in trends:
        lowered = column.lower()
        if "due" in lowered:
            continue
        if any(token in lowered for token in ["date", "reported", "added", "seen"]):
            return column
    return next(iter(trends))


def _summarize_sources(df: pd.DataFrame) -> list[str]:
    if "source_name" not in df.columns or df.empty:
        return []

    points: list[str] = []
    normalized_source_names = (
        df["source_name"]
        .fillna("unknown")
        .astype(str)
        .str.strip()
        .str.lower()
        .str.replace(r"[\s_-]+", "_", regex=True)
    )
    source_counts = normalized_source_names.value_counts()

    if "urlhaus" in source_counts.index:
        points.append(f"URLHaus contributed {int(source_counts['urlhaus']):,} cleaned URL records.")
    if "cisa_kev" in source_counts.index:
        kev_count = int(source_counts["cisa_kev"])
        points.append(f"CISA KEV contributed {kev_count:,} exploited-vulnerability records.")
        vendor_column = find_matching_column(df.columns, ["vendorProject", "vendor", "vendor_project"])
        if vendor_column:
            top_vendor = (
                df.loc[normalized_source_names == "cisa_kev", vendor_column]
                .dropna()
                .astype(str)
                .value_counts()
            )
            if not top_vendor.empty:
                points.append(
                    f"The most frequently affected KEV vendor is {top_vendor.index[0]} with {int(top_vendor.iloc[0]):,} entries."
                )
    return points


def build_segmentations(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    segmentations: dict[str, pd.DataFrame] = {}
    mappings = {
        "threat_type": ["threat", "threat_type", "tags"],
        "country": ["country", "country_code", "host"],
        "vendor": ["vendorProject", "vendor", "vendor_project"],
        "severity": ["derived_severity", "severity", "cvssseverity", "cvss_severity"],
        "status": ["status", "url_status", "vulnStatus"],
    }
    for key, candidates in mappings.items():
        column = _find_column(df.columns, candidates)
        if not column:
            continue
        segmentations[key] = (
            df[column]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .rename_axis(column)
            .reset_index(name="count")
        )
    return segmentations


def compute_correlations(df: pd.DataFrame, schema: dict[str, str]) -> pd.DataFrame:
    numeric_columns = [column for column, kind in schema.items() if kind == "numeric"]
    if len(numeric_columns) < 2:
        return pd.DataFrame()
    return df[numeric_columns].apply(pd.to_numeric, errors="coerce").corr(numeric_only=True)


def derive_severity(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    score_column = _find_column(df.columns, ["baseScore", "cvssScore", "cvss_score"])
    severity_column = _find_column(df.columns, ["severity", "cvssSeverity", "cvss_severity"])
    if severity_column:
        result["derived_severity"] = result[severity_column].fillna("Unknown").astype(str).str.title()
        return result
    if score_column:
        score = pd.to_numeric(result[score_column], errors="coerce")
        result["derived_severity"] = pd.cut(
            score,
            bins=[-np.inf, 0, 3.9, 6.9, 8.9, np.inf],
            labels=["Unknown", "Low", "Medium", "High", "Critical"],
        ).astype("string")
        return result
    result["derived_severity"] = "Unknown"
    return result


def build_trends(df: pd.DataFrame, schema: dict[str, str]) -> tuple[dict[str, pd.DataFrame], pd.DataFrame]:
    trends: dict[str, pd.DataFrame] = {}
    anomaly_frames: list[pd.DataFrame] = []
    for column, kind in schema.items():
        if kind != "date":
            continue
        parsed = pd.to_datetime(df[column], errors="coerce", utc=True).dropna()
        if parsed.empty:
            continue
        trend = (
            parsed.dt.floor("D")
            .value_counts()
            .sort_index()
            .rename_axis("date")
            .reset_index(name="count")
        )
        trend["date_label"] = trend["date"].dt.strftime("%Y-%m-%d")
        trend["rolling_mean"] = trend["count"].rolling(window=7, min_periods=2).mean()
        trend["rolling_std"] = trend["count"].rolling(window=7, min_periods=2).std().fillna(0)
        trend["is_anomaly"] = trend["count"] > (trend["rolling_mean"] + 2 * trend["rolling_std"]).fillna(np.inf)
        trend["source_column"] = column
        trends[column] = trend
        anomaly_frames.append(trend[trend["is_anomaly"]].copy())
    anomalies = pd.concat(anomaly_frames, ignore_index=True) if anomaly_frames else pd.DataFrame()
    return trends, anomalies


def build_summary_statistics(df: pd.DataFrame) -> dict[str, object]:
    return {
        "dataset": empty_safe_describe(df),
        "row_count": int(len(df)),
        "column_count": int(len(df.columns)),
    }


def generate_executive_summary(
    df: pd.DataFrame,
    segmentations: dict[str, pd.DataFrame],
    trends: dict[str, pd.DataFrame],
    anomalies: pd.DataFrame,
) -> tuple[str, list[str]]:
    if df.empty:
        return (
            "The pipeline ingested no usable records, so trend and threat-intelligence analysis could not be performed.",
            ["Validate source availability, credentials, and CSV structure before rerunning the pipeline."],
        )

    points: list[str] = [
        f"The combined threat-intelligence dataset contains {len(df):,} records."
    ]
    points.extend(_summarize_sources(df))
    threat_seg = segmentations.get("threat_type")
    if threat_seg is not None and not threat_seg.empty:
        top = threat_seg.iloc[0]
        points.append(f"The dominant threat category is {top.iloc[0]} with {int(top['count']):,} records.")
    country_seg = segmentations.get("country")
    if country_seg is not None and not country_seg.empty:
        top = country_seg.iloc[0]
        points.append(f"The top hosting or reporting country dimension is {top.iloc[0]} with {int(top['count']):,} records.")
    primary_trend_column = choose_primary_trend_column(trends)
    if primary_trend_column:
        primary_anomalies = anomalies[anomalies["source_column"] == primary_trend_column] if not anomalies.empty else pd.DataFrame()
        if not primary_anomalies.empty:
            peak = primary_anomalies.sort_values("count", ascending=False).iloc[0]
            peak_date = peak["date_label"] if "date_label" in primary_anomalies.columns else str(peak["date"])
            points.append(
                f"An activity spike was detected on {peak_date} in {primary_trend_column} with {int(peak['count'])} observations."
            )
        else:
            points.append(
                f"No statistically significant spikes were detected in {primary_trend_column} with the rolling 7-day anomaly threshold."
            )
    else:
        points.append("No statistically significant spikes were detected with the rolling 7-day anomaly threshold.")

    if primary_trend_column:
        primary_trend = trends[primary_trend_column]
        if len(primary_trend) >= 2:
            recent = primary_trend["count"].tail(min(30, len(primary_trend)))
            baseline = primary_trend["count"].head(max(len(primary_trend) - len(recent), 1))
            if not baseline.empty and baseline.mean() > 0:
                pct_change = ((recent.mean() - baseline.mean()) / baseline.mean()) * 100
                direction = "increased" if pct_change >= 0 else "decreased"
                points.append(
                    f"Observed daily activity in {primary_trend_column} has {direction} by {abs(pct_change):.1f}% "
                    "in the most recent period versus the earlier baseline."
                )

    recommendations = [
        "Prioritize investigation on the highest-volume URL categories and KEV vendors identified in the segmentation output.",
        "Review anomaly dates in the primary activity timeline to determine whether spikes map to active campaigns, disclosure waves, or ingestion artifacts.",
        "Push cleaned indicators and KEV enrichments into downstream SIEM, case-management, or data-lake workflows for analyst follow-up.",
    ]
    return " ".join(points), recommendations
