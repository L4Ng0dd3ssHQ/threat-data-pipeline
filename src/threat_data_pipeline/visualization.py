from __future__ import annotations

from pathlib import Path
import warnings

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

from .analysis import choose_primary_trend_column


plt.style.use("ggplot")


def _save_current_plot(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    figure = plt.gcf()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        figure.tight_layout(pad=1.2)
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(figure)
    return path


def generate_charts(
    df: pd.DataFrame,
    segmentations: dict[str, pd.DataFrame],
    trends: dict[str, pd.DataFrame],
    anomalies: pd.DataFrame,
    output_dir: Path,
) -> dict[str, Path]:
    charts: dict[str, Path] = {}
    charts_dir = output_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    threat_seg = segmentations.get("threat_type")
    if threat_seg is not None and not threat_seg.empty:
        chart = threat_seg.head(10)
        plt.figure(figsize=(10, 5))
        plt.bar(chart.iloc[:, 0].astype(str), chart["count"])
        plt.xticks(rotation=45, ha="right")
        plt.title("Threat Type Distribution")
        plt.xlabel("Threat Type")
        plt.ylabel("Count")
        charts["threat_type_distribution"] = _save_current_plot(charts_dir / "threat_type_distribution.png")

    country_seg = segmentations.get("country")
    if country_seg is not None and not country_seg.empty:
        chart = country_seg.head(10)
        plt.figure(figsize=(10, 5))
        plt.bar(chart.iloc[:, 0].astype(str), chart["count"])
        plt.xticks(rotation=45, ha="right")
        plt.title("Top Hosting Countries")
        plt.xlabel("Country / Dimension")
        plt.ylabel("Count")
        charts["top_hosting_countries"] = _save_current_plot(charts_dir / "top_hosting_countries.png")

    severity_seg = segmentations.get("severity")
    if severity_seg is not None and not severity_seg.empty:
        plt.figure(figsize=(8, 5))
        plt.pie(severity_seg["count"], labels=severity_seg.iloc[:, 0].astype(str), autopct="%1.1f%%")
        plt.title("CVE Severity Breakdown")
        charts["cve_severity_breakdown"] = _save_current_plot(charts_dir / "cve_severity_breakdown.png")

    primary_trend_column = choose_primary_trend_column(trends)
    if primary_trend_column:
        trend = trends[primary_trend_column]
        plt.figure(figsize=(11, 5))
        plt.plot(trend["date"], trend["count"], marker="o", label="Daily count")
        highlight = trend[trend["is_anomaly"]]
        if not highlight.empty:
            plt.scatter(highlight["date"], highlight["count"], color="red", label="Anomaly")
        axis = plt.gca()
        axis.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
        axis.xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.xticks(rotation=45, ha="right")
        plt.title(f"Timeline of Reported Activity: {primary_trend_column}")
        plt.xlabel("Date")
        plt.ylabel("Count")
        plt.legend()
        charts[f"timeline_{primary_trend_column}"] = _save_current_plot(
            charts_dir / f"timeline_{primary_trend_column}.png"
        )

    if not anomalies.empty:
        anomaly_view = anomalies
        if primary_trend_column:
            focused = anomalies[anomalies["source_column"] == primary_trend_column]
            if not focused.empty:
                anomaly_view = focused
        plt.figure(figsize=(10, 5))
        labels = anomaly_view["date_label"].astype(str) + " | " + anomaly_view["source_column"].astype(str)
        plt.bar(labels, anomaly_view["count"], color="crimson")
        plt.xticks(rotation=45, ha="right")
        plt.title("Anomaly Highlights")
        plt.xlabel("Detected Spike")
        plt.ylabel("Count")
        charts["anomaly_highlights"] = _save_current_plot(charts_dir / "anomaly_highlights.png")

    if df.shape[1] == 1:
        sole_column = df.columns[0]
        counts = df[sole_column].fillna("Unknown").astype(str).value_counts().head(10)
        plt.figure(figsize=(10, 5))
        plt.bar(counts.index.astype(str), counts.values)
        plt.xticks(rotation=45, ha="right")
        plt.title(f"Single-Column Distribution: {sole_column}")
        plt.xlabel(sole_column)
        plt.ylabel("Count")
        charts["single_column_distribution"] = _save_current_plot(charts_dir / "single_column_distribution.png")

    return charts
