from __future__ import annotations

import argparse
import json
from pathlib import Path

from .cleaning import CleaningConfig
from .config import load_settings
from .logging_config import setup_logging
from .pipeline import FilterConfig, run_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Threat intelligence CSV analytics pipeline.")
    parser.add_argument("--input-csv", action="append", default=[], help="Path to a local CSV file.")
    parser.add_argument("--urlhaus", action="store_true", help="Pull URLHaus recent CSV feed.")
    parser.add_argument("--kev", action="store_true", help="Pull CISA KEV CSV feed.")
    parser.add_argument("--output-dir", default=None, help="Directory for reports and charts.")
    parser.add_argument("--start-date", default=None, help="Optional inclusive start date filter.")
    parser.add_argument("--end-date", default=None, help="Optional inclusive end date filter.")
    parser.add_argument("--threat-category", default=None, help="Optional threat type or tag filter.")
    parser.add_argument("--status-filter", default=None, help="Optional status filter.")
    parser.add_argument(
        "--numeric-missing-strategy",
        choices=["median", "zero"],
        default="median",
        help="How to fill missing numeric values.",
    )
    parser.add_argument(
        "--categorical-missing-strategy",
        choices=["mode", "unknown"],
        default="mode",
        help="How to fill missing categorical values.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    settings = load_settings()
    output_dir = Path(args.output_dir) if args.output_dir else settings.output_dir
    setup_logging(output_dir)
    artifact = run_pipeline(
        settings=settings,
        local_files=args.input_csv,
        include_urlhaus=args.urlhaus,
        include_kev=args.kev,
        output_dir=output_dir,
        cleaning_config=CleaningConfig(
            numeric_strategy=args.numeric_missing_strategy,
            categorical_strategy=args.categorical_missing_strategy,
        ),
        filter_config=FilterConfig(
            start_date=args.start_date,
            end_date=args.end_date,
            threat_category=args.threat_category,
            status=args.status_filter,
        ),
    )
    print(
        json.dumps(
            {
                "rows": artifact.quality_report.total_rows,
                "columns": artifact.quality_report.total_columns,
                "executive_summary": artifact.executive_summary,
                "outputs": {key: str(value) for key, value in artifact.generated_files.items()},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
