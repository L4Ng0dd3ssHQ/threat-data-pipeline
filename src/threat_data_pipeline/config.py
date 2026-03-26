from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


DEFAULT_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/data/"
    "known_exploited_vulnerabilities.csv"
)
DEFAULT_URLHAUS_URL = "https://urlhaus-api.abuse.ch/files/exports/recent.csv"


@dataclass(slots=True)
class Settings:
    urlhaus_api_key: str | None
    urlhaus_feed_url: str = DEFAULT_URLHAUS_URL
    cisa_kev_url: str = DEFAULT_KEV_URL
    max_file_size_mb: int = 512
    chunk_size: int = 100_000
    output_dir: Path = Path("output")


def load_settings() -> Settings:
    load_dotenv()
    return Settings(
        urlhaus_api_key=os.getenv("URLHAUS_API_KEY"),
        urlhaus_feed_url=os.getenv("URLHAUS_FEED_URL", DEFAULT_URLHAUS_URL),
        cisa_kev_url=os.getenv("CISA_KEV_URL", DEFAULT_KEV_URL),
        max_file_size_mb=int(os.getenv("MAX_FILE_SIZE_MB", "512")),
        chunk_size=int(os.getenv("CSV_CHUNK_SIZE", "100000")),
        output_dir=Path(os.getenv("OUTPUT_DIR", "output")),
    )
