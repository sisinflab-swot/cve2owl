from cve2owl.core.fetch import git_sync
from cve2owl.data import DataDir

RECORDS_URL = "https://github.com/CVEProject/cvelistV5.git"
SCHEMA_URL = "https://github.com/CVEProject/cve-schema.git"


def fetch_schema(data: DataDir) -> None:
    git_sync(SCHEMA_URL, data.cve_schema_repo_dir)


def fetch_records(data: DataDir, ref: str | None = None) -> None:
    git_sync(RECORDS_URL, data.cve_repo_dir, ref)
