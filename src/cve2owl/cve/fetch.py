from cve2owl.core.fetch import git_sync
from cve2owl.data import CVE_REPO_DIR, CVE_SCHEMA_REPO_DIR

RECORDS_URL = "https://github.com/CVEProject/cvelistV5.git"
SCHEMA_URL = "https://github.com/CVEProject/cve-schema.git"


def fetch_schema() -> None:
    git_sync(SCHEMA_URL, CVE_SCHEMA_REPO_DIR)


def fetch_records(ref: str | None = None) -> None:
    git_sync(RECORDS_URL, CVE_REPO_DIR, ref)
