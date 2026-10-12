from dataclasses import dataclass
from pathlib import Path

DEFAULT_DATA_DIR = Path("data")


@dataclass(frozen=True)
class DataDir:
    root: Path = DEFAULT_DATA_DIR

    @property
    def cve_dir(self) -> Path:
        return self.root / "cve"

    @property
    def cve_repo_dir(self) -> Path:
        return self.cve_dir / "records"

    @property
    def cve_records_dir(self) -> Path:
        return self.cve_repo_dir / "cves"

    @property
    def cve_schema_repo_dir(self) -> Path:
        return self.cve_dir / "schema"

    @property
    def cve_schema(self) -> Path:
        return self.cve_schema_repo_dir / "schema" / "docs" / "CVE_Record_Format_bundled.json"

    @property
    def cpe_dir(self) -> Path:
        return self.root / "cpe"

    @property
    def cpe_schema(self) -> Path:
        return self.cpe_dir / "schema.json"

    @property
    def cpe_feed(self) -> Path:
        return self.cpe_dir / "nvdcpe-2.0.tar.gz"

    @property
    def cpe_records_dir(self) -> Path:
        return self.cpe_dir / "records"

    @property
    def cwe_dir(self) -> Path:
        return self.root / "cwe"

    @property
    def cwe_schema(self) -> Path:
        return self.cwe_dir / "openapi.json"

    @property
    def cwe_catalogue_dir(self) -> Path:
        return self.cwe_dir / "catalogue"
