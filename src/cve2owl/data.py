from pathlib import Path

DATA_DIR = Path("data")

CVE_DIR = DATA_DIR / "cve"
CVE_REPO_DIR = CVE_DIR / "records"
CVE_RECORDS_DIR = CVE_REPO_DIR / "cves"
CVE_SCHEMA_REPO_DIR = CVE_DIR / "schema"
CVE_SCHEMA = CVE_SCHEMA_REPO_DIR / "schema" / "docs" / "CVE_Record_Format_bundled.json"

CPE_DIR = DATA_DIR / "cpe"
CPE_SCHEMA = CPE_DIR / "schema.json"
CPE_FEED = CPE_DIR / "nvdcpe-2.0.tar.gz"
CPE_RECORDS_DIR = CPE_DIR / "records"

CWE_DIR = DATA_DIR / "cwe"
CWE_SCHEMA = CWE_DIR / "openapi.json"
CWE_CATALOGUE_DIR = CWE_DIR / "catalogue"
