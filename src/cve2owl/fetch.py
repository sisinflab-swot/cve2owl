from .core.log import logger as log
from .cpe import fetch as cpe
from .cve import fetch as cve
from .cwe import fetch as cwe

DATASETS = ("cve", "cpe", "cwe")


def fetch(
    datasets: list[str] | None = None,
    *,
    cve_ref: str | None = None,
    force: bool = False,
) -> None:
    datasets = datasets or list(DATASETS)

    log.info("Fetching schemas...")
    cve.fetch_schema()
    cpe.fetch_schema(force=force)
    cwe.fetch_schema(force=force)

    if "cve" in datasets:
        log.info("Fetching CVE records...")
        cve.fetch_records(cve_ref)
    if "cpe" in datasets:
        log.info("Fetching CPE dictionary...")
        cpe.fetch_dictionary(force=force)
    if "cwe" in datasets:
        log.info("Fetching CWE catalogue...")
        cwe.fetch_catalogue()
    log.info("Done.")
