from .core.log import logger as log
from .cpe import fetch as cpe
from .cve import fetch as cve
from .cwe import fetch as cwe
from .data import DataDir

DATASETS = ("cve", "cpe", "cwe")


def fetch(
    datasets: list[str] | None = None,
    *,
    data: DataDir,
    cve_ref: str | None = None,
    force: bool = False,
) -> None:
    datasets = datasets or list(DATASETS)

    log.info("Fetching schemas...")
    cve.fetch_schema(data)
    cpe.fetch_schema(data, force=force)
    cwe.fetch_schema(data, force=force)

    if "cve" in datasets:
        log.info("Fetching CVE records...")
        cve.fetch_records(data, cve_ref)
    if "cpe" in datasets:
        log.info("Fetching CPE dictionary...")
        cpe.fetch_dictionary(data, force=force)
    if "cwe" in datasets:
        log.info("Fetching CWE catalogue...")
        cwe.fetch_catalogue(data)
    log.info("Done.")
