## cve2owl

**cve2owl** is a high-performance Python command-line utility designed to transform the [Common Vulnerabilities and Exposures (CVE)][cve] dataset into a formally grounded OWL 2 knowledge graph, optionally integrated with the [Common Platform Enumeration (CPE)][cpe] dictionary and the [Common Weakness Enumeration (CWE)][cwe] catalogue.

### Key Features

- **Schema-grounded transformation**: Unlike tools that rely on manual mapping, *cve2owl* programmatically derives its TBox (conceptual layer) directly from the official [CVE JSON schema][cve-schema], ensuring full alignment with the standard. The CPE and CWE TBoxes are derived the same way from the NVD CPE schema and the CWE REST API OpenAPI document.
- **Cross-dataset integration**: CPE names and CWE identifiers mentioned by CVE records become individuals linked to the records, so affected products and weaknesses can be queried directly instead of by string matching.
- **Low memory footprint**: Built upon the [PyCowl][pycowl] library, the tool can process the entire CVE dataset with a remarkably low memory footprint (typically around 40 MB), making it executable on standard consumer hardware.
- **High scalability**: The pipeline is capable of ingesting thousands of records per second. As of May 2026, it can transform the entirety of the dataset in minutes.

### Usage

1. Clone this repository:
   ```bash
   git clone https://github.com/sisinflab-swot/cve2owl
   ```
   **Note for peer reviewers:** if you're viewing the anonymized repository, you must download the sources by clicking on *ZIP* in the top-right corner of the web interface.
2. Install the project and its dependencies:
   ```bash
   cd cve2owl
   python -m venv .venv
   source .venv/bin/activate # Or .venv/Scripts/activate on Windows.
   pip install .
   ```
   This installs the `cve2owl` command, which is also available as `python -m cve2owl`.
3. Download the input data (requires [git][git]):
   ```bash
   cve2owl fetch
   ```
   This fetches the CVE records, the NVD CPE dictionary and the CWE catalogue, along with their schemas, into the `data` directory, which can be changed via `--data-dir` (also accepted by `generate`). The first download may take a while, depending on your connection and disk speed, as the CVE repository alone holds hundreds of thousands of files. To fetch only some datasets, name them, e.g. `cve2owl fetch cve cwe`. The schemas are always fetched, as every run needs all three TBoxes. Running the command again updates the existing data: the CVE repositories are synchronized, the CPE dictionary is downloaded and preprocessed again only if NVD published a newer one (`--force` does it anyway), and the CWE catalogue is downloaded again.
4. Generate the knowledge graph:
   ```bash
   cve2owl generate
   ```
   The ontology and per-record metrics (CSV) are written to the `output` directory, which can be changed via `--output-dir`. Records can be selected by publication date via `--from-date` and `--to-date`, which accept a year, a month or a day (e.g. `2024`, `2024-03`, `2024-03-15`), and by ID via `--ids`, which accepts glob patterns (e.g. `--ids 'CVE-2024-*'`).

### CPE and CWE integration

Every CPE name (2.3 or 2.2 format) found in a CVE record becomes an individual described by its components (`hasVendor`, `hasProduct`, `hasVersion`, etc.), linked to the record via `vulnerableCpe`, or via `platformCpe` for match criteria marked `"vulnerable": false`. Similarly, every CWE identifier becomes an individual linked via `cwe`. Individual names are derived deterministically, so the same product or weakness always maps to the same individual.

These individuals are further described by the CPE dictionary and the CWE catalogue:

- `--cpe` selects the products read from the CPE dictionary: those mentioned by the processed CVE records (`referenced`, the default), the whole dictionary (`all`, at the cost of a much larger output), or none (`none`, so CPE individuals are only described by their components).
- `--no-cwe` skips the CWE catalogue, leaving CWE individuals bare, since nothing can be derived from a CWE identifier alone.

### Experiments reproducibility

To reproduce the experiments presented in the paper, synchronize the CVE repository to the [cve_2026-09-25_at_end_of_day](https://github.com/CVEProject/cvelistV5/tree/cve_2026-09-25_at_end_of_day) tag before generating the knowledge graph as above:

```bash
cve2owl fetch cve --cve-ref cve_2026-09-25_at_end_of_day
```

### Copyright and License

Copyright © 2026 [SisInf Lab][swot], [Polytechnic University of Bari][poliba].

cve2owl is distributed under the [Eclipse Public License, Version 2.0][epl2].

[cpe]: https://nvd.nist.gov/products/cpe
[cve]: https://github.com/CVEProject/cvelistV5
[cve-schema]: https://github.com/CVEProject/cve-schema
[cwe]: https://cwe.mitre.org
[epl2]: https://www.eclipse.org/legal/epl-2.0
[git]: https://git-scm.com
[poliba]: https://www.poliba.it
[pycowl]: https://pypi.org/project/pycowl
[swot]: https://swot.sisinflab.poliba.it
