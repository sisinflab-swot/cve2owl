## cve2owl

**cve2owl** is a high-performance Python command-line utility designed to transform the [Common Vulnerabilities and Exposures (CVE)][cve] dataset into a formally grounded OWL 2 knowledge graph.

### Key Features

- **Schema-grounded transformation**: Unlike tools that rely on manual mapping, *cve2owl* programmatically derives its TBox (conceptual layer) directly from the official [CVE JSON schema][cve-schema], ensuring full alignment with the standard.
- **Low memory footprint**: Built upon the [PyCowl][pycowl] library, the tool can process the entire CVE dataset with a remarkably low memory footprint (typically under 40 MB), making it executable on standard consumer hardware.
- **High scalability**: The pipeline is capable of ingesting thousands of records per second. As of May 2026, it can transform the entirety of the dataset in minutes.

### Usage

1. Clone this repository:
   ```bash
   git clone https://github.com/sisinflab-swot/cve2owl && cd cve2owl
   ```
   **Note for peer reviewers:** if you're viewing the anonymized repository, you must download the sources by clicking on *ZIP* in the top-right corner of the web interface.
2. Clone the CVE and CVE schema repositories:
   ```bash
   mkdir data
   git clone https://github.com/CVEProject/cvelistV5.git data/cvelistv5
   git clone https://github.com/CVEProject/cve-schema.git data/cve-schema
   ```
3. Install the project and its dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install .
   ```
4. Generate the knowledge graph:
   ```bash
   python -m cve2owl -s data/cve-schema/schema/docs/CVE_Record_Format_bundled.json data/cvelistV5/cves # Or choose a subdirectory to generate a subset.
   ```

### Experiments reproducibility

To reproduce the experiments presented in the paper, synchronize the CVE repository to the [cve_2026-05-05_0000Z](https://github.com/CVEProject/cvelistV5/tree/cve_2026-05-05_0000Z) tag before generating the knowledge graph as above:

```bash
cd data/cvelistv5
git checkout cve_2026-05-05_0000Z
```

### Copyright and License

Copyright © 2026 [SisInf Lab][swot], [Polytechnic University of Bari][poliba].

cve2owl is distributed under the [Eclipse Public License, Version 2.0][epl2].

[cve]: https://github.com/CVEProject/cvelistV5
[cve-schema]: https://github.com/CVEProject/cve-schema
[epl2]: https://www.eclipse.org/legal/epl-2.0
[poliba]: https://www.poliba.it
[pycowl]: https://pypi.org/project/pycowl
[swot]: https://swot.sisinflab.poliba.it
