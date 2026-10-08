## cve2owl

**cve2owl** is a high-performance Python command-line utility designed to transform the [Common Vulnerabilities and Exposures (CVE)][cve] dataset into a formally grounded OWL 2 knowledge graph, optionally integrated with the [Common Platform Enumeration (CPE)][cpe] dictionary and the [Common Weakness Enumeration (CWE)][cwe] catalogue.

### Key Features

- **Schema-grounded transformation**: Unlike tools that rely on manual mapping, *cve2owl* programmatically derives its TBox (conceptual layer) directly from the official [CVE JSON schema][cve-schema], ensuring full alignment with the standard. The CPE and CWE TBoxes are derived the same way from the NVD CPE schema and the CWE REST API OpenAPI document.
- **Cross-dataset integration**: CPE names and CWE identifiers mentioned by CVE records become individuals linked to the records, so affected products and weaknesses can be queried directly instead of by string matching.
- **Low memory footprint**: Built upon the [PyCowl][pycowl] library, the tool can process the entire CVE dataset with a remarkably low memory footprint (typically under 40 MB), making it executable on standard consumer hardware.
- **High scalability**: The pipeline is capable of ingesting thousands of records per second. As of May 2026, it can transform the entirety of the dataset in minutes.

### Usage

1. Clone this repository:
   ```bash
   git clone https://github.com/sisinflab-swot/cve2owl
   ```
   **Note for peer reviewers:** if you're viewing the anonymized repository, you must download the sources by clicking on *ZIP* in the top-right corner of the web interface.
2. Clone the CVE and CVE schema repositories, and download the CPE and CWE schemas:
   ```bash
   cd cve2owl
   mkdir -p data/cpe-schema data/cwe-schema
   git clone https://github.com/CVEProject/cvelistV5.git data/cvelistv5
   git clone https://github.com/CVEProject/cve-schema.git data/cve-schema
   curl -fL -o data/cpe-schema/cpe_api_json_2.0.schema https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema
   curl -fL -o data/cwe-schema/openapi.json https://raw.githubusercontent.com/CWE-CAPEC/REST-API-wg/main/openapi.json
   ```
   The CPE and CWE schemas are always required, as the three TBoxes are generated on every run. Their location can be changed via `--cpe-schema` and `--cwe-schema`.
3. Install the project and its dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate # Or .venv/Scripts/activate on Windows.
   pip install .
   ```
4. Generate the knowledge graph:
   ```bash
   python -m cve2owl -s data/cve-schema/schema/docs/CVE_Record_Format_bundled.json data/cvelistv5/cves # Or choose a subdirectory to generate a subset.
   ```
   The ontology and per-record metrics (CSV) are written to the `output` directory, which can be changed via `--output-dir`. Records can also be selected by publication date via `--from-date` and `--to-date`, which accept a year, a month or a day (e.g. `2024`, `2024-03`, `2024-03-15`). Note that subdirectories of the CVE dataset are named after the year of the CVE identifier, not the publication year.

### CPE and CWE integration

Every CPE name (2.3 or 2.2 format) found in a CVE record becomes an individual described by its components (`hasVendor`, `hasProduct`, `hasVersion`, etc.), linked to the record via `vulnerableCpe`, or via `platformCpe` for match criteria marked `"vulnerable": false`. Similarly, every CWE identifier becomes an individual linked via `cwe`. Individual names are derived deterministically, so the same product or weakness always maps to the same individual.

Without further data, CPE individuals are only described by their components, and CWE individuals are left bare. They can be enriched with the CPE dictionary and the CWE catalogue as follows.

#### CPE dictionary

Download the NVD CPE dictionary and split it into one file per product:

```bash
mkdir -p data/cpe
curl -fL -o data/cpe/nvdcpe-2.0.tar.gz https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz
python -m cve2owl._cpe_feed data/cpe/nvdcpe-2.0.tar.gz
```

Then pass the resulting directory via `--cpe-dir`:

```bash
python -m cve2owl -s data/cve-schema/schema/docs/CVE_Record_Format_bundled.json data/cvelistv5/cves --cpe-dir data/cpe/dictionary/records
```

By default, only the products mentioned by the processed CVE records are read from the dictionary. Use `--all-cpe` to include the whole dictionary, at the cost of a much larger output.

#### CWE catalogue

The CWE catalogue is fetched from the MITRE REST API (requires [jq][jq]). Weaknesses, categories and views must be stored in separate directories, as CVE records may reference any of them:

```bash
mkdir -p data/cwe/weaknesses data/cwe/categories data/cwe/views

# Save one file per entry from a JSON response
save() { jq -r ".$1[] | \"\(.ID)\t\(tojson)\"" | while IFS=$'\t' read -r id json; do printf '%s' "$json" > "data/cwe/$2/CWE-$id.json"; done; }

# Weaknesses, in batches of 50 (view 1000 plus deprecated weaknesses referenced by CVE records)
curl -fsSL 'https://cwe-api.mitre.org/api/v1/cwe/1000/descendants?view=1000' \
  | jq -r '.. | objects | select(.Type? // "" | endswith("_weakness")) | .ID' \
  | { sort -un; printf '%s\n' 92 216 249 292 443 533 534 592 769; } \
  | xargs -n 50 echo | tr ' ' ',' | while read -r batch; do
      curl -fsSL "https://cwe-api.mitre.org/api/v1/cwe/weakness/$batch" | save Weaknesses weaknesses
    done

curl -fsSL https://cwe-api.mitre.org/api/v1/cwe/category/all | save Categories categories
curl -fsSL https://cwe-api.mitre.org/api/v1/cwe/view/all | save Views views
```

**Note:** avoid the `/cwe/weakness/all` endpoint, as it may silently return truncated responses.

Then pass the catalogue directory via `--cwe-dir`:

```bash
python -m cve2owl -s data/cve-schema/schema/docs/CVE_Record_Format_bundled.json data/cvelistv5/cves --cwe-dir data/cwe
```

### Experiments reproducibility

To reproduce the experiments presented in the paper, synchronize the CVE repository to the [cve_2026-09-25_at_end_of_day](https://github.com/CVEProject/cvelistV5/tree/cve_2026-09-25_at_end_of_day) tag before generating the knowledge graph as above:

```bash
cd data/cvelistv5
git checkout cve_2026-09-25_at_end_of_day
```

### Copyright and License

Copyright © 2026 [SisInf Lab][swot], [Polytechnic University of Bari][poliba].

cve2owl is distributed under the [Eclipse Public License, Version 2.0][epl2].

[cpe]: https://nvd.nist.gov/products/cpe
[cve]: https://github.com/CVEProject/cvelistV5
[cve-schema]: https://github.com/CVEProject/cve-schema
[cwe]: https://cwe.mitre.org
[epl2]: https://www.eclipse.org/legal/epl-2.0
[jq]: https://jqlang.org
[poliba]: https://www.poliba.it
[pycowl]: https://pypi.org/project/pycowl
[swot]: https://swot.sisinflab.poliba.it
