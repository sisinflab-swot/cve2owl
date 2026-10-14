## cve2owl

**cve2owl** is a Python command-line utility designed to transform the [Common Vulnerabilities and Exposures (CVE)][cve] dataset into a formally grounded OWL 2 knowledge graph, optionally integrated with the [Common Platform Enumeration (CPE)][cpe] dictionary and the [Common Weakness Enumeration (CWE)][cwe] catalogue.

### Key features

- **Schema-grounded transformation**: Unlike tools that rely on manual mapping, *cve2owl* programmatically derives its TBox (conceptual layer) from the official [CVE JSON schema][cve-schema], the NVD CPE schema and the CWE REST API OpenAPI document, with targeted fixes where a schema disagrees with the data it describes. When the upstream schemas evolve, the ontology follows by just running the tool again, with no hand-written mapping to maintain.
- **Cross-dataset integration**: CVE records are linked to the products they affect and the weaknesses they exhibit, and the CWE catalogue links back to the records it cites as examples. Weakness hierarchies and CPE deprecation chains are part of the graph too, so all of it can be queried by following links rather than by string matching (see [CVE, CPE and CWE integration](#cve-cpe-and-cwe-integration)).
- **Reasoning-ready modelling**: The output is standard OWL 2 (functional syntax), usable with any OWL tool or reasoner. Enumerated values such as CVSS metrics are modelled as classes of named individuals, schema constraints become datatype facets and XML Schema patterns, the CWE weakness hierarchy is transitive, and CPE deprecation links are declared inverse of each other.
- **Low memory footprint**: Built upon the [PyCowl][pycowl] library, the tool streams records one at a time, so memory use does not grow with the size of the dataset: the whole CVE dataset is processed in tens to a few hundreds of MB, depending on the operating system, making it executable on standard consumer hardware.
- **High throughput**: The pipeline ingests thousands of records per second (roughly 2,000 to 5,000 in our measurements, depending on the hardware), transforming the entire dataset in minutes.
- **Reproducibility**: The same input always yields byte-identical output, and the CVE data can be pinned to a specific cvelistV5 snapshot tag.
- **Selective and incremental processing**: The knowledge graph can be generated for a subset of the CVE records, selected by ID or publication date. Fetching again only updates the existing data, and an interrupted update leaves the previous data intact.
- **Built-in instrumentation**: Per-record metrics (input and output size, axiom count, parsing and writing times, memory use) are written to a CSV file alongside the ontology, easing benchmarking.

### CVE, CPE and CWE integration

Each dataset has its own namespace (`cve:`, `cpe:` and `cwe:`) and its own TBox, derived from its schema. The ABox maps the data as follows:

- **CVE**: every record becomes an individual of `cve:CveRecord`, named after its ID. Nested JSON objects become individuals (named after their parent and key), and scalar values become literals. Enumerated values, such as CVSS metrics, become named individuals of classes enumerating them, rather than plain strings.
- **CPE**: every CPE name, in 2.3 or 2.2 format, becomes an individual of `cpe:CpeName` described by its components (`hasPart`, `hasVendor`, `hasProduct`, `hasVersion`, etc.). Dictionary entries add NVD metadata (titles, references, deprecation status) and link to the names they replace (`deprecates`) or are replaced by (`deprecatedBy`), declared as inverse properties.
- **CWE**: every catalogue entry becomes an individual of `cwe:Weakness`, `cwe:Category` or `cwe:View`. References between entries (related weaknesses, category and view members, mapping suggestions) point to the entries themselves (`hasCwe`, `hasView`) instead of holding their IDs as strings. Each weakness is linked to its direct parents in the Research Concepts view (CWE-1000) via `childOf`, a sub-property of the transitive `descendantOf`, so the whole hierarchy can be navigated.

The datasets are linked by object properties between their individuals:

- CVE → CPE: `vulnerableCpe` links a record to the products it affects, `platformCpe` to the platforms they must run on (match criteria marked `"vulnerable": false`, e.g. the operating system).
- CVE → CWE: `cwe` links a record to the weaknesses it is classified under.
- CWE → CVE: `observedExample` links a weakness to the records the catalogue cites as examples of it.

Individual names are derived deterministically from the identifiers (e.g. `cve:CVE-2024-1234`, `cwe:Cwe79`, `cpe:cpe~a~vendor~product~1.0`), and 2.2 and 2.3 CPE names of the same product map to the same individual. A link therefore always reaches the same individual, whether it comes from a CVE record, the CPE dictionary or the CWE catalogue, so affected products, weaknesses and their ancestors can be queried by following links rather than by string matching. Since CPE individuals are described by their components, they remain meaningful even when the dictionary is not ingested, while CWE individuals are only described by the catalogue.

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
   This fetches the CVE records, the NVD CPE dictionary and the CWE catalogue, along with their schemas, into the `data` directory. The first download may take a while, depending on your connection and disk speed, as the CVE repository alone holds hundreds of thousands of files. Running the command again updates the existing data: the CVE repositories are synchronized, the CPE dictionary is downloaded and preprocessed again only if NVD published a newer one, and the CWE catalogue is downloaded anew.
4. Generate the knowledge graph:
   ```bash
   cve2owl generate
   ```
   The ontology and per-record metrics (CSV) are written to the `output` directory. See [Command-line reference](#command-line-reference) for the available options.

### Command-line reference

The `fetch` command downloads or updates the input data; `generate` builds the knowledge graph from it.

| Command | Option | Description |
|---|---|---|
| both | `-d`, `--data-dir DIR` | Directory of the input data (default: `data`). |
| `fetch` | `DATASET ...` | Datasets to fetch or update, among `cve`, `cpe` and `cwe` (default: all of them). The CVE, CPE and CWE schemas are always fetched, as every `generate` run needs all three TBoxes. |
| `fetch` | `--cve-ref REF` | Tag or commit of cvelistV5 to check out, e.g. a snapshot tag for reproducibility (default: the latest commit). |
| `fetch` | `--force` | Download the CPE dictionary and the CPE and CWE schemas again, and preprocess the dictionary, even if they are up to date. |
| `generate` | `--ids PATTERN ...` | Only process the CVE records whose ID matches one of these glob patterns (e.g. `'CVE-2024-1*'`). |
| `generate` | `--from-date DATE` | Only process the CVE records published on this date or after it. The date can be a year, a month or a day (e.g. `2024`, `2024-03`, `2024-03-15`). |
| `generate` | `--to-date DATE` | Only process the CVE records published on this date or before it. Same formats as `--from-date`. |
| `generate` | `--cpe {none,referenced,all}` | Products to read from the CPE dictionary: those referenced by the processed CVE records (`referenced`, the default), the whole dictionary (`all`, about 1.7 million products, at the cost of a much larger output), or none (`none`). CPE individuals are described by their components in any case. |
| `generate` | `--no-cwe` | Do not read the CWE catalogue, leaving the CWE individuals linked from the CVE records bare. |
| `generate` | `-o`, `--output-dir DIR` | Directory where the ontology and metrics are written (default: `output`). |

#### Examples

```bash
# Update only the CVE records, leaving the CPE dictionary and the CWE catalogue untouched
cve2owl fetch cve

# Update only the CWE catalogue
cve2owl fetch cwe

# Refresh only the CPE dictionary, even if NVD has not published a newer one
cve2owl fetch cpe --force

# Fetch everything into a custom directory
cve2owl fetch -d /path/to/data

# Generate the knowledge graph for the records published in the first half of 2024
cve2owl generate --from-date 2024-01 --to-date 2024-06

# Generate the knowledge graph for the CVE-2025-1xxx records only, without CPE and CWE data
cve2owl generate --ids 'CVE-2025-1???' --cpe none --no-cwe

# Generate the knowledge graph for the whole dataset, including the whole CPE dictionary
cve2owl generate --cpe all -d /path/to/data -o /path/to/output
```

### Copyright and license

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
