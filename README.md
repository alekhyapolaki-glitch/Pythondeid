# pythondeid: SQL Server de-identification with referential integrity

A Python tool, built to run on an **ActiveState** Python runtime, that masks PII in SQL Server
databases **in place**. A given input value always produces the same masked value in every
table, database and server that uses the same secret key and rules, so joins and foreign keys
keep working after masking. It is built for SQL Server 2022 and large tables.

| Requirement | Where it lives |
|---|---|
| Table structure and fields as input | `discover` writes the live schema to CSV. Rules go in `config/deid_rules.yaml` (or `wizard` / `import-csv`). |
| Columns to de-identify | `config/deid_rules.yaml`: table → column → *domain* |
| Same masking across tables, databases and servers | Deterministic keyed algorithms per *domain*, plus key fingerprint pinning, `algorithm_version` and `test-vectors` |
| Full de-identification or keep last 4 (SSN, account, card) | `mode: full \| last4` (cards also `first6_last4`) per domain |
| Input/output data types and recommendations | `expected_input_type`, `output_type` and `output_format` per column; `recommend`; `list-types` |
| Per-person date shifting | `date_shift` with `shift_by: entity` + `entity_column` |
| Free-text options | `free_text` with `mode: scrub \| redact \| nullify \| hash` and per-detector actions |
| Big tables | `batch_size: auto` sized per table, parallel masking workers, unique-index handling, DB readiness checks |
| Update SQL Server, ask questions, audit | `run` with confirmations, `configure`/`wizard`, `deid_audit.*` tables + `audit/<run_id>/` files |

## Configuration files

| File | Holds | Shared between servers? | In Git? |
|---|---|---|---|
| `config/connections.yaml` | **Database connections**: several named ones (`dev`, `uat`, …), one `default` | No, one per machine | No (template: `connections.example.yaml`) |
| `config/paths.yaml` | **File/folder locations**: rules file, audit folder, logs, discovery/test-vector CSVs | Usually the same | Yes |
| `config/settings.yaml` | **How it runs**: batching, workers, key fingerprint, audit options, log level | Yes | Yes |
| `config/deid_rules.yaml` | **What to mask**: policy, domains, tables | Yes, must be identical | Yes |

* Secrets are in **no** file: the masking key is `DEID_SECRET_KEY`, and SQL passwords go in the
  variable named by each connection's `password_env`.
* `python main.py configure` adds or updates a connection, the run settings and the policy.
  `python main.py connections` lists connections.
* Pick a connection per command: `python main.py -c uat validate`. Without `-c`, the default is used.
* Relative paths in `paths.yaml` are relative to the project folder, so commands work from any
  directory.

---

## 1. Consistency across tables, databases and servers

**Domains.** A domain is a named masking definition (type + parameters). Every column that holds
the same kind of identifier uses the same domain, wherever it lives. Each domain has its own key:
`HMAC-SHA256(master_secret, "v1|" + domain_name)`.

A masked value depends only on the **secret key, the algorithm version, the domain (name and
parameters) and the canonical input value**. Nothing else feeds in: no randomness, server name,
run id or row order. So the same value gives the same mask in every table, database and server,
on every run.

Four ways to keep every environment configured identically:

| Mechanism | What it does |
|---|---|
| Same `DEID_SECRET_KEY` everywhere | Store it in your vault and inject it on each server. |
| `security.expected_key_fingerprint` | Pin the fingerprint printed by `python main.py key-fingerprint`. A server with a different key refuses to run. |
| `algorithm_version: 1` in the rules | Refuses to run if the tool's algorithm differs. |
| `python main.py test-vectors` | Writes known-answer masks for every domain, using synthetic inputs only. `test-vectors --check file.csv` on another server proves it produces byte-identical output. |

**Canonical input** removes representation differences before masking, so different storage
types still match:

| Same identity | How |
|---|---|
| `John.Doe@Mail.COM` = `john.doe@mail.com` | `email` lowercases and trims |
| `123-45-6789` (char) = `123456789` (varchar) = `123456789` (int) | `ssn` works on the 9 digits; ints are zero-padded |
| `'000000012345'` (varchar(12)) = `12345` (bigint) | `account_number`/`fpe` with `normalize: digits, pad_to: 12` |
| `ACC-000123-01` = `ACC00012301` | FPE ignores separator positions |

The run also checks foreign keys. Both columns of every FK must be in the same domain (partner
columns are added automatically), and a domain used on mixed types without normalisation produces
a warning.

## 2. Masking algorithms and options

| Type | Algorithm | Options | Unique / FK-safe |
|---|---|---|---|
| `ssn` | FF1-style Feistel FPE on the 9 digits. Cycle-walking keeps valid SSNs valid (area ≠ 000/666/9xx). | `mode: full \| last4`, `output_format: preserve \| dashed \| digits` (per column allowed), `realistic` | ✅ bijective |
| `account_number`, `fpe` | FPE on digits (radix 10) and letters (radix 26). Format, separators and case are kept. | `mode: full \| last4`, `normalize: digits` + `pad_to`, `preserve_first/last` | ✅ bijective |
| `credit_card` | FPE + recomputed Luhn check digit | `mode: full \| last4 \| first6_last4`, `output_format: preserve \| digits \| grouped` | ✅ |
| `phone` | FPE on digits; punctuation kept | `preserve_first/last` | ✅ bijective |
| `email` | `user<HMAC token>@example.com` | `token_length` (16), `domain`, `preserve_domain` | ✅ collision-checked |
| `hash` | HMAC-SHA256 hex | `length`, `prefix` | ✅ collision-checked |
| `first_name`, `last_name`, `full_name`, `street_address`, `city` | Deterministic pick from lists | — | ❌ not unique |
| `account_name` | People → fake person names; businesses → fake company words with INC/LLC/LTD and industry words kept (`ACME DEVELOPMENT INC` → `OASIS DEVELOPMENT INC`); trusts/estates keep their wording with fake person names | `keep_industry_words`, `extra_business_words`, `keep_numbers` | ❌ not unique |
| `zip` | `truncate` (first 3 digits) or `fpe` | `mode`, `keep_digits` | fpe ✅ |
| `date_shift` | ±N-day shift | `shift_by: value \| entity`, `max_days`, `generalize: none \| year \| month` | ❌ |
| `free_text` | Regex scrub of PII inside text | see §5 | ❌ |
| `redact`, `nullify` | Constant / NULL | `value`, `preserve_length` | ❌ |

**Masking policy (full vs last 4, name method).** These choices sit in one place, the `policy:`
section at the top of `config/deid_rules.yaml`:

```yaml
policy:
  ssn:             full           # full | last4
  account_number:  full           # full | last4
  credit_card:     first6_last4   # full | last4 | first6_last4
  names:           realistic      # realistic | hash | redact   (full_name and account_name columns)
  phone:           full           # full | last4 | area_code
  address:         realistic      # realistic | hash | redact   (street_address columns)
  city:            realistic      # realistic | hash | redact
  zip:             truncate       # truncate (first 3 digits kept) | fpe (fully de-identified)
```

| Policy | Values (examples with a demo key) |
|---|---|
| `phone` | `full` `(555) 123-4567`→`(568) 988-7543` · `last4` →`(384) 539-4567` · `area_code` →`(555) 137-8309` (also keeps a leading `+1`) |
| `address` | `realistic` `12 High St`→`4255 River Way` · `hash` →`89d6919c7f05ff94` · `redact` →`REDACTED` |
| `city` | `realistic` `Boston`→`Milton` · `hash` · `redact` |
| `zip` | `truncate` `80202-1234`→`80200-0000` · `fpe` →`85819-5248` (unique, nothing kept) |

* Set them with questions: `python main.py policy`. `configure` and `wizard` also ask them.
* They apply to every domain of that type. A domain that sets `mode`/`method` itself overrides the
  policy for that domain only.
* The plan printed by `validate`, `dry-run` and `run` shows the resulting `[mode=…]`/`[method=…]`
  per column before anything changes.
* Masked values depend on these choices, so use the same policy on every server.

The masked part stays collision-free in both modes. Keeping the last 4 digits weakens the
protection: `last4` SSNs are not HIPAA Safe Harbor de-identified, so `full` is the default.
**Columns that join must use the same mode** (they share one domain).

## 3. Input and output data types

Column-level options in the rules file:

```yaml
- {name: SSN, domain: ssn, expected_input_type: char(11), output_type: char(11)}
- {name: OwnerSSN, domain: ssn, output_format: digits}     # format-only; still matches SSN joins
- {name: MemberNo, domain: member_no, expected_input_type: bigint}
```

| Option | Meaning |
|---|---|
| `expected_input_type` | The type you expect in the source. `validate` fails (or warns, with `execution.type_mismatch: warn`) if the live column differs. This catches schema drift between servers. `discover`/`wizard` fill it in from the live schema. |
| `output_type` | Masked values must also fit this type, e.g. for downstream systems. Checked for every value during `dry-run`. |
| `output_format` | A rendering option for `ssn` and `credit_card`. It doesn't change the masked identity. |

**Recommendations.** `python main.py list-types` prints the accepted input types and recommended
output types for each mask type. `python main.py recommend --out rec.csv` profiles each target
column (sampled lengths, formats such as `999-99-9{4}`, digit share, leading zeros) and reports:

* the output length each masker needs, compared with the column (e.g. `email` needs `varchar(32)`);
* domains whose columns use different types or leading zeros, with the exact
  `normalize: digits, pad_to: N` to add;
* differing SSN formats, date columns that would benefit from `shift_by: entity`, and free-text
  risks.

## 4. Per-person date shifting

```yaml
person_dates: {type: date_shift, params: {shift_by: entity, max_days: 180}}
...
- {name: DateOfBirth, domain: person_dates, entity_column: CustomerId}   # Customers
- {name: AdmitDate,   domain: person_dates, entity_column: CustomerId}   # Visits
```

The offset is derived from the person id (`entity_column`), so all of one person's dates (in any
table, database or server) move by the same number of days. Ages, lengths of stay and the order of
events are preserved, while the actual dates are hidden. The tool reads the person id before
masking, in the same statement, even if that column is masked too. Rows with a NULL person id fall
back to the per-value shift. Time of day is kept.

## 5. Free text (notes, comments)

```yaml
notes:
  type: free_text
  params:
    mode: scrub              # scrub | redact (constant) | nullify | hash
    on_overflow: truncate    # or error, if scrubbed text no longer fits the column
    detectors:               # email, ssn, credit_card (Luhn-checked), phone, ip_address, date
      email: {action: mask, domain: email}   # hit -> same token as the Email columns
      ssn:   {action: mask, domain: ssn}     # hit -> same masked SSN as the SSN columns
      phone: {action: tag, tag: "[PHONE]"}
      date:  {action: remove}
    custom_patterns:
      - {name: mrn, regex: "MRN\\d{8}", action: tag, tag: "[MRN]"}
```

Regex scrubbing can't find names or PII written in prose (for example "lives next to the
bakery"). For high-risk text use `mode: redact` or `nullify`, and review a sample after `dry-run`.

## 6. Large tables (SQL Server 2022)

| Feature | Behaviour |
|---|---|
| `execution.batch_size: auto` | Per-table batch = `batching.target_batch_mb` (256 MB) ÷ the table's average row size (from catalog page counts), clamped to 10k–500k rows. `validate`/`recommend` show rows, MB, bytes/row, batch size and number of batches. |
| Chunked strategy | Uses key ranges of an unmasked single-column key. Each batch commits with a checkpoint; `--resume` continues from the last one. |
| Unique indexes on masked columns | Nonclustered unique indexes are **disabled** during the batched update and **rebuilt** afterwards, which re-validates uniqueness. This avoids transient duplicate-key errors without falling back to one huge transaction. |
| Single strategy | Used only when the PK itself is masked, a masked column is in a clustered/FK-referenced unique index, or there's no usable key. `recommend` estimates the log space needed. |
| `execution.workers: auto` | Masking runs in parallel processes (CPU count − 1, max 8) for tables over 100k rows. The results are identical to single-process masking. |
| DB readiness (`recommend`) | Checks the recovery model (recommends SIMPLE on the masking copy), **Accelerated Database Recovery** (recommended ON for SQL 2019/2022), free log space against the largest single-transaction table, and free tempdb space. |

Recommended setup on the masking copy before a large run:

```sql
ALTER DATABASE CURRENT SET RECOVERY SIMPLE;
ALTER DATABASE CURRENT SET ACCELERATED_DATABASE_RECOVERY = ON;
-- pre-grow the log if 'recommend' says the largest single-transaction table needs more than is free
```

Measured in testing: 300k rows / 107 MB, with 2 masked columns and 350k distinct values, took
35 s with 4 workers.

## 7. How the update works

1. Distinct values (or distinct (person, date) pairs) are read, grouped by
   `HASHBYTES('SHA2_256', …)`.
2. Each one is masked, validated against the column and the `output_type`, and collision-checked.
   The results go into the session temp table `#deid_map` as (column, hash, masked).
   **Original values are never stored anywhere.**
3. A set-based `UPDATE … LEFT JOIN #deid_map` runs per batch or as a single statement. FKs touching
   masked columns are set to `NOCHECK` and re-validated `WITH CHECK` at the end, and triggers are
   disabled and then re-enabled.
4. Safety checks:
   * `dry-run` writes nothing.
   * A run that has committed any data (status `PARTIAL`/`SUCCEEDED`) blocks a fresh run on the
     same database, because double masking would break consistency. Use `--resume <run_id>`.
   * ON UPDATE CASCADE FKs and IDENTITY/computed columns are rejected.

---

## 8. Step-by-step instructions

### Step 1: Prerequisites (one time per machine)
1. **ODBC Driver 18 for SQL Server** from Microsoft.
2. **ActiveState State Tool**. Windows PowerShell:
   `powershell -Command "& $([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://platform.activestate.com/dl/cli/install.ps1')))"`.
   Linux: `sh <(curl -q https://platform.activestate.com/dl/cli/install.sh)`. Then run `state auth`.
   These commands change between releases; check `state --help` if one fails.

### Step 2: ActiveState runtime
```bat
cd C:\work\Pythondeid
state init <your-org>/pythondeid --language python@3.11
state import requirements.txt          :: pyodbc, pyyaml, pytest
state shell                            :: older State Tool versions: state activate
python -c "import pyodbc, yaml; print('ok')"
```

Optional `activestate.yaml` script, so you can run `state run deid <command>`:
```yaml
scripts:
  - name: deid
    language: python3
    value: |
      import runpy, sys
      sys.argv = ["main.py"] + sys.argv[1:]
      runpy.run_path("main.py", run_name="__main__")
```

### Step 3: One secret key for all servers
```bat
python main.py genkey                  :: once, for the whole organisation; store in your vault
setx DEID_SECRET_KEY "<key>"           :: on every server / machine that masks
python main.py key-fingerprint         :: put the fingerprint in settings.yaml -> security.expected_key_fingerprint
```

### Step 4: Connection and masking policy (asks questions)
```bat
python main.py configure               :: connection -> connections.yaml, run settings -> settings.yaml, policy
python main.py test-connection
python main.py connections             :: list connections (* = default)
python main.py -c uat test-connection  :: use another named connection
python main.py policy                  :: change only the policy later
```
The password goes in the `DEID_DB_PASSWORD` environment variable, never in a file.
`db_owner` on the masking copy is simplest. Demo database:
`sqlcmd -S localhost -E -I -i sql\sample_schema.sql`.

### Step 5: Table structure and columns
Choose one:
* `python main.py wizard`. For each column it asks whether to mask it, the type and domain,
  **full or last 4**, **number vs. text storage** (normalisation), **per-person dates and the
  person-id column**, **free-text handling**, and the expected output type. It records the live
  type as `expected_input_type`.
* Spreadsheet: `python main.py discover`, fill `mask_type`/`domain`/`params_json`/`output_type`/
  `entity_column` in Excel, then `python main.py import-csv config\discovered_schema.csv`.
* Edit `config/deid_rules.yaml` directly; the sample is commented.

### Step 6: Recommendations (types, formats, batch sizes, DB readiness)
```bat
python main.py recommend --out recommendations.csv
```
Apply the advice: add `normalize/pad_to`, widen or set `output_type`, switch the copy to SIMPLE
recovery, enable ADR, pre-grow the log.

### Step 7: Validate and dry run
```bat
python main.py validate                :: schema, FK domains, types, strategy, batch sizes
python main.py dry-run                 :: masks and checks every value, writes nothing
python main.py preview --domain ssn 123-45-6789           :: spot-check algorithms offline
python main.py preview --domain person_dates --entity 42 1980-04-12
```

### Step 8: Run on a backed-up, non-production copy
```bat
python main.py run                     :: confirmations: backup, passing dry-run, type DB name
python main.py run --resume <run_id>   :: after fixing a PARTIAL run
```

### Step 9: Other databases and servers
On each additional server: use the same key, `settings.yaml` (with the pinned fingerprint) and
`deid_rules.yaml`, then:
```bat
python main.py test-vectors --check config\test_vectors.csv   :: proves identical masking here
python main.py validate                                        :: expected_input_type catches schema drift
python main.py dry-run
python main.py run
```
Create `config/test_vectors.csv` once on the first server with `python main.py test-vectors`.

### Step 10: Audit and verification
```bat
python main.py audit-report
python main.py audit-report --run-id <run_id>
```
```sql
SELECT * FROM deid_audit.run ORDER BY started_at DESC;          -- key fingerprint, algorithm version, status
SELECT * FROM deid_audit.column_result WHERE run_id = '<run_id>'; -- per column: rows, distinct before/after, batch size
SELECT * FROM deid_audit.event WHERE run_id = '<run_id>' ORDER BY id;  -- FK/index/trigger actions, warnings
```
Re-run the integrity query at the end of `sql/sample_schema.sql` (or your own) and compare it with
the counts from before masking.

---

## 9. Project layout

```
main.py                    CLI: genkey, key-fingerprint, configure, test-connection, discover, import-csv,
                           wizard, recommend, validate, dry-run, run, audit-report, preview, list-types,
                           test-vectors
config/connections.yaml    database connections for this machine (not in Git; see connections.example.yaml)
config/paths.yaml          file and folder locations (rules file, audit, logs, CSVs)
config/settings.yaml       security (key fingerprint), execution, batching, audit, logging level
config/deid_rules.yaml     algorithm_version, domains, tables/columns (+ type/format/entity options)
deid/config.py             YAML/CSV loading and validation
deid/maskers.py            masking algorithms, key derivation, free-text scrubber, registry
deid/fpe.py                Feistel format-preserving encryption
deid/engine.py             planner (integrity, types, strategy, batch size) + executor
deid/advisor.py            type guide, batch sizing, DB readiness, column profiling
deid/parallel.py           multi-process masking
deid/schema.py             catalog: columns, keys, unique indexes, FKs, sizes, type parsing
deid/audit.py              DB + file audit trail, checkpoints
deid/db.py                 pyodbc connections, quoting, retries
deid/discovery.py          PII heuristics, CSV export, interactive wizard
deid/prompts.py            console questions
sql/sample_schema.sql      demo DB: cross-table PII, bigint/varchar ids, visits with notes
tests/                     unit tests + opt-in live SQL Server tests (DEID_IT_SERVER)
```

## 10. Tests

```bat
python -m pytest -q
set DEID_IT_SERVER=localhost & set DEID_IT_PASSWORD=... & python -m pytest -q   :: + live end-to-end tests
```

The live tests mask the demo database and check that all integrity counts (joins, member-number
matches across bigint/varchar, stay lengths, ages) are unchanged. They also mask **two independent
databases** and assert that every masked value is identical.

## 11. Limitations

* Requires SQL Server 2016 or later (built and tested on 2022). Masked values over 4000
  characters aren't supported.
* Changing a domain's name, type or identity parameters (e.g. `mode`) changes its masks. Keep the
  rules file under version control and identical on every server.
* Regex free-text scrubbing doesn't detect names or other PII written in prose.
* A masked primary key (or a masked column in a clustered/FK-referenced unique index) forces a
  single-transaction update for that table. Size the log accordingly; `recommend` estimates it.
