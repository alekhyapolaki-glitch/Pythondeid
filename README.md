# pythondeid: SQL Server de-identification with referential integrity

A Python tool, built to run on an **ActiveState** Python runtime, that masks PII in a SQL Server
database **in place**. The same original value always gets the same masked value in every table,
so joins and foreign keys keep working after masking.

| Requirement | Where it lives |
|---|---|
| 1. Table structure and fields as input | `discover` writes the live schema to CSV. Rules go in `config/deid_rules.yaml` (or `import-csv`). |
| 2. Columns to de-identify | `config/deid_rules.yaml`: table → column → *domain* |
| 3. Same masking across tables | Deterministic keyed algorithms per *domain* (`deid/maskers.py`, `deid/fpe.py`) |
| 4. Update the data in SQL Server | `deid/engine.py`: set-based, batched, resumable updates |
| 5. Ask questions | `configure`, `wizard`, and the confirmation prompts before `run` |
| 6. Separate config and reusable utilities | `config/*.yaml` + `deid/` package (db, schema, maskers, audit, prompts) |
| 7. Audit results | `deid_audit.*` tables in the DB, plus `audit/<run_id>/` files |

---

## 1. How the masking keeps referential integrity

**Domains.** A domain is a named masking definition, for example `email`, `ssn` or
`account_number`. Every column that holds the same kind of identifier is assigned to the same
domain. That applies across tables too, e.g. `Customers.SSN` and `Accounts.OwnerSSN`.

**Deterministic keyed masking.** Each domain gets its own key, derived as
`domain_key = HMAC-SHA256(master_secret, domain_name)`. The masked value is a pure function of
`(domain_key, normalised original value)`, which means:

* the same value gives the same mask in every table, every batch, every run, and every database
  masked with the same secret (so separately masked copies still line up);
* the mask can't be reversed without the secret, and changing the secret changes every mask;
* domains are independent: the same text in two different domains masks differently.

**Algorithms**

| Type | Algorithm | Unique / FK-safe |
|---|---|---|
| `ssn` | Format-preserving encryption (FPE) on the 9 digits, using an FF1-style Feistel network over radix 10. *Cycle-walking* keeps valid SSNs inside the valid SSA ranges (area ≠ 000/666/9xx, group ≠ 00, serial ≠ 0000). `123-45-6789` and `123456789` mask to the same digits, and the original format is kept. | ✅ bijective |
| `account_number`, `fpe` | FPE on letters (radix 26, case kept) and digits (radix 10). Separators and length stay the same. Optional `preserve_first` / `preserve_last`, with the kept characters bound into the tweak. | ✅ bijective |
| `credit_card` | FPE on the digit body plus a recomputed **Luhn** check digit. Optional BIN (`preserve_first: 6`) or last-4. | ✅ (collision-checked) |
| `phone` | FPE on digits only. Punctuation is kept. | ✅ bijective |
| `email` | `user<base32(HMAC(lowercased email))>@example.com`. Case-insensitive, so `John@X.com` = `john@x.com`. | ✅ (collision-checked) |
| `hash` | HMAC-SHA256 hex token | ✅ (collision-checked) |
| `first_name`, `last_name`, `full_name`, `street_address`, `city` | HMAC-indexed pick from built-in lists. Case style is kept. | ❌ realistic, not unique |
| `zip` | `truncate` keeps the first 3 digits (HIPAA style); `fpe` is bijective | truncate ❌ / fpe ✅ |
| `date_shift` | Deterministic ±N-day shift derived from the date, or generalise to year/month | ❌ |
| `redact`, `nullify` | Constant / NULL | ❌ |

"Bijective" means it's mathematically impossible for two different inputs to produce the same
output, which is why these types are safe for primary keys and unique columns. The planner
**rejects** a non-unique type on a PK or unique column.

**How the database update works**

1. Distinct values are read per column, grouped by `HASHBYTES('SHA2_256', value)`, so
   case-only and trailing-space variants are never merged.
2. Python masks each distinct value and checks that the result fits the column (length, int
   range, decimal precision, NOT NULL, date range). It also detects collisions. It then loads
   `(column, sha256(original), masked)` into the session temp table `#deid_map`.
   **Original values are never written anywhere.**
3. A set-based `UPDATE t ... LEFT JOIN #deid_map` rewrites the table:
   * **chunked**: uses ranges of an unmasked single-column key, committing each chunk together
     with an atomic checkpoint. These runs can be resumed.
   * **single**: one transaction. Used when the key itself is masked, a masked column is unique,
     or there is no usable key. This avoids transient duplicate-key errors and double masking.
4. Foreign keys that touch masked columns are set to `NOCHECK` first and re-validated
   `WITH CHECK` at the end. The run also confirms the FKs are trusted again.

**Built-in safety checks**

* Both columns of every FK must use the same domain. With `auto_include_fk_columns` on (the
  default), the partner column is added automatically.
* `ON UPDATE CASCADE` FKs on masked columns are rejected, because cascading would double-mask.
* IDENTITY and computed columns are rejected.
* A rules set that was already applied can't be re-run without `--force`, because masking masked
  data again breaks consistency. Interrupted runs continue with `--resume <run_id>`.
* Enabled triggers are disabled for the update and re-enabled afterwards.
* Deadlocks are retried with backoff.
* `dry-run` does the full masking in memory, validates every value, and **writes nothing to the
  database**.

---

## 2. Step-by-step instructions

### Step 1: Install the prerequisites (one time)

1. **Microsoft ODBC Driver 18 for SQL Server** (or 17). On Windows, download it from Microsoft
   ("Download ODBC Driver for SQL Server"). Check that it's installed:
   `Get-OdbcDriver -Name "*SQL Server*"` (PowerShell).
2. **ActiveState State Tool**
   * Windows (PowerShell):
     `powershell -Command "& $([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://platform.activestate.com/dl/cli/install.ps1')))"`
   * Linux/macOS: `sh <(curl -q https://platform.activestate.com/dl/cli/install.sh)`
   * Then open a new terminal and run `state auth` to log in.
   * These commands change between State Tool releases; check `state --help` if one fails.

### Step 2: Create the ActiveState Python runtime for this project

```bat
cd C:\work\Pythondeid
state init <your-org>/pythondeid --language python@3.11
state install pyodbc
state install pyyaml
state install pytest
:: or, in one go:  state import requirements.txt
state shell
```

`state shell` (named `state activate` in older releases) opens a shell that uses the project's
ActiveState Python. Check it with `python -c "import pyodbc, yaml; print('ok')"`.

Optional: append this to the generated `activestate.yaml` so you can run `state run deid <command>`:

```yaml
scripts:
  - name: deid
    language: python3
    description: pythondeid CLI
    value: |
      import runpy, sys
      sys.argv = ["main.py"] + sys.argv[1:]
      runpy.run_path("main.py", run_name="__main__")
```

### Step 3: Create the masking secret (one time per organisation)

```bat
python main.py genkey
setx DEID_SECRET_KEY "<the key printed above>"
```

Store the key in your vault. **Use the same key for every run and every database** that has to
stay consistent. If the key is lost, masks can't be reproduced. If it leaks, someone could test
guesses against the masks. Audit records keep only a non-reversible key fingerprint.

### Step 4: Configure the connection (answers questions)

```bat
python main.py configure
python main.py test-connection
```

This writes `config/settings.yaml`. Windows authentication is the default. For SQL
authentication, put the password in an environment variable (`set DEID_DB_PASSWORD=...`). It is
never stored in a file.

The login needs permission to `SELECT`/`UPDATE` the target tables and `ALTER` them (to toggle
FKs and triggers). It also needs `CREATE SCHEMA`/`CREATE TABLE` for the audit schema; `db_owner`
on the masking copy is simplest.

*Optional demo database:* `sqlcmd -S localhost -E -I -i sql\sample_schema.sql`

### Step 5: Supply the table structure and choose the columns

Pick one of these:

* **A. Interactive wizard (asks questions):** `python main.py wizard`. It lists the schemas and
  tables, shows each table's columns with types, PK flags and a suggested mask type. For each
  column it asks whether to mask it, which type to use, which domain, and any parameters. It then
  writes `config/deid_rules.yaml`.
* **B. Spreadsheet:**
  ```bat
  python main.py discover --out config\discovered_schema.csv
  :: open in Excel: fill mask_type (and domain / params_json where needed), save as CSV
  python main.py import-csv config\discovered_schema.csv
  ```
* **C. Edit `config/deid_rules.yaml` directly.** It is commented and lists the mask types
  (`python main.py list-types`).

Rule of thumb: **columns that join to each other must use the same domain name.**

### Step 6: Preview the algorithms (no database needed)

```bat
python main.py preview --domain ssn 123-45-6789 123456789
python main.py preview --type email John.Doe@Mail.com john.doe@mail.com
python main.py preview --type account_number --params "{\"preserve_last\": 4}" ACC-0001234567
```

### Step 7: Validate the plan against the live schema

```bat
python main.py validate
```

This shows every table, column, domain, update strategy and affected FK. It reports errors such
as missing columns, an FK whose partner column isn't masked, a domain mismatch, a non-unique
masker on a key, or IDENTITY/computed columns.

### Step 8: Dry run (changes nothing)

```bat
python main.py dry-run
```

This masks every distinct value in memory and validates it against the target column. Results go
to `audit/<run_id>/`. Fix anything it reports, for example an email token that's too long for a
`varchar(20)`: lower `token_length` or use a shorter `domain`.

### Step 9: Back up, then run

1. **Run this only on a restored non-production copy**, and take a backup first.
2. Optionally record integrity counts first (see the query at the end of `sql/sample_schema.sql`).
3. Run:
   ```bat
   python main.py run
   ```
   It asks you to confirm it's a non-production copy with a backup, checks that a passing dry-run
   exists, and asks you to type the database name. Use `-y` for unattended runs.
4. If it stops partway (`PARTIAL`): fix the cause, then run `python main.py run --resume <run_id>`.
   Completed tables are skipped and chunked tables continue from their checkpoint. FKs stay
   disabled until every table is done.

### Step 10: Verify and review the audit

```bat
python main.py audit-report
python main.py audit-report --run-id <run_id>
```

```sql
SELECT * FROM deid_audit.run ORDER BY started_at DESC;
SELECT * FROM deid_audit.column_result WHERE run_id = '<run_id>';
SELECT * FROM deid_audit.event WHERE run_id = '<run_id>' ORDER BY id;
```

The integrity join counts should match the pre-masking counts. For bijective types,
`distinct_before` should equal `distinct_after`.

---

## 3. Project layout

```
main.py                    CLI (genkey, configure, test-connection, discover, import-csv, wizard,
                           validate, dry-run, run, audit-report, preview, list-types)
config/settings.yaml       connection / execution / audit / logging (no secrets)
config/deid_rules.yaml     domains + tables/columns to mask
deid/config.py             YAML/CSV loading and validation
deid/db.py                 pyodbc connection factory, identifier quoting, retry helper
deid/schema.py             catalog introspection: columns, PKs, unique indexes, FKs, triggers
deid/fpe.py                Feistel format-preserving encryption
deid/maskers.py            masking algorithms + key derivation + registry
deid/engine.py             planner (integrity checks, strategy) + executor
deid/audit.py              DB + file audit trail, checkpoints
deid/discovery.py          PII column heuristics, CSV export, interactive wizard
deid/prompts.py            console question helpers
deid/logging_setup.py      console + rotating file logs (logs/deid.log)
sql/sample_schema.sql      demo database with cross-table PII
tests/                     unit tests + opt-in live SQL Server test
```

Adding a mask type: subclass `BaseMasker` in `deid/maskers.py`, set `type_name`,
`default_params`, `families` and `injective`, implement `_mask`, and add it to `MASKERS`.

## 4. Tests

```bat
python -m pytest -q
```

The end-to-end test runs against a real SQL Server and is skipped unless `DEID_IT_SERVER` is set.
See `tests/test_integration_sqlserver.py`; a Docker `mssql/server:2022` container works.

## 5. Limitations

* Requires SQL Server 2016 or later (`HASHBYTES` over `NVARCHAR(MAX)`). Values that mask to more
  than 4000 characters aren't supported.
* Consistency depends on the value's text form. `'00123'` in a varchar and `123` in an int are
  different inputs; `ssn` pads integers to 9 digits to handle the common case.
* `date_shift` shifts each distinct date on its own, so intervals between two dates of the same
  person aren't preserved. Use `generalize: year` if that matters.
* Free-text columns (notes, comments) can contain embedded PII. Use `redact`/`nullify` for them;
  masking can't find PII inside prose.
* `float`/`real`, binary, XML and spatial columns support `nullify` only.
* Single-strategy tables are updated in one transaction, so size the transaction log (or use
  SIMPLE recovery on the copy).
