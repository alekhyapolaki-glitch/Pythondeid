# Security

This document describes how pythondeid protects data, what it relies on, and the controls an
operator must put in place. Review it before a production run.

## What the tool does with sensitive data

| Data | Where it goes | Never goes to |
|---|---|---|
| Original values (database) | Read over the ODBC connection into process memory, masked, discarded | Disk, temp tables, logs, audit, error messages |
| Original values (files) | Streamed from the input file, masked in memory | Output files, logs, audit, error messages |
| Masked values | The target table, or the `<name>_deid` output file | — |
| Value maps | `#deid_map` in tempdb: **SHA-256 of the original** + masked value, per session, dropped afterwards | Permanent tables |
| Secret key | Environment variable `DEID_SECRET_KEY`, process memory, worker processes (via OS pipes) | Config files, logs, audit (only a non-reversible fingerprint) |
| DB password (SQL auth) | Environment variable named by `password_env`, the ODBC connection string in memory | Config files, logs |

Regression tests in `tests/test_security.py` check that error messages and audit files never
contain input values.

## Cryptography

* **Keys:** one key per domain, derived with HMAC-SHA256(master secret, domain name).
* **Tokens:** emails, hashes, names, addresses and date offsets are derived with HMAC-SHA256.
* **Format-preserving masking:** SSNs, account numbers, phones and cards use a balanced Feistel
  network with HMAC-SHA256 round functions and 10 rounds, modelled on NIST FF1. It is a bijection
  (no collisions), which keeps keys and joins intact. It is **not** a NIST-validated FF1
  implementation and is used for masking, not for encrypting data that has to be decrypted.
* **Determinism is by design:** the same input always gives the same output, which is what keeps
  referential integrity. As a result:
  * Anyone with access to masked data can see that two records share a value (frequency/linkage),
    but not what the value is.
  * Anyone who gets **both the secret key and the rules** can test guesses. Fields with small
    value spaces (SSN, phone, ZIP) can be brute-forced with the key. **Protect the key like a
    production credential.**
* Changing the key or the rules changes every masked value. Pin the key with
  `security.expected_key_fingerprint` and the algorithm with `algorithm_version`.

## Profiles and linkage

* **Same key for internal and external profiles (current decision).** Values masked the same way
  in both profiles are identical. For example, a customer's masked email or SSN in a vendor file
  equals the one in the internal QA copy. A vendor that also obtained internal masked data could link
  the two. To prevent that, give the external profile its own key: run external refreshes with a
  different `DEID_SECRET_KEY` and pinned fingerprint.
* **HIPAA Safe Harbor (external profile).**
  * Dates tied to a person keep only the year.
  * Birth dates of people aged 90+ are grouped.
  * ZIP codes keep 3 digits, and HHS-listed low-population ZIP3 areas become `000`.
  * Free text is redacted.
  * Safe Harbor also requires removing the other identifiers (names, contact details, account and
    record numbers, etc.), so make sure every such column is in the rules, and that there is no
    actual knowledge that the remaining data could identify a person. Have your privacy officer
    review the rules.
* **Run lock:** one masking run per database at a time (`sp_getapplock`).

## Input safety

* **SQL:**
  * Every data value is sent as a `?` parameter.
  * Identifiers (schema, table, column, index and trigger names) come from SQL Server's own
    catalog or the validated config, and only enter SQL through `quote_ident()` (`deid/database/sql.py`). That function
    bracket-quotes, escapes `]`, and rejects empty, NUL-containing or over-128-character names.
  * Catalog queries are fully static.
  * Bandit's B608 findings were reviewed one by one and are marked `# nosec B608` on those lines.
* **YAML:** `yaml.safe_load` only, so no object construction.
* **Connection strings:**
  * Values containing separators are brace-quoted.
  * Extra ODBC keywords are allow-listed by pattern and can't override `DRIVER`, `UID` or `PWD`.
* **Excel:**
  * `defusedxml` is required, which blocks XML entity-expansion ("billion laughs") attacks;
    without it, Excel processing refuses to run.
  * Inputs over `max_file_mb` are rejected.
  * Formula cells are never evaluated or modified.
* **CSV:** files are streamed, with a configurable field-size limit (`csv.max_field_kb`).
* **Output files:**
  * Written to a temporary `.part` file and atomically renamed.
  * An output can never replace its input.
  * Existing outputs are only replaced with `--overwrite`.
* **Regular expressions:** the built-in free-text detectors have bounded repetition. Custom
  patterns in `free_text.custom_patterns` are trusted configuration; review them for catastrophic
  backtracking.

## Database safety

* Runs refuse to start until a `validate` plan is clean. A completed or partially applied rules
  set can't be run again without `--force`, because double masking breaks consistency.
* Foreign keys touching masked columns are re-validated `WITH CHECK` after the run; disabled
  unique indexes are rebuilt, which re-checks uniqueness.
* Each batch commits together with its checkpoint, so `--resume` continues without masking any
  row twice. Any committed change marks the run `PARTIAL`, never `FAILED`.

### On-the-fly masking

* The source is only read; nothing is written to it (not even audit tables). Only the target is
  changed, so the target connection must point at a non-production database: `run` shows both and
  asks for the target database name as confirmation.
* Unmasked values never reach the target: masked columns are taken from the mask map, and a value
  missing from it fails the statement instead of being copied. Streamed rows are masked by the
  source session, so original values of masked columns don't cross the network to the target.
* Refused before anything is written: target equals the source table, NOT NULL target columns that
  nothing writes, target tables that aren't copied but reference a reloaded table and have rows.
* After a complete load the target's FKs are validated `WITH CHECK` and its indexes rebuilt. After a
  failed load the FKs are re-enabled without validation (untrusted); a re-run or `--resume`
  validates them.

## Operator checklist (production)

1. Run only against a **restored, non-production copy**, with a verified backup.
2. **Least privilege:** use a dedicated login with `db_owner` on the masking copy only (it needs
   ALTER for FKs, triggers and indexes, and to create the `deid_audit` schema), and no access to
   production.
3. Store `DEID_SECRET_KEY` in an enterprise vault and inject it at run time. Don't type it into
   shared terminals, and don't put it in scripts, tickets or chat. Pin its fingerprint in
   `settings.yaml`.
4. Restrict NTFS permissions on the project folder, `audit\`, `logs\` and `data\` to the people who
   run masking. They hold no original values, but they describe the data estate.
5. Keep `config/connections.yaml` and `data/` out of source control (both are in `.gitignore`).
6. Use `encrypt: true`. Prefer `trust_server_certificate: false` with a trusted server certificate
   where your PKI allows it.
7. After each run, review `validate`/`audit-report` and the integrity queries, and spot-check
   free-text columns (regex can't find names or PII written in prose).
8. Keep dependencies patched: run `pip-audit -r requirements.txt` regularly; CI runs it on every push.

## Scans

```bash
pip install -r requirements-dev.txt
ruff check deid main.py tests        # lint and bug patterns
bandit -r deid main.py -q            # static security analysis
pip-audit -r requirements.txt        # known CVEs in dependencies
python -m pytest                      # unit + security regression tests
```

Results at the time of this review are in the README ("Quality and security status").

## Reporting

Report suspected vulnerabilities privately to the repository owner rather than in a public issue.
