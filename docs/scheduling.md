# Scheduled refresh (Stonebranch primary, SQL Server Agent alternative)

A refresh masks a freshly restored copy of production, unattended:

```
[1] Restore prod backup to the masking copy   (DBA's existing task - separate step)
[2] pythondeid refresh --profile <internal|external>   (validate -> dry-run -> mask [-> files])
[3] Extracts / delivery to vendors            (Stonebranch tasks; run ONLY if [2] exited with 0)
```

**On-the-fly variant** (`execution.mode: on_the_fly`, target in `config/copy_map.yaml`):

```
[1] Restore prod backup (or create a database snapshot) as the SOURCE   (separate step)
[2] pythondeid --mode on_the_fly refresh --profile <internal|external>  (source read, target reloaded)
[3] Extracts / delivery                                                (only if [2] exited with 0)
```

The source is never changed, so the ALREADY_MASKED check (exit 3) does not apply: every refresh
empties and reloads the target. LOCKED (exit 7) refers to the target database.

`refresh` never prompts. It reports its outcome as an **exit code**, a final stdout line
`DEID_RESULT status=... exit_code=... run_id=... result_file=...`, and a **JSON result file**
(`run_results_dir` in `paths.yaml`, plus `latest_<profile>.json`).

## Exit codes

| Code | Status | Meaning | Scheduler action |
|---|---|---|---|
| 0 | SUCCEEDED | Database (and files, with `--with-files`) de-identified | Continue to extracts/delivery |
| 2 | INVALID | Rules/plan or dry-run found problems; **nothing changed** | Fail; fix config (see message) |
| 3 | ALREADY_MASKED | This copy was masked before; the restore probably didn't run | Fail; check step [1] |
| 4 | PARTIAL | Some tables masked; FKs left disabled until finished | Fail and alert; after fixing, rerun with `--resume <resume_run_id>` from the result file |
| 5 | FAILED | Failed before any data was committed | Fail; safe to rerun |
| 6 | FILES_FAILED | Database OK, one or more files failed | Fail the file branch only |
| 7 | LOCKED | Another masking run is active on this database | **Retry** later (e.g. 3 x every 10 min) |
| 10 | CONFIG_ERROR | Bad profile/rules/settings, missing key, or key doesn't match the pinned fingerprint | Fail; fix config |
| 11 | CONNECTION_ERROR | Can't connect to SQL Server | Retry, then fail |
| 1 | UNEXPECTED | Unexpected error; see `logs\deid.log` | Fail |

**Never run extracts unless step [2] returned 0.** The result file's `"status": "SUCCEEDED"`
together with the expected `"profile"` is the gate for vendor deliveries.

## Masking server setup (once)

1. Install ODBC Driver 18 and the ActiveState State Tool. In the project folder run
   `state checkout WTFC/python-dm-deid .` and then `state pull`.
2. Note the runtime's `python.exe`. It's the folder printed by `state checkout` ("executables at …").
   Set it as `DEID_PYTHON` on the task.
3. Service account (Windows authentication) needs `db_owner` on the masking copy **only**. It
   needs read access to the project folder and write access to `audit\`, `logs\` and
   `data\output\`.
4. `config\connections.yaml` on this server: one connection per masking copy (e.g. `uat`, `qa`).
5. Check the key once: `python main.py test-vectors --check config\test_vectors.csv`.

## Stonebranch (Universal Automation Center)

**Task: "DEID refresh – external"** (Windows task):

| Field | Value |
|---|---|
| Agent | the masking server |
| Credentials | service account with `db_owner` on the masking copy (Windows auth) |
| Runtime directory | `D:\pythondeid` (project folder) |
| Command | `scripts\deid_refresh.cmd external uat --with-files` |
| Environment variables | `DEID_PYTHON=<ActiveState python.exe>`; `DEID_SECRET_KEY` from a Stonebranch credential (e.g. its password field via the credential functions your Universal Controller version provides), never typed in plain text |
| Exit code processing | Success exit code range: `0` |
| Retry | Retry exit codes `7,11`; max 3 retries; 10-minute interval |
| Output | Capture STDOUT/STDERR; attach to the task instance (contains no data values) |
| Notifications | On failure: notify the data-platform team, including the `DEID_RESULT`/`DEID_MESSAGE` lines |

**Workflow:** `Restore (DBA)` → `DEID refresh` → `Extract/encrypt/deliver` (Stonebranch). Each step
depends on the previous one succeeding. Use the same pattern with `internal` for DEV/QA refreshes
(usually without `--with-files`).

## SQL Server Agent (alternative)

Agent's CmdExec step runs **on the SQL Server machine**, so ODBC Driver 18 and the ActiveState
runtime must be installed there. Use a proxy account for the CmdExec step. See
`docs/sql_agent_refresh_job.sql`.

## Resuming a PARTIAL run

The result file contains `"resume_run_id"`. After fixing the cause shown in `message`:

```
scripts\deid_refresh.cmd external uat --resume <resume_run_id>
```

Completed tables are skipped and batched tables continue from their checkpoint, so no row is
masked twice.
