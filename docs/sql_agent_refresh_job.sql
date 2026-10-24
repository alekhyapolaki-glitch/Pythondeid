/* ---------------------------------------------------------------------------
   SQL Server Agent job: restore (your existing step) + pythondeid refresh.
   Alternative to Stonebranch. Review every <PLACEHOLDER> before running.
   The CmdExec step runs ON THIS SQL SERVER: ODBC Driver 18 + ActiveState runtime must be installed here.
--------------------------------------------------------------------------- */
USE msdb;
GO
DECLARE @job NVARCHAR(128) = N'pythondeid refresh - <PROFILE> - <DATABASE>';

IF EXISTS (SELECT 1 FROM dbo.sysjobs WHERE name = @job) EXEC dbo.sp_delete_job @job_name = @job;
EXEC dbo.sp_add_job @job_name = @job, @description = N'Restore masking copy, then de-identify with pythondeid';

-- Step 1: restore (replace with your DBA's restore step / script)
EXEC dbo.sp_add_jobstep @job_name = @job, @step_name = N'Restore masking copy', @subsystem = N'TSQL',
     @database_name = N'master',
     @command = N'/* RESTORE DATABASE [<DATABASE>] FROM DISK = N''<BACKUP_PATH>'' WITH REPLACE, MOVE ... */',
     @on_success_action = 3,   -- go to next step
     @on_fail_action = 2;      -- quit with failure

-- Step 2: mask (exit code 0 = success; anything else fails the job)
EXEC dbo.sp_add_jobstep @job_name = @job, @step_name = N'pythondeid refresh', @subsystem = N'CmdExec',
     @command = N'cmd /c "set DEID_PYTHON=<ACTIVESTATE_PYTHON_EXE>&& <PROJECT_FOLDER>\scripts\deid_refresh.cmd <PROFILE> <CONNECTION>"',
     @cmdexec_success_code = 0,
     @proxy_name = N'<PROXY_NAME>',   -- proxy whose credential has db_owner on the masking copy
     @retry_attempts = 0,
     @on_success_action = 1, @on_fail_action = 2;
-- DEID_SECRET_KEY: set it as a user environment variable of the proxy's Windows account (setx), or load it
-- from your vault in a wrapper script. Never put the key in this job definition.

EXEC dbo.sp_add_jobserver @job_name = @job;
GO
