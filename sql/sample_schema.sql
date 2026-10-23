/* ---------------------------------------------------------------------------
   Demo database for pythondeid.  Run in SSMS / sqlcmd:
       sqlcmd -S localhost -E -I -i sql\sample_schema.sql
   Creates DeidDemo with related tables that share emails, SSNs and account
   numbers so you can see referential integrity preserved after masking.
--------------------------------------------------------------------------- */
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO
IF DB_ID(N'DeidDemo') IS NULL CREATE DATABASE DeidDemo;
GO
USE DeidDemo;
GO
IF OBJECT_ID(N'dbo.Transactions') IS NOT NULL DROP TABLE dbo.Transactions;
IF OBJECT_ID(N'dbo.Accounts') IS NOT NULL DROP TABLE dbo.Accounts;
IF OBJECT_ID(N'dbo.Customers') IS NOT NULL DROP TABLE dbo.Customers;
IF OBJECT_ID(N'dbo.MarketingContacts') IS NOT NULL DROP TABLE dbo.MarketingContacts;
GO
CREATE TABLE dbo.Customers (
    CustomerId   INT IDENTITY(1,1) CONSTRAINT PK_Customers PRIMARY KEY,
    FirstName    NVARCHAR(50)  NOT NULL,
    LastName     NVARCHAR(50)  NOT NULL,
    Email        VARCHAR(100)  NULL,
    SSN          CHAR(11)      NULL,
    Phone        VARCHAR(20)   NULL,
    Street       NVARCHAR(100) NULL,
    City         NVARCHAR(50)  NULL,
    Zip          VARCHAR(10)   NULL,
    DateOfBirth  DATE          NULL,
    CreatedAt    DATETIME2(0)  NOT NULL CONSTRAINT DF_Customers_CreatedAt DEFAULT SYSUTCDATETIME()
);
CREATE UNIQUE INDEX UX_Customers_SSN ON dbo.Customers (SSN) WHERE SSN IS NOT NULL;

CREATE TABLE dbo.Accounts (
    AccountNumber VARCHAR(20) NOT NULL CONSTRAINT PK_Accounts PRIMARY KEY,
    CustomerId    INT         NOT NULL CONSTRAINT FK_Accounts_Customers REFERENCES dbo.Customers (CustomerId),
    OwnerSSN      VARCHAR(11) NULL,
    CardNumber    VARCHAR(19) NULL,
    Balance       MONEY       NOT NULL DEFAULT 0
);

CREATE TABLE dbo.Transactions (
    TxnId         BIGINT IDENTITY(1,1) CONSTRAINT PK_Transactions PRIMARY KEY,
    AccountNumber VARCHAR(20)   NOT NULL CONSTRAINT FK_Transactions_Accounts REFERENCES dbo.Accounts (AccountNumber),
    Amount        DECIMAL(12,2) NOT NULL,
    NotifyEmail   VARCHAR(100)  NULL,
    TxnDate       DATETIME      NOT NULL
);

CREATE TABLE dbo.MarketingContacts (      -- deliberately a heap with no key
    Email  VARCHAR(100)  NULL,
    Notes  NVARCHAR(400) NULL
);
GO
INSERT dbo.Customers (FirstName, LastName, Email, SSN, Phone, Street, City, Zip, DateOfBirth) VALUES
 (N'John',  N'Doe',     'John.Doe@Mail.com',   '123-45-6789', '(555) 123-4567', N'12 High St',   N'Boston',  '02118',      '1980-04-12'),
 (N'Jane',  N'Smith',   'jane.smith@corp.org', '587-65-4321', '555-987-6543',   N'99 Elm Ave',   N'Denver',  '80202-1234', '1975-11-30'),
 (N'Ravi',  N'Kumar',   'ravi.k@mail.com',     '219-09-9999', '+1 555 222 3333', N'7 Oak Rd',    N'Austin',  '73301',      '1990-01-01'),
 (N'MARIA', N'GARCIA',  NULL,                  NULL,          NULL,             NULL,            NULL,       NULL,         NULL);

INSERT dbo.Accounts (AccountNumber, CustomerId, OwnerSSN, CardNumber, Balance) VALUES
 ('ACC-000123-01', 1, '123456789',   '4111111111111111', 1500.25),
 ('ACC-000123-02', 1, '123-45-6789', '5500000000000004',   20.00),
 ('ACC-778899-01', 2, '587-65-4321', '340000000000009',  9876.54),
 ('ACC-445566-01', 3, '219-09-9999', NULL,                  0.00);

INSERT dbo.Transactions (AccountNumber, Amount, NotifyEmail, TxnDate) VALUES
 ('ACC-000123-01',  100.00, 'john.doe@mail.com',   '2024-01-05T10:15:00'),
 ('ACC-000123-01',  -25.50, 'JOHN.DOE@MAIL.COM',   '2024-01-06T09:00:00'),
 ('ACC-000123-02',   20.00, 'john.doe@mail.com',   '2024-02-01T12:00:00'),
 ('ACC-778899-01', 5000.00, 'jane.smith@corp.org', '2024-03-10T08:30:00'),
 ('ACC-445566-01',   12.34, NULL,                  '2024-03-11T17:45:00');

INSERT dbo.MarketingContacts (Email, Notes) VALUES
 ('jane.smith@corp.org', N'Called 3/4, prefers email'),
 ('ravi.k@mail.com',     N'VIP - SSN on file 219-09-9999'),
 ('jane.smith@corp.org', NULL);
GO

/* --- Referential-integrity check: run BEFORE and AFTER masking; counts must match --- */
SELECT
  (SELECT COUNT(*) FROM dbo.Transactions t JOIN dbo.Accounts a ON a.AccountNumber = t.AccountNumber) AS txn_account_joins,
  (SELECT COUNT(*) FROM dbo.Accounts a JOIN dbo.Customers c ON REPLACE(a.OwnerSSN,'-','') = REPLACE(c.SSN,'-','')) AS ssn_joins,
  (SELECT COUNT(*) FROM dbo.Transactions t JOIN dbo.Customers c ON t.NotifyEmail = c.Email) AS email_joins,
  (SELECT COUNT(*) FROM dbo.MarketingContacts m JOIN dbo.Customers c ON m.Email = c.Email) AS marketing_joins;
GO
