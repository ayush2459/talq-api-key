# Isolated partner-onboarding test environment

## Why this exists

The configured `DATABASE_URL` currently points to the shared production Neon database. Do not use that database for partner onboarding test records.

This local test launcher starts separate admin and partner API processes using a dedicated SQLite file:

- Database: `flowsense_talq_test.db`
- Admin API: `http://127.0.0.1:8011`
- Partner API: `http://127.0.0.1:8017`
- Bind address: loopback only (`127.0.0.1`)

It does not create, modify, or connect to a new Neon database. GitHub can store this setup and run CI, but it cannot provision a database inside your Neon account without Neon access.

## Start on Windows PowerShell

From the repository root, after installing the project requirements into `.venv`:

```powershell
.\scripts\run_isolated_test.ps1
```

The launcher sets `APP_ENV=testing`, `DEMO_MODE=true`, and `DATABASE_URL=sqlite:///./flowsense_talq_test.db` in the environment inherited by the two test processes. These environment overrides take precedence over values loaded from `.env`; the production `.env` file is not edited.

The existing production services and their database configuration are not stopped or changed. The test database file is ignored by Git.

## Safety boundaries

- Do not point this test launcher at the production Neon URL.
- Do not copy production data into the test database.
- The test APIs are loopback-only and are not available to another computer on the LAN.
- Do not use this HTTP loopback setup to exchange credentials over a network.
- This environment is for local onboarding, approval, OAuth, and key-lifecycle development. Real FlowSense RDS data access and second-machine/TLS testing remain separate steps.

## Reset the test database

Stop both test service processes first. Then, from the repository root:

```powershell
Remove-Item .\flowsense_talq_test.db -ErrorAction SilentlyContinue
```

The tables will be recreated when the isolated test services start again. Never run this command against the production database.
