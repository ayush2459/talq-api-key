-- PostgreSQL migration: email verification and API-key expiration.
-- Take a backup before running against an existing production database.
-- Apply once before deploying code that reads these columns.

BEGIN;

ALTER TABLE access_requests
    ADD COLUMN IF NOT EXISTS verification_token_hash VARCHAR(64);
ALTER TABLE access_requests
    ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ;
ALTER TABLE access_requests
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

ALTER TABLE client_api_keys
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Existing keys receive a 90-day lifetime measured from their original issue time.
-- Existing revoked_at values remain unchanged.
UPDATE client_api_keys
SET expires_at = COALESCE(created_at, NOW()) + INTERVAL '90 days'
WHERE expires_at IS NULL;

ALTER TABLE client_api_keys
    ALTER COLUMN expires_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS ix_access_requests_verification_token_hash
    ON access_requests (verification_token_hash);
CREATE INDEX IF NOT EXISTS ix_client_api_keys_expires_at
    ON client_api_keys (expires_at);

COMMIT;
