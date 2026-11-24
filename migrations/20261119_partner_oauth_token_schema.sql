-- Safe additive migration for partner OAuth tokens.
-- Preserves all existing oauth_access_tokens rows and their legacy FK.
BEGIN;

ALTER TABLE oauth_access_tokens
    ADD COLUMN IF NOT EXISTS integration_client_id INTEGER;

-- Legacy tokens continue to reference oauth_clients. New partner tokens use
-- integration_clients and leave oauth_client_id NULL.
ALTER TABLE oauth_access_tokens
    ALTER COLUMN oauth_client_id DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'oauth_access_tokens_integration_client_id_fkey'
          AND conrelid = 'oauth_access_tokens'::regclass
    ) THEN
        ALTER TABLE oauth_access_tokens
            ADD CONSTRAINT oauth_access_tokens_integration_client_id_fkey
            FOREIGN KEY (integration_client_id)
            REFERENCES integration_clients(id);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS ix_oauth_access_tokens_integration_client_id
    ON oauth_access_tokens (integration_client_id);

COMMIT;
