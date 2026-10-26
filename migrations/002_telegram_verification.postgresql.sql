-- PostgreSQL migration: Telegram verification fields for API access requests.
-- Back up the database and apply this once before deploying the Telegram-enabled app.
BEGIN;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS telegram_username VARCHAR(64);
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS telegram_chat_id VARCHAR(64);
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS telegram_verified_at TIMESTAMPTZ;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS request_token_hash VARCHAR(64);
CREATE INDEX IF NOT EXISTS ix_access_requests_request_token_hash ON access_requests (request_token_hash);
COMMIT;
