-- Migration to add MFA columns and rate limits table.
-- Run as migrator role: psql "$MIGRATOR_URL" -f scripts/migrate_mfa.sql

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_encrypted TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_codes JSONB DEFAULT '[]'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_timestep BIGINT DEFAULT 0;

CREATE TABLE IF NOT EXISTS rate_limits (
  key      TEXT PRIMARY KEY,
  count    INT NOT NULL DEFAULT 1,
  reset_at TIMESTAMPTZ NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limits TO app_user;
