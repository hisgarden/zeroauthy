-- Plan 33b passkeys and WebAuthn MFA. Forward only; no existing row is
-- rewritten: the new columns are NULL for old rows ("none"). JSON columns
-- are LONGTEXT as elsewhere in MySQL. The snooze key stays within InnoDB's
-- 3072-byte index limit: (64 + 255 + 32 + 255) utf8mb4 characters.
ALTER TABLE sessions ADD COLUMN auth_methods LONGTEXT NULL;
ALTER TABLE clients ADD COLUMN mobile LONGTEXT NULL;
ALTER TABLE tenants ADD COLUMN domain_rp_ids LONGTEXT NULL;
CREATE TABLE webauthn_snoozes (tenant_id VARCHAR(64) NOT NULL, user_id VARCHAR(255) NOT NULL, kind VARCHAR(32) NOT NULL, scope_key VARCHAR(255) NOT NULL, until BIGINT NOT NULL, PRIMARY KEY (tenant_id,user_id,kind,scope_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX webauthn_snoozes_until ON webauthn_snoozes (until);
