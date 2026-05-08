-- Cloak vault schema v2: BIP-39 recovery seed.
--
-- Adds two columns to `meta` for the recovery-key wrap of the master key,
-- plus a `recovery_format` discriminator so v1.1+ can introduce alternate
-- wraps (hardware tokens, Shamir, etc.) without ambiguity.
--
-- The columns are nullable because vaults created before this migration
-- have no recovery wrap. `cloak backup mnemonic` / `cloak restore` refuse
-- to operate on such vaults until v1.1 ships an in-place migration.

ALTER TABLE meta ADD COLUMN recovery_format TEXT;
ALTER TABLE meta ADD COLUMN recovery_wrap_nonce BLOB;
ALTER TABLE meta ADD COLUMN recovery_wrap_aead BLOB;
