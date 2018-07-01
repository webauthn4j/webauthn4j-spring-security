-- Authenticator table  --
CREATE TABLE authenticators(
  id                SERIAL         NOT NULL,
  name              VARCHAR(32)    NOT NULL,
  counter           BIGINT         NOT NULL,
  aa_guid  bytea  NOT NULL,
  credential_id bytea NOT NULL,
  credential_public_key VARCHAR(4096) NOT NULL,
  attestation_statement  VARCHAR(4096) NOT NULL,
);
