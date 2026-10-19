-- A client is now the URL of the document it publishes (identity-provider/specs/auth.md § 1,
-- "Clients"), so no client is registered here. Codes issued to the old `web-client` id could no
-- longer be read back.
DELETE FROM authorization_codes;
DROP TABLE oauth_clients;
