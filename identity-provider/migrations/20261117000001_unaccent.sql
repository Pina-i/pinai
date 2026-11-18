-- Searching people by name ignores accents on both sides of the comparison
-- (identity-provider/specs/identity.md § 7): "hoku" finds "Hōkū", and "Hōkū" finds "Hoku".
CREATE EXTENSION IF NOT EXISTS unaccent;
