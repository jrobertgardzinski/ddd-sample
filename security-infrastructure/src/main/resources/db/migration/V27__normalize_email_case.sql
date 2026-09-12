-- DB-8: the deduplication form stops depending on how somebody held the shift key.
--
-- `NormalizedEmail` lower-cases the local part for EVERY domain since 2026-09-12 (it used to do it
-- only for gmail/yahoo/outlook/icloud). The rows written before that carry the old form, so without
-- this migration a registration of `alice@corp.com` would not notice the existing `Alice@corp.com`:
-- the new value is compared against a stored value computed by the old rule, and they differ.
--
-- The re-normalisation is in place and touches nothing a user sees — `email` keeps the spelling its
-- owner typed; only `normalized_email`, which exists solely to answer "is this the same person",
-- changes.
--
-- IT REFUSES rather than choosing. If two accounts would end up with the same normalized address,
-- the UPDATE below cannot run (unique index) — and the check before it says so by name, because the
-- alternative is a migration deciding which of two people's accounts survives. Run
-- docs/db8-case-collisions.sql first on any database that has been in use; resolve the pairs by
-- hand, then let this through.
DO $$
DECLARE
    collisions text;
BEGIN
    SELECT string_agg(addresses, '; ')
      INTO collisions
      FROM (SELECT string_agg(email, ' + ' ORDER BY email) AS addresses
              FROM users
             GROUP BY lower(split_part(normalized_email, '@', 1)) || '@' || split_part(normalized_email, '@', 2)
            HAVING count(*) > 1) AS pairs;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION 'account-case collisions must be resolved by hand before this migration: %',
            collisions
            USING HINT = 'see docs/db8-case-collisions.sql — two accounts would become one identity';
    END IF;
END $$;

UPDATE users
   SET normalized_email = lower(split_part(normalized_email, '@', 1))
                          || '@' || split_part(normalized_email, '@', 2)
 WHERE normalized_email <> lower(split_part(normalized_email, '@', 1))
                           || '@' || split_part(normalized_email, '@', 2);
