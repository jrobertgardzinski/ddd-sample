-- DB-8: which accounts would collide once the local part is lower-cased for every domain?
--
-- Until 2026-09-12 `NormalizedEmail` lower-cased the local part only for gmail/yahoo/outlook/icloud,
-- so `Alice@corp.com` and `alice@corp.com` were two accounts. They are one identity now, which means
-- a deployment whose users table already holds BOTH cannot simply be re-normalised: the unique index
-- on normalized_email would refuse, and the migration that follows this report is written to refuse
-- WITH it rather than silently pick a winner.
--
-- Run it against the deployment's database BEFORE letting V27 run:
--   psql "$DATABASE_URL" -f docs/db8-case-collisions.sql
--
-- An empty result means nothing to do: V27 will re-normalise in place and the change is invisible.
-- Rows mean two accounts belong to one person (or to two people who chose the same name in
-- different cases) and a HUMAN has to decide which survives — that is not a decision a migration
-- may make, because one of them is somebody's account with somebody's content behind it.
WITH normalized AS (
    SELECT id,
           email,
           normalized_email,
           lower(split_part(normalized_email, '@', 1)) || '@' || split_part(normalized_email, '@', 2)
               AS would_become
    FROM users
)
SELECT would_become                       AS "one identity after the change",
       count(*)                           AS "accounts today",
       string_agg(email, ', ' ORDER BY email) AS "the addresses as their owners typed them",
       string_agg(id::text, ', ' ORDER BY email) AS "ids"
FROM normalized
GROUP BY would_become
HAVING count(*) > 1
ORDER BY count(*) DESC, would_become;
