-- DB-14: the password_resets table had retention only by accident.
--
-- A row dies when the link is REDEEMED. Somebody who asked for a reset and then remembered their
-- password, and every address a scanner typed into the public "forgot password" endpoint, left a
-- row behind for as long as the database lives — an e-mail address and the hash of a token that
-- stopped working an hour later (V20). UnclaimedPasswordResetReaper sweeps them after a week.
--
-- The sweep goes by age alone and the table is keyed by e-mail, so without this it reads every row.
CREATE INDEX IF NOT EXISTS idx_password_resets_requested_at ON password_resets (requested_at);
