-- ACC-6: a verification link that never stops working.
--
-- The row carries the hash of the token mailed to an address, and nothing carried WHEN. So a link
-- from a year ago verified the address as happily as one from a minute ago — while its neighbours
-- (the password reset in V20, the e-mail change in V24) both learned to expire. The V24 comment
-- already claimed every mailed token had an age; this is the one that did not.
--
-- The same shape as V20: add the column, give the rows that exist a date in the distant past (they
-- are older than any TTL anybody will configure, which is the honest reading of "we do not know
-- when this was sent"), then make it required.
ALTER TABLE email_verifications ADD COLUMN requested_at TIMESTAMP;
UPDATE email_verifications SET requested_at = TIMESTAMP '1970-01-01 00:00:00' WHERE requested_at IS NULL;
ALTER TABLE email_verifications ALTER COLUMN requested_at SET NOT NULL;

-- the reaper's index: rows are swept by age, and without this the sweep reads the whole table
CREATE INDEX IF NOT EXISTS idx_email_verifications_requested_at
    ON email_verifications (requested_at) WHERE verified = FALSE;
