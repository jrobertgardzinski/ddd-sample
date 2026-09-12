-- Two indexes the sessions table has needed since it was written, and one comment that said so.
--
-- Every lookup by e-mail — "log out everywhere", the offboarding listener's revoke, the account
-- screen's session list, and the revoke that rides an e-mail change — scans the whole table. So
-- does the reaper, which asks for expired rows. On a laptop with a hundred sessions that is free;
-- it is also why nobody noticed. The deadlock comment in SessionJdbcRepository#lockFamily names
-- the same absence from the other side: two locking statements reached overlapping rows by
-- different plans precisely BECAUSE email had no index, and one of them had to sequentially scan.
--
-- Neither index changes a result. They change how the plan gets there.
CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions (email);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_expiration ON sessions (refresh_token_expiration);
