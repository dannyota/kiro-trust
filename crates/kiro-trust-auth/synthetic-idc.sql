-- Synthetic Kiro CLI database rows for the audit gate and unit tests (spec
-- 8.7; task-20-rulings.md ruling 2). Included via `include_str!` from both
-- `xtask/src/main.rs`'s `make-db` command and the `#[cfg(test)] mod tests`
-- block in `crates/kiro-trust/src/audit.rs`, so the audit gate's fixture and
-- the unit tests that exercise the same shape can never drift out of
-- byte-identical sync (task-20-fix-1.md Important 4). `xtask` reaches this
-- file by a relative path only, never a crate dependency: CLAUDE.md forbids
-- `xtask` depending on the binary crate, and this file lives outside
-- `crates/kiro-trust` and outside `tests/fixtures/` so it stays out of both
-- the binary package and the fixture scanner's scope
-- (scripts/check-fixtures.sh's `DIR=tests/fixtures`).
--
-- Never a real credential; the SSO region and ARN are the fixture's own
-- (task-20-rulings.md ruling 1, ruling 4). The refresh_token and
-- clientSecret placeholder values ("ph-ref", "ph-sec") must stay under eight
-- characters: scripts/check-fixtures.sh's credential regex flags any
-- refresh_token/client_secret-shaped JSON field with an 8-or-more character
-- value as leaked credential material (task-20-fix-1.md minor 4).
CREATE TABLE IF NOT EXISTS auth_kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value BLOB);
DELETE FROM auth_kv; DELETE FROM state;
INSERT INTO auth_kv VALUES ('kirocli:odic:token', '{"access_token":"placeholder-access","refresh_token":"ph-ref","expires_at":"2099-01-01T00:00:00Z","region":"us-east-1"}');
INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{"clientId":"placeholder-client","clientSecret":"ph-sec"}');
INSERT INTO state VALUES ('auth.idc.region', '"us-east-1"');
INSERT INTO state VALUES ('api.codewhisperer.profile', '{"arn":"arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE","profile_name":"KiroProfile-us-east-1"}');
