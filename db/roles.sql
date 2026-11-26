-- Production role separation (run once, as the database owner, after migrations).
-- The service connects as condlock_app, which can't alter the schema, drop the
-- triggers, or edit/delete audit rows. Replace the password placeholder yourself;
-- never commit a real one.
create role condlock_app login password 'CHANGE_ME';
grant usage on schema public to condlock_app;
grant select, insert on devices, audit_log to condlock_app;
grant select, insert, update (status, met_at, released_at) on locks to condlock_app;
grant select, insert, delete on request_nonces to condlock_app;
grant usage on sequence audit_log_id_seq to condlock_app;
