SQL migrations, applied in filename order by `services/escrow` (`migrate()`), each once,
recorded in `schema_migrations`.

- `001_init.sql`: `devices`, `locks`, `audit_log`, `request_nonces`, plus triggers that make
  `audit_log` append-only and lock rows tamper-resistant (sealed fields immutable, status only
  moves forward, no deletes).
- `../roles.sql`: optional production role setup so the service runs without owner rights.
