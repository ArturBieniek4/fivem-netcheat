# Example middlewares

Examples here are not loaded automatically. Copy one `.py` file into the
parent `middlewares/` directory to enable it. Review and adapt its event names
and rules first; enabled scripts affect live traffic immediately.

- `randomize_angle.py` randomizes outbound JSON string values containing
  `ANGLE (` while preserving their length.
- `redact_outbound_secrets.py` replaces values under common secret-like JSON
  keys.
- `block_event_names.py` drops events whose names match a configurable set.
- `clamp_numeric_fields.py` constrains selected outbound numeric fields to a
  configured range.

Files are applied in alphabetical filename order when several middlewares are enabled.
