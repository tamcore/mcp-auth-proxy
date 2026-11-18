-- Per-key source networks, JSON arrays of CIDR prefixes. allowed_cidrs, when
-- non-empty, is the only place the key may be used from; tool calls from
-- trusted_cidrs skip the one-time code.
ALTER TABLE keys ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT '[]';
ALTER TABLE keys ADD COLUMN trusted_cidrs TEXT NOT NULL DEFAULT '[]';
