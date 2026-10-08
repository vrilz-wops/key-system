CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    key TEXT NOT NULL UNIQUE,

    type TEXT NOT NULL DEFAULT 'FREE',

    username TEXT,

    duration_seconds INTEGER NOT NULL DEFAULT 86400,

    claimed_at INTEGER,
    claim_expires_at INTEGER,

    redeemed_at INTEGER,
    expires_at INTEGER,

    active INTEGER NOT NULL DEFAULT 1,

    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_key
ON keys(key);

CREATE INDEX IF NOT EXISTS idx_keys_username
ON keys(username);

CREATE INDEX IF NOT EXISTS idx_keys_claimed
ON keys(username, claimed_at);

CREATE INDEX IF NOT EXISTS idx_keys_active
ON keys(active);


-- Premium device binding: max 5 unique devices per key.
CREATE TABLE IF NOT EXISTS key_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    UNIQUE(key_id, device_id),
    FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_key_devices_key_id ON key_devices(key_id);
