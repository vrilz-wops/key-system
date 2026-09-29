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
