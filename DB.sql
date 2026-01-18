CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users (id),
    hash TEXT UNIQUE NOT NULL,
    revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_api_keys on api_keys(user_id);