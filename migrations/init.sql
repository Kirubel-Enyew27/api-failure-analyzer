CREATE TABLE logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE errors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id UUID REFERENCES logs(id) ON DELETE CASCADE,
    error_message TEXT,
    error_type VARCHAR(100),
    fingerprint VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
    
CREATE TABLE clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint VARCHAR(255) UNIQUE,
    error_type VARCHAR(100),
    count INT DEFAULT 1,
    last_seen TIMESTAMP DEFAULT NOW()
);