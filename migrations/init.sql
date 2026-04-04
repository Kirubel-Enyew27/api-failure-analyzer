CREATE TABLE apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    raw_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE errors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id UUID REFERENCES logs(id) ON DELETE CASCADE,
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    error_message TEXT,
    error_type VARCHAR(100),
    fingerprint VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
    
CREATE TABLE clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    fingerprint VARCHAR(255),
    error_type VARCHAR(100),
    severity VARCHAR(20) DEFAULT 'low',
    count INT DEFAULT 1,
    last_seen TIMESTAMP DEFAULT NOW(),
    UNIQUE(app_id, fingerprint)
);

CREATE INDEX idx_logs_app ON logs(app_id);
CREATE INDEX idx_errors_app ON errors(app_id);
CREATE INDEX idx_clusters_app ON clusters(app_id);