-- Archive tables for retention
CREATE TABLE IF NOT EXISTS logs_archive (
    id UUID PRIMARY KEY,
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    raw_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS errors_archive (
    id UUID PRIMARY KEY,
    log_id UUID,
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    error_message TEXT,
    error_type VARCHAR(100),
    fingerprint VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clusters_archive (
    id UUID PRIMARY KEY,
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    fingerprint VARCHAR(255),
    error_type VARCHAR(100),
    severity VARCHAR(20),
    count INT DEFAULT 1,
    last_seen TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_logs_archive_app ON logs_archive(app_id);
CREATE INDEX IF NOT EXISTS idx_errors_archive_app ON errors_archive(app_id);
CREATE INDEX IF NOT EXISTS idx_clusters_archive_app ON clusters_archive(app_id);