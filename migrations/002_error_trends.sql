-- Add error trends table for time-based analytics
CREATE TABLE IF NOT EXISTS error_trends (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    error_type VARCHAR(100) NOT NULL,
    interval_start TIMESTAMP NOT NULL,
    interval_type VARCHAR(10) NOT NULL CHECK (interval_type IN ('hourly', 'daily')),
    count INT DEFAULT 1,
    UNIQUE(app_id, error_type, interval_start, interval_type)
);

CREATE INDEX IF NOT EXISTS idx_error_trends_app_type_interval 
ON error_trends(app_id, error_type, interval_start DESC);

CREATE INDEX IF NOT EXISTS idx_error_trends_interval 
ON error_trends(interval_start DESC) WHERE interval_type = 'daily';