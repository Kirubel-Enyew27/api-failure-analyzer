-- Add severity column to clusters
ALTER TABLE clusters ADD COLUMN IF NOT EXISTS severity VARCHAR(20) DEFAULT 'low';

CREATE INDEX IF NOT EXISTS idx_clusters_severity ON clusters(severity);