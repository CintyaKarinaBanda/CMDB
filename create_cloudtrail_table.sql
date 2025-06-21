-- Agregar columnas faltantes a tabla cloudtrail_events existente
ALTER TABLE cloudtrail_events 
ADD COLUMN IF NOT EXISTS event_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS resource_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS region VARCHAR(50),
ADD COLUMN IF NOT EXISTS event_source VARCHAR(255),
ADD COLUMN IF NOT EXISTS account_id VARCHAR(20),
ADD COLUMN IF NOT EXISTS account_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Crear índices para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_cloudtrail_event_id ON cloudtrail_events(event_id);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_event_time ON cloudtrail_events(event_time);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_resource ON cloudtrail_events(resource_type, resource_name);