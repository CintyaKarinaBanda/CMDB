-- Tabla unificada de cambios para todos los servicios
CREATE TABLE IF NOT EXISTS changes_history (
    id SERIAL PRIMARY KEY,
    service_type VARCHAR(50) NOT NULL,        -- 'EC2', 'RDS', 'S3', etc.
    resource_id VARCHAR(255) NOT NULL,        -- instance_id, bucket_name, etc.
    field_name VARCHAR(100) NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by VARCHAR(255),
    account_id VARCHAR(20),
    region VARCHAR(50),
    change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices optimizados
CREATE INDEX IF NOT EXISTS idx_changes_service_resource ON changes_history(service_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_changes_date ON changes_history(change_date);
CREATE INDEX IF NOT EXISTS idx_changes_account ON changes_history(account_id);
CREATE INDEX IF NOT EXISTS idx_changes_service ON changes_history(service_type);