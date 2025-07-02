-- Tabla unificada de cambios para todos los servicios
CREATE TABLE IF NOT EXISTS resource_changes_history (
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
CREATE INDEX IF NOT EXISTS idx_changes_service_resource ON resource_changes_history(service_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_changes_date ON resource_changes_history(change_date);
CREATE INDEX IF NOT EXISTS idx_changes_account ON resource_changes_history(account_id);
CREATE INDEX IF NOT EXISTS idx_changes_user ON resource_changes_history(changed_by);

-- Vista para compatibilidad con consultas existentes
CREATE VIEW ec2_changes_history AS 
SELECT id, resource_id as instance_id, field_name, old_value, new_value, changed_by, change_date 
FROM resource_changes_history WHERE service_type = 'EC2';

CREATE VIEW rds_changes_history AS 
SELECT id, resource_id as db_instance_id, field_name, old_value, new_value, changed_by, change_date 
FROM resource_changes_history WHERE service_type = 'RDS';