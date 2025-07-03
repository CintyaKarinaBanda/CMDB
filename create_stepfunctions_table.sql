-- Crear tabla principal stepfunctions (sin tabla de historial)
CREATE TABLE IF NOT EXISTS stepfunctions (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255),
    account_id VARCHAR(20),
    stepfunction_arn VARCHAR(255) UNIQUE NOT NULL,
    instance_id VARCHAR(255),
    stepfunction_name VARCHAR(255),
    description VARCHAR(500),
    triggers INTEGER DEFAULT 1,
    versions INTEGER DEFAULT 1,
    roles_permissions VARCHAR(255),
    status VARCHAR(50),
    region VARCHAR(50),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Crear índices para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_stepfunctions_arn ON stepfunctions(stepfunction_arn);
CREATE INDEX IF NOT EXISTS idx_stepfunctions_account ON stepfunctions(account_id);
CREATE INDEX IF NOT EXISTS idx_stepfunctions_region ON stepfunctions(region);
CREATE INDEX IF NOT EXISTS idx_stepfunctions_status ON stepfunctions(status);
CREATE INDEX IF NOT EXISTS idx_stepfunctions_name ON stepfunctions(stepfunction_name);