-- Crear tabla principal ssm (sin tabla de historial)
CREATE TABLE IF NOT EXISTS ssm (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255),
    account_id VARCHAR(20),
    association_id VARCHAR(255) UNIQUE NOT NULL,
    association_name VARCHAR(255),
    domain VARCHAR(255),
    compliant_resources INTEGER DEFAULT 0,
    non_compliant_resources INTEGER DEFAULT 0,
    compliance_percentage DECIMAL(5,2) DEFAULT 0.00,
    non_compliant_15_days INTEGER DEFAULT 0,
    non_compliant_15_90_days INTEGER DEFAULT 0,
    non_compliant_90_days INTEGER DEFAULT 0,
    region VARCHAR(50),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Crear índices para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_ssm_association_id ON ssm(association_id);
CREATE INDEX IF NOT EXISTS idx_ssm_account ON ssm(account_id);
CREATE INDEX IF NOT EXISTS idx_ssm_region ON ssm(region);
CREATE INDEX IF NOT EXISTS idx_ssm_compliance ON ssm(compliance_percentage);