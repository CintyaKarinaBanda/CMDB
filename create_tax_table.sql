-- Crear tabla principal tax (sin tabla de historial)
CREATE TABLE IF NOT EXISTS tax (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255),
    account_id VARCHAR(20),
    query_id VARCHAR(255) UNIQUE NOT NULL,
    query_name VARCHAR(255),
    domain VARCHAR(255),
    description VARCHAR(500),
    database_name VARCHAR(255),
    tables_used VARCHAR(500),
    execution_duration DECIMAL(10,3) DEFAULT 0.000,
    execution_frequency VARCHAR(100),
    owner VARCHAR(255),
    region VARCHAR(50),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Crear índices para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_tax_query_id ON tax(query_id);
CREATE INDEX IF NOT EXISTS idx_tax_account ON tax(account_id);
CREATE INDEX IF NOT EXISTS idx_tax_region ON tax(region);
CREATE INDEX IF NOT EXISTS idx_tax_owner ON tax(owner);
CREATE INDEX IF NOT EXISTS idx_tax_database ON tax(database_name);