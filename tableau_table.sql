-- Tabla Tableau
CREATE TABLE IF NOT EXISTS tableau (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255),
    account_id VARCHAR(20),
    workbook_name VARCHAR(255),
    content_type VARCHAR(100),
    data_source VARCHAR(255),
    refresh_frequency VARCHAR(100),
    integrations VARCHAR(255),
    workbook_id VARCHAR(255) UNIQUE NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);