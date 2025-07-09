-- Tabla Route53
CREATE TABLE IF NOT EXISTS route53 (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255),
    account_id VARCHAR(20),
    domain_name VARCHAR(500),
    record_type VARCHAR(50),
    record_value TEXT,
    ttl VARCHAR(20),
    hosted_zone VARCHAR(500),
    record_id VARCHAR(600) UNIQUE NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);