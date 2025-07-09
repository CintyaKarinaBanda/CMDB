-- Tabla SNS
CREATE TABLE IF NOT EXISTS sns (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255),
    account_id VARCHAR(20),
    topic_name VARCHAR(255),
    domain VARCHAR(255),
    topic_arn VARCHAR(500) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    type VARCHAR(50),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);