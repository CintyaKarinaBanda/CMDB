-- Tabla CodeBuild
CREATE TABLE IF NOT EXISTS codebuild (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(255),
    account_id VARCHAR(20),
    project_name VARCHAR(255) UNIQUE NOT NULL,
    source_provider VARCHAR(100),
    repository VARCHAR(500),
    last_build_status VARCHAR(50),
    description TEXT,
    last_modified TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);