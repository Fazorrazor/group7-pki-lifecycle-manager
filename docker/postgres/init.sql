-- PostgreSQL Database Initialization Script for Group 7 PKI Lifecycle Manager

CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    environment VARCHAR(50) NOT NULL DEFAULT 'lab',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_endpoint_host_port UNIQUE (hostname, port)
);

CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    serial_number VARCHAR(128) UNIQUE NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    issuer VARCHAR(255) NOT NULL,
    sans TEXT,
    key_type VARCHAR(50) NOT NULL,
    key_size INTEGER NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    revocation_reason VARCHAR(100),
    chain_complete BOOLEAN DEFAULT TRUE,
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL,
    error_message TEXT,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS renewal_logs (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    serial_number VARCHAR(128) NOT NULL,
    validity_days INTEGER NOT NULL,
    downtime_seconds NUMERIC(5, 2) DEFAULT 0.0,
    status VARCHAR(50) NOT NULL,
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ct_audit_logs (
    id SERIAL PRIMARY KEY,
    log_id BIGINT,
    domain VARCHAR(255) NOT NULL,
    common_name VARCHAR(255),
    issuer_name VARCHAR(255) NOT NULL,
    is_authorized BOOLEAN DEFAULT TRUE,
    logged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Seed initial 5 lab microservices
INSERT INTO endpoints (hostname, port, service_name, environment) VALUES
    ('auth.internal.lab', 8443, 'auth-service', 'lab'),
    ('billing.internal.lab', 8444, 'billing-service', 'lab'),
    ('vault.internal.lab', 8445, 'vault-service', 'lab'),
    ('metrics.internal.lab', 8446, 'metrics-service', 'lab'),
    ('portal.internal.lab', 8447, 'portal-service', 'lab')
ON CONFLICT (hostname, port) DO NOTHING;

