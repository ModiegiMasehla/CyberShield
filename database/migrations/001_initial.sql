-- CyberShield PostgreSQL schema reference (generated from app/models.py).
-- Apply with: cd backend && alembic upgrade head. This file is for review only.

CREATE TABLE users (
	id SERIAL NOT NULL, 
	email VARCHAR(255) NOT NULL, 
	password_hash VARCHAR(512) NOT NULL, 
	role VARCHAR(32) NOT NULL, 
	failed_logins INTEGER NOT NULL, 
	locked_until TIMESTAMP WITH TIME ZONE, 
	mfa_secret VARCHAR(64), 
	mfa_enabled BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE TABLE vulnerabilities (
	id SERIAL NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	description TEXT NOT NULL, 
	impact TEXT NOT NULL, 
	recommendation TEXT NOT NULL, 
	evidence TEXT NOT NULL, 
	cve_id VARCHAR(32), 
	cvss FLOAT, 
	PRIMARY KEY (id)
);

CREATE TABLE alerts (
	id SERIAL NOT NULL, 
	alert_type VARCHAR(64) NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	source VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	evidence TEXT NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	assigned_analyst_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(assigned_analyst_id) REFERENCES users (id)
);

CREATE TABLE audit_logs (
	id SERIAL NOT NULL, 
	user_id INTEGER, 
	action VARCHAR(64) NOT NULL, 
	resource VARCHAR(255) NOT NULL, 
	result VARCHAR(64) NOT NULL, 
	ip_address VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE incidents (
	id SERIAL NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	category VARCHAR(64) NOT NULL, 
	affected_asset VARCHAR(255) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	assigned_analyst_id INTEGER, 
	resolution TEXT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(assigned_analyst_id) REFERENCES users (id)
);
