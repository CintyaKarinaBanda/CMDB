-- Agregar campos account_id y account_name a la tabla cloudtrail_events
ALTER TABLE cloudtrail_events 
ADD COLUMN IF NOT EXISTS account_id VARCHAR(20),
ADD COLUMN IF NOT EXISTS account_name VARCHAR(255);