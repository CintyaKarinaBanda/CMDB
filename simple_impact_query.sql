-- Consulta Simplificada para Diagrama de Impacto
-- Reemplazar 'YOUR_ACCOUNT_ID' con el ID de cuenta

SELECT 
    'EC2' as resource_type,
    COUNT(*) as total,
    COALESCE(string_agg(DISTINCT region, ', '), 'N/A') as regions
FROM ec2 
WHERE accountid = 'YOUR_ACCOUNT_ID'

UNION ALL

SELECT 
    'RDS' as resource_type,
    COUNT(*) as total,
    COALESCE(string_agg(DISTINCT region, ', '), 'N/A') as regions
FROM rds 
WHERE accountid = 'YOUR_ACCOUNT_ID'

UNION ALL

SELECT 
    'LAMBDA' as resource_type,
    COUNT(*) as total,
    COALESCE(string_agg(DISTINCT region, ', '), 'N/A') as regions
FROM lambda_functions 
WHERE accountid = 'YOUR_ACCOUNT_ID'

UNION ALL

SELECT 
    'VPC' as resource_type,
    COUNT(*) as total,
    COALESCE(string_agg(DISTINCT region, ', '), 'N/A') as regions
FROM vpcs 
WHERE account_id = 'YOUR_ACCOUNT_ID'

UNION ALL

SELECT 
    'S3' as resource_type,
    COUNT(*) as total,
    COALESCE(string_agg(DISTINCT region, ', '), 'N/A') as regions
FROM s3 
WHERE account_id = 'YOUR_ACCOUNT_ID'

UNION ALL

SELECT 
    'APIGATEWAY' as resource_type,
    COUNT(*) as total,
    COALESCE(string_agg(DISTINCT region, ', '), 'N/A') as regions
FROM apigateway 
WHERE account_id = 'YOUR_ACCOUNT_ID'

ORDER BY resource_type;