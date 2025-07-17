-- Relaciones Simples para Diagramas
-- Reemplazar 'ACCOUNT_ID' con el ID real

-- CONEXIONES DIRECTAS
WITH connections AS (
  -- Lambda -> API Gateway
  SELECT 
    l.functionname as from_resource,
    'LAMBDA' as from_type,
    CASE 
      WHEN l.triggers LIKE '%API Gateway:%' THEN 
        regexp_replace(l.triggers, '.*"API Gateway:([^"]+)".*', '\1')
      ELSE 'Unknown API'
    END as to_resource,
    'APIGATEWAY' as to_type,
    'TRIGGERED_BY' as connection_type,
    l.region
  FROM lambda_functions l
  WHERE l.accountid = 'ACCOUNT_ID'
    AND l.triggers LIKE '%API Gateway%'

  UNION ALL

  -- Lambda -> S3
  SELECT 
    l.functionname as from_resource,
    'LAMBDA' as from_type,
    CASE 
      WHEN l.triggers LIKE '%S3:%' THEN 
        regexp_replace(l.triggers, '.*"S3:([^"]+)".*', '\1')
      ELSE 'Unknown Bucket'
    END as to_resource,
    'S3' as to_type,
    'TRIGGERED_BY' as connection_type,
    l.region
  FROM lambda_functions l
  WHERE l.accountid = 'ACCOUNT_ID'
    AND l.triggers LIKE '%S3%'

  UNION ALL

  -- EC2 -> VPC
  SELECT 
    e.instancename as from_resource,
    'EC2' as from_type,
    e.vpc as to_resource,
    'VPC' as to_type,
    'RUNS_IN' as connection_type,
    e.region
  FROM ec2 e
  WHERE e.accountid = 'ACCOUNT_ID'
    AND e.vpc IS NOT NULL

  UNION ALL

  -- Lambda -> VPC
  SELECT 
    l.functionname as from_resource,
    'LAMBDA' as from_type,
    split_part(split_part(l.vpcconfig, ':', 2), ',', 1) as to_resource,
    'VPC' as to_type,
    'RUNS_IN' as connection_type,
    l.region
  FROM lambda_functions l
  WHERE l.accountid = 'ACCOUNT_ID'
    AND l.vpcconfig LIKE 'VPC:%'
)

SELECT 
  connection_type,
  from_type || ' -> ' || to_type as relationship,
  from_resource,
  to_resource,
  region,
  COUNT(*) OVER (PARTITION BY connection_type) as total_connections
FROM connections
ORDER BY connection_type, from_type, from_resource;