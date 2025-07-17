-- Consulta mejorada para Diagramas de Relaciones por Cuenta
-- Reemplazar '729694432199' con el ID de cuenta específico

-- 1. RELACIONES VPC: EC2, RDS, Lambda que comparten VPC/Subnets
SELECT 
    'VPC_NETWORK' as diagram_type,
    v.vpc_name as group_name,
    v.vpc_id as group_id,
    e.instancename as source_name,
    'EC2' as source_type,
    e.instanceid as source_id,
    v.vpc_name as target_name,
    'VPC' as target_type,
    v.vpc_id as target_id,
    'RUNS_IN' as relationship,
    e.region
FROM vpcs v
JOIN ec2 e ON v.vpc_id = e.vpc
WHERE v.account_id = '729694432199'

UNION ALL

SELECT 
    'VPC_NETWORK' as diagram_type,
    v.vpc_name as group_name,
    v.vpc_id as group_id,
    r.dbname as source_name,
    'RDS' as source_type,
    r.dbinstanceid as source_id,
    v.vpc_name as target_name,
    'VPC' as target_type,
    v.vpc_id as target_id,
    'RUNS_IN' as relationship,
    r.region
FROM vpcs v
JOIN rds r ON v.account_id = r.accountid
WHERE v.account_id = '729694432199'

UNION ALL

SELECT 
    'VPC_NETWORK' as diagram_type,
    v.vpc_name as group_name,
    v.vpc_id as group_id,
    l.functionname as source_name,
    'LAMBDA' as source_type,
    l.functionid as source_id,
    v.vpc_name as target_name,
    'VPC' as target_type,
    v.vpc_id as target_id,
    'RUNS_IN' as relationship,
    l.region
FROM vpcs v
JOIN lambda_functions l ON v.vpc_id = split_part(split_part(l.vpcconfig, ':', 2), ',', 1)
WHERE v.account_id = '729694432199'
  AND l.vpcconfig LIKE 'VPC:%'

UNION ALL

-- 2. TODAS LAS LAMBDAS: Mostrar todas las funciones Lambda
SELECT
    'LAMBDA_FUNCTIONS' as diagram_type,
    'ALL_LAMBDAS' as group_name,
    'all-lambdas' as group_id,
    l.functionname as source_name,
    'LAMBDA' as source_type,
    l.functionid as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    l.accountid as target_id,
    'BELONGS_TO' as relationship,
    l.region
FROM lambda_functions l
WHERE l.accountid = '729694432199'

UNION ALL

-- 3. LAMBDA-TRIGGERS: Solo las que tienen triggers
SELECT
    'LAMBDA_TRIGGERS' as diagram_type,
    'LAMBDA_WITH_TRIGGERS' as group_name,
    'lambda-with-triggers' as group_id,
    COALESCE(l.triggers, 'No triggers') as source_name,
    'TRIGGER' as source_type,
    l.functionid || '_trigger' as source_id,
    l.functionname as target_name,
    'LAMBDA' as target_type,
    l.functionid as target_id,
    'TRIGGERS' as relationship,
    l.region
FROM lambda_functions l
WHERE l.accountid = '729694432199'
  AND l.triggers IS NOT NULL
  AND l.triggers != '[]'

UNION ALL

-- 4. SUBNET RELATIONSHIPS: Recursos en la misma subnet
SELECT 
    'SUBNET_NETWORK' as diagram_type,
    s.subnetname as group_name,
    s.subnetid as group_id,
    e.instancename as source_name,
    'EC2' as source_type,
    e.instanceid as source_id,
    s.subnetname as target_name,
    'SUBNET' as target_type,
    s.subnetid as target_id,
    'BELONGS_TO' as relationship,
    e.region
FROM subnets s
JOIN ec2 e ON s.subnetid = e.subnet
WHERE s.accountid = '729694432199'

ORDER BY diagram_type, group_name, source_type, source_name;
