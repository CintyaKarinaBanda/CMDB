-- RELACIÓN JERÁRQUICA: SERVICIOS → SUBNET → VPC
-- Cuenta: 729694432199

-- EC2 pertenece a SUBNET
SELECT 
    'HIERARCHICAL' as relationship_type,
    'EC2_TO_SUBNET' as relationship_subtype,
    e.instancename as source_name,
    'EC2' as source_type,
    e.instanceid as source_id,
    COALESCE(s.subnetname, s.subnetid) as target_name,
    'SUBNET' as target_type,
    s.subnetid as target_id,
    'RUNS_IN' as relationship,
    e.region,
    e.accountid as account_id
FROM ec2 e
JOIN subnets s ON e.subnet = s.subnetid
WHERE e.accountid = '729694432199'

UNION ALL

-- LAMBDA con VPC pertenece a SUBNET (extrayendo subnet de VPCConfig)
SELECT 
    'HIERARCHICAL' as relationship_type,
    'LAMBDA_TO_SUBNET' as relationship_subtype,
    l.functionname as source_name,
    'LAMBDA' as source_type,
    l.functionid as source_id,
    COALESCE(s.subnetname, s.subnetid) as target_name,
    'SUBNET' as target_type,
    s.subnetid as target_id,
    'RUNS_IN' as relationship,
    l.region,
    l.accountid as account_id
FROM lambda_functions l
JOIN subnets s ON split_part(split_part(l.vpcconfig, ':', 3), ',', 1) = s.subnetid
WHERE l.accountid = '729694432199'
  AND l.vpcconfig LIKE 'VPC:%'

UNION ALL

-- RDS que tienen subnet group (usando campo VPC para encontrar subnets relacionadas)
SELECT 
    'HIERARCHICAL' as relationship_type,
    'RDS_TO_SUBNET' as relationship_subtype,
    r.dbname as source_name,
    'RDS' as source_type,
    r.dbinstanceid as source_id,
    COALESCE(s.subnetname, s.subnetid) as target_name,
    'SUBNET' as target_type,
    s.subnetid as target_id,
    'RUNS_IN' as relationship,
    r.region,
    r.accountid as account_id
FROM rds r
JOIN subnets s ON s.vpcid = r.vpc
WHERE r.accountid = '729694432199'
  AND r.vpc IS NOT NULL

UNION ALL

-- EKS Clusters que tienen subnets
SELECT 
    'HIERARCHICAL' as relationship_type,
    'EKS_TO_SUBNET' as relationship_subtype,
    e.clustername as source_name,
    'EKS' as source_type,
    e.clusterid as source_id,
    COALESCE(s.subnetname, s.subnetid) as target_name,
    'SUBNET' as target_type,
    s.subnetid as target_id,
    'RUNS_IN' as relationship,
    'N/A' as region,
    e.accountid as account_id
FROM eks e
CROSS JOIN subnets s
WHERE e.accountid = '729694432199'
  AND s.accountid = '729694432199'
  AND s.subnetname LIKE '%eks%' OR s.subnetname LIKE '%cluster%'

UNION ALL

-- Redshift Clusters en subnets específicas
SELECT 
    'HIERARCHICAL' as relationship_type,
    'REDSHIFT_TO_SUBNET' as relationship_subtype,
    r.database_name as source_name,
    'REDSHIFT' as source_type,
    r.database_id as source_id,
    COALESCE(s.subnetname, s.subnetid) as target_name,
    'SUBNET' as target_type,
    s.subnetid as target_id,
    'RUNS_IN' as relationship,
    r.region,
    r.account_id as account_id
FROM redshift r
CROSS JOIN subnets s
WHERE r.account_id = '729694432199'
  AND s.accountid = '729694432199'
  AND (s.subnetname LIKE '%redshift%' OR s.subnetname LIKE '%data%')

UNION ALL

-- SUBNET pertenece a VPC
SELECT 
    'HIERARCHICAL' as relationship_type,
    'SUBNET_TO_VPC' as relationship_subtype,
    COALESCE(s.subnetname, s.subnetid) as source_name,
    'SUBNET' as source_type,
    s.subnetid as source_id,
    v.vpc_name as target_name,
    'VPC' as target_type,
    v.vpc_id as target_id,
    'BELONGS_TO' as relationship,
    s.region,
    s.accountid as account_id
FROM subnets s
JOIN vpcs v ON s.vpcid = v.vpc_id
WHERE s.accountid = '729694432199'

ORDER BY relationship_subtype, source_name;