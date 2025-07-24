-- Consulta Simplificada para Diagramas de Relaciones
-- Reemplazar '729694432199' con el ID de cuenta específico

WITH account_resources AS (
    -- EC2
    SELECT 'EC2' as service_type, instancename as name, instanceid as id, accountid as account, region FROM ec2 WHERE accountid = '729694432199'
    UNION ALL
    -- RDS  
    SELECT 'RDS', dbname, dbinstanceid, accountid, region FROM rds WHERE accountid = '729694432199'
    UNION ALL
    -- Lambda
    SELECT 'LAMBDA', functionname, functionid, accountid, region FROM lambda_functions WHERE accountid = '729694432199'
    UNION ALL
    -- VPC
    SELECT 'VPC', vpc_name, vpc_id, account_id, region FROM vpcs WHERE account_id = '729694432199'
    UNION ALL
    -- Subnets
    SELECT 'SUBNET', COALESCE(subnetname, subnetid), subnetid, accountid, region FROM subnets WHERE accountid = '729694432199'
    UNION ALL
    -- S3
    SELECT 'S3', bucket_name_display, bucket_name, account_id, region FROM s3 WHERE account_id = '729694432199'
    UNION ALL
    -- API Gateway
    SELECT 'APIGATEWAY', name, api_id, account_id, region FROM apigateway WHERE account_id = '729694432199'
    UNION ALL
    -- Redshift
    SELECT 'REDSHIFT', database_name, database_id, account_id, region FROM redshift WHERE account_id = '729694432199'
    UNION ALL
    -- EKS
    SELECT 'EKS', clustername, clusterid, accountid, 'N/A' FROM eks WHERE accountid = '729694432199'
    UNION ALL
    -- ECR
    SELECT 'ECR', repositoryname, repositoryname, accountid, 'N/A' FROM ecr WHERE accountid = '729694432199'
    UNION ALL
    -- KMS
    SELECT 'KMS', COALESCE(keyname, keyid), keyid, accountid, 'N/A' FROM kms WHERE accountid = '729694432199'
    UNION ALL
    -- Glue
    SELECT 'GLUE', job_name, job_name, account_id, region FROM glue WHERE account_id = '729694432199'
    UNION ALL
    -- CloudFormation
    SELECT 'CLOUDFORMATION', stack_name, stack_name, account_id, region FROM cloudformation WHERE account_id = '729694432199'
    UNION ALL
    -- CloudTrail
    SELECT 'CLOUDTRAIL', trail_name, trail_name, account_id, region FROM cloudtrail_trails WHERE account_id = '729694432199'
    UNION ALL
    -- SSM
    SELECT 'SSM', COALESCE(association_name, association_id), association_id, account_id, region FROM ssm WHERE account_id = '729694432199'
    UNION ALL
    -- Step Functions
    SELECT 'STEPFUNCTIONS', stepfunction_name, stepfunction_arn, account_id, region FROM stepfunctions WHERE account_id = '729694432199'
    UNION ALL
    -- Athena
    SELECT 'ATHENA', COALESCE(query_name, query_id), query_id, account_id, region FROM athena WHERE account_id = '729694432199'
    UNION ALL
    -- CodePipeline
    SELECT 'CODEPIPELINE', pipeline_name, pipeline_name, account_id, region FROM codepipeline WHERE account_id = '729694432199'
)

-- Todos los recursos por servicio
SELECT 
    'ALL_' || service_type as diagram_type,
    service_type || '_RESOURCES' as group_name,
    lower(service_type) || '-resources' as group_id,
    name as source_name,
    service_type as source_type,
    id as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    account as target_id,
    'BELONGS_TO' as relationship,
    region
FROM account_resources

UNION ALL

-- Relaciones VPC: EC2 en VPCs
SELECT 
    'VPC_NETWORK',
    v.vpc_name,
    v.vpc_id,
    e.instancename,
    'EC2',
    e.instanceid,
    v.vpc_name,
    'VPC',
    v.vpc_id,
    'RUNS_IN',
    e.region
FROM vpcs v
JOIN ec2 e ON v.vpc_id = e.vpc AND v.account_id = e.accountid
WHERE v.account_id = '729694432199'

UNION ALL

-- Relaciones VPC: RDS en VPCs  
SELECT 
    'VPC_NETWORK',
    v.vpc_name,
    v.vpc_id,
    r.dbname,
    'RDS',
    r.dbinstanceid,
    v.vpc_name,
    'VPC',
    v.vpc_id,
    'RUNS_IN',
    r.region
FROM vpcs v
JOIN rds r ON v.account_id = r.accountid
WHERE v.account_id = '729694432199'

UNION ALL

-- Relaciones Subnet: EC2 en Subnets
SELECT 
    'SUBNET_NETWORK',
    COALESCE(s.subnetname, s.subnetid),
    s.subnetid,
    e.instancename,
    'EC2',
    e.instanceid,
    COALESCE(s.subnetname, s.subnetid),
    'SUBNET',
    s.subnetid,
    'BELONGS_TO',
    e.region
FROM subnets s
JOIN ec2 e ON s.subnetid = e.subnet AND s.accountid = e.accountid
WHERE s.accountid = '729694432199'

ORDER BY diagram_type, group_name, source_type, source_name;