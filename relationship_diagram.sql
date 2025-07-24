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

-- 2. TODOS LOS EC2
SELECT
    'ALL_EC2' as diagram_type,
    'EC2_INSTANCES' as group_name,
    'ec2-instances' as group_id,
    e.instancename as source_name,
    'EC2' as source_type,
    e.instanceid as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    e.accountid as target_id,
    'BELONGS_TO' as relationship,
    e.region
FROM ec2 e
WHERE e.accountid = '729694432199'

UNION ALL

-- 3. TODAS LAS RDS
SELECT
    'ALL_RDS' as diagram_type,
    'RDS_DATABASES' as group_name,
    'rds-databases' as group_id,
    r.dbname as source_name,
    'RDS' as source_type,
    r.dbinstanceid as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    r.accountid as target_id,
    'BELONGS_TO' as relationship,
    r.region
FROM rds r
WHERE r.accountid = '729694432199'

UNION ALL

-- 4. TODAS LAS LAMBDAS
SELECT
    'ALL_LAMBDA' as diagram_type,
    'LAMBDA_FUNCTIONS' as group_name,
    'lambda-functions' as group_id,
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

-- 5. TODAS LAS VPCs
SELECT
    'ALL_VPC' as diagram_type,
    'VPC_NETWORKS' as group_name,
    'vpc-networks' as group_id,
    v.vpc_name as source_name,
    'VPC' as source_type,
    v.vpc_id as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    v.account_id as target_id,
    'BELONGS_TO' as relationship,
    v.region
FROM vpcs v
WHERE v.account_id = '729694432199'

UNION ALL

-- 6. TODAS LAS SUBNETS
SELECT
    'ALL_SUBNET' as diagram_type,
    'SUBNETS' as group_name,
    'subnets' as group_id,
    COALESCE(s.subnetname, s.subnetid) as source_name,
    'SUBNET' as source_type,
    s.subnetid as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    s.accountid as target_id,
    'BELONGS_TO' as relationship,
    s.region
FROM subnets s
WHERE s.accountid = '729694432199'

UNION ALL

-- 7. TODOS LOS S3 BUCKETS
SELECT
    'ALL_S3' as diagram_type,
    'S3_BUCKETS' as group_name,
    's3-buckets' as group_id,
    s.bucket_name_display as source_name,
    'S3' as source_type,
    s.bucket_name as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    s.account_id as target_id,
    'BELONGS_TO' as relationship,
    s.region
FROM s3 s
WHERE s.account_id = '729694432199'

UNION ALL

-- 8. TODOS LOS API GATEWAYS
SELECT
    'ALL_APIGATEWAY' as diagram_type,
    'API_GATEWAYS' as group_name,
    'api-gateways' as group_id,
    a.name as source_name,
    'APIGATEWAY' as source_type,
    a.api_id as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    a.account_id as target_id,
    'BELONGS_TO' as relationship,
    a.region
FROM apigateway a
WHERE a.account_id = '729694432199'

UNION ALL

-- 9. TODOS LOS REDSHIFT
SELECT
    'ALL_REDSHIFT' as diagram_type,
    'REDSHIFT_CLUSTERS' as group_name,
    'redshift-clusters' as group_id,
    r.database_name as source_name,
    'REDSHIFT' as source_type,
    r.database_id as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    r.account_id as target_id,
    'BELONGS_TO' as relationship,
    r.region
FROM redshift r
WHERE r.account_id = '729694432199'

UNION ALL

-- 10. TODOS LOS EKS
SELECT
    'ALL_EKS' as diagram_type,
    'EKS_CLUSTERS' as group_name,
    'eks-clusters' as group_id,
    e.clustername as source_name,
    'EKS' as source_type,
    e.clusterid as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    e.accountid as target_id,
    'BELONGS_TO' as relationship,
    'N/A' as region
FROM eks e
WHERE e.accountid = '729694432199'

UNION ALL

-- 11. TODOS LOS ECR
SELECT
    'ALL_ECR' as diagram_type,
    'ECR_REPOSITORIES' as group_name,
    'ecr-repositories' as group_id,
    e.repositoryname as source_name,
    'ECR' as source_type,
    e.repositoryname as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    e.accountid as target_id,
    'BELONGS_TO' as relationship,
    'N/A' as region
FROM ecr e
WHERE e.accountid = '729694432199'

UNION ALL

-- 12. TODOS LOS KMS
SELECT
    'ALL_KMS' as diagram_type,
    'KMS_KEYS' as group_name,
    'kms-keys' as group_id,
    COALESCE(k.keyname, k.keyid) as source_name,
    'KMS' as source_type,
    k.keyid as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    k.accountid as target_id,
    'BELONGS_TO' as relationship,
    'N/A' as region
FROM kms k
WHERE k.accountid = '729694432199'

UNION ALL

-- 13. TODOS LOS GLUE
SELECT
    'ALL_GLUE' as diagram_type,
    'GLUE_JOBS' as group_name,
    'glue-jobs' as group_id,
    g.job_name as source_name,
    'GLUE' as source_type,
    g.job_name as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    g.account_id as target_id,
    'BELONGS_TO' as relationship,
    g.region
FROM glue g
WHERE g.account_id = '729694432199'

UNION ALL

-- 14. TODOS LOS CLOUDFORMATION
SELECT
    'ALL_CLOUDFORMATION' as diagram_type,
    'CLOUDFORMATION_STACKS' as group_name,
    'cloudformation-stacks' as group_id,
    c.stack_name as source_name,
    'CLOUDFORMATION' as source_type,
    c.stack_name as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    c.account_id as target_id,
    'BELONGS_TO' as relationship,
    c.region
FROM cloudformation c
WHERE c.account_id = '729694432199'

UNION ALL

-- 15. TODOS LOS CLOUDTRAIL
SELECT
    'ALL_CLOUDTRAIL' as diagram_type,
    'CLOUDTRAIL_TRAILS' as group_name,
    'cloudtrail-trails' as group_id,
    c.trail_name as source_name,
    'CLOUDTRAIL' as source_type,
    c.trail_name as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    c.account_id as target_id,
    'BELONGS_TO' as relationship,
    c.region
FROM cloudtrail_trails c
WHERE c.account_id = '729694432199'

UNION ALL

-- 16. TODOS LOS SSM
SELECT
    'ALL_SSM' as diagram_type,
    'SSM_ASSOCIATIONS' as group_name,
    'ssm-associations' as group_id,
    COALESCE(s.association_name, s.association_id) as source_name,
    'SSM' as source_type,
    s.association_id as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    s.account_id as target_id,
    'BELONGS_TO' as relationship,
    s.region
FROM ssm s
WHERE s.account_id = '729694432199'

UNION ALL

-- 17. TODOS LOS STEP FUNCTIONS
SELECT
    'ALL_STEPFUNCTIONS' as diagram_type,
    'STEP_FUNCTIONS' as group_name,
    'step-functions' as group_id,
    s.stepfunction_name as source_name,
    'STEPFUNCTIONS' as source_type,
    s.stepfunction_arn as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    s.account_id as target_id,
    'BELONGS_TO' as relationship,
    s.region
FROM stepfunctions s
WHERE s.account_id = '729694432199'

UNION ALL

-- 18. TODOS LOS ATHENA
SELECT
    'ALL_ATHENA' as diagram_type,
    'ATHENA_QUERIES' as group_name,
    'athena-queries' as group_id,
    COALESCE(a.query_name, a.query_id) as source_name,
    'ATHENA' as source_type,
    a.query_id as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    a.account_id as target_id,
    'BELONGS_TO' as relationship,
    a.region
FROM athena a
WHERE a.account_id = '729694432199'

UNION ALL

-- 19. TODOS LOS CODEPIPELINE
SELECT
    'ALL_CODEPIPELINE' as diagram_type,
    'CODE_PIPELINES' as group_name,
    'code-pipelines' as group_id,
    c.pipeline_name as source_name,
    'CODEPIPELINE' as source_type,
    c.pipeline_name as source_id,
    'ACCOUNT' as target_name,
    'ACCOUNT' as target_type,
    c.account_id as target_id,
    'BELONGS_TO' as relationship,
    c.region
FROM codepipeline c
WHERE c.account_id = '729694432199'

UNION ALL

-- 20. SUBNET RELATIONSHIPS: Recursos en la misma subnet
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
