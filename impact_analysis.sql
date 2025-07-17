-- Consulta para Diagrama de Impacto por Cuenta
-- Reemplazar 'ACCOUNT_ID_HERE' con el ID de cuenta específico

WITH account_resources AS (
    -- EC2 Instances
    SELECT 
        'EC2' as resource_type,
        instanceid as resource_id,
        instancename as resource_name,
        vpc as vpc_info,
        subnet as subnet_info,
        securitygroups::text as security_groups,
        region,
        accountid
    FROM ec2 
    WHERE accountid = 'ACCOUNT_ID_HERE'
    
    UNION ALL
    
    -- RDS Instances
    SELECT 
        'RDS' as resource_type,
        dbinstanceid as resource_id,
        dbname as resource_name,
        NULL as vpc_info,
        NULL as subnet_info,
        NULL as security_groups,
        region,
        accountid
    FROM rds 
    WHERE accountid = 'ACCOUNT_ID_HERE'
    
    UNION ALL
    
    -- Lambda Functions
    SELECT 
        'LAMBDA' as resource_type,
        functionid as resource_id,
        functionname as resource_name,
        vpcconfig as vpc_info,
        NULL as subnet_info,
        NULL as security_groups,
        region,
        accountid
    FROM lambda_functions 
    WHERE accountid = 'ACCOUNT_ID_HERE'
    
    UNION ALL
    
    -- VPCs
    SELECT 
        'VPC' as resource_type,
        vpc_id as resource_id,
        vpc_name as resource_name,
        vpc_id as vpc_info,
        NULL as subnet_info,
        security_groups::text as security_groups,
        region,
        account_id as accountid
    FROM vpcs 
    WHERE account_id = 'ACCOUNT_ID_HERE'
    
    UNION ALL
    
    -- Subnets
    SELECT 
        'SUBNET' as resource_type,
        subnetid as resource_id,
        subnetname as resource_name,
        vpcid as vpc_info,
        subnetid as subnet_info,
        securitygroups as security_groups,
        region,
        accountid
    FROM subnets 
    WHERE accountid = 'ACCOUNT_ID_HERE'
    
    UNION ALL
    
    -- S3 Buckets
    SELECT 
        'S3' as resource_type,
        bucket_name as resource_id,
        bucket_name_display as resource_name,
        NULL as vpc_info,
        NULL as subnet_info,
        NULL as security_groups,
        region,
        account_id as accountid
    FROM s3 
    WHERE account_id = 'ACCOUNT_ID_HERE'
    
    UNION ALL
    
    -- API Gateway
    SELECT 
        'APIGATEWAY' as resource_type,
        api_id as resource_id,
        name as resource_name,
        NULL as vpc_info,
        NULL as subnet_info,
        NULL as security_groups,
        region,
        account_id as accountid
    FROM apigateway 
    WHERE account_id = 'ACCOUNT_ID_HERE'
),

-- Lambda triggers con detalles
lambda_triggers AS (
    SELECT 
        l.functionname as lambda_name,
        l.functionid as lambda_id,
        CASE 
            WHEN l.triggers LIKE '%API Gateway:%' THEN 
                regexp_replace(l.triggers, '.*"API Gateway:([^"]+)".*', '\1')
            ELSE NULL
        END as api_gateway_id,
        CASE 
            WHEN l.triggers LIKE '%S3:%' THEN 
                regexp_replace(l.triggers, '.*"S3:([^"]+)".*', '\1')
            ELSE NULL
        END as s3_bucket,
        l.triggers,
        l.region,
        l.accountid
    FROM lambda_functions l
    WHERE l.accountid = 'ACCOUNT_ID_HERE'
      AND l.triggers != '["None"]'
)

-- Consulta principal: Recursos por tipo
SELECT 
    'INVENTORY' as analysis_type,
    resource_type,
    COUNT(*) as resource_count,
    string_agg(DISTINCT region, ', ') as regions,
    string_agg(resource_name, ', ' ORDER BY resource_name) as resource_names
FROM account_resources
GROUP BY resource_type

UNION ALL

-- VPC Dependencies
SELECT 
    'VPC_DEPENDENCIES' as analysis_type,
    COALESCE(vpc_info, 'NO_VPC') as resource_type,
    COUNT(*) as resource_count,
    string_agg(DISTINCT region, ', ') as regions,
    string_agg(resource_type || ':' || resource_name, ', ') as resource_names
FROM account_resources
WHERE resource_type IN ('EC2', 'LAMBDA', 'SUBNET')
GROUP BY COALESCE(vpc_info, 'NO_VPC')

UNION ALL

-- Lambda Trigger Dependencies
SELECT 
    'LAMBDA_TRIGGERS' as analysis_type,
    'LAMBDA_TO_' || 
    CASE 
        WHEN api_gateway_id IS NOT NULL THEN 'APIGATEWAY'
        WHEN s3_bucket IS NOT NULL THEN 'S3'
        ELSE 'OTHER'
    END as resource_type,
    COUNT(*) as resource_count,
    string_agg(DISTINCT region, ', ') as regions,
    string_agg(
        lambda_name || ' -> ' || 
        COALESCE(api_gateway_id, s3_bucket, 'OTHER'), 
        ', '
    ) as resource_names
FROM lambda_triggers
WHERE api_gateway_id IS NOT NULL OR s3_bucket IS NOT NULL
GROUP BY 
    CASE 
        WHEN api_gateway_id IS NOT NULL THEN 'APIGATEWAY'
        WHEN s3_bucket IS NOT NULL THEN 'S3'
        ELSE 'OTHER'
    END

ORDER BY analysis_type, resource_type;