-- RELACIÓN JERÁRQUICA: SERVICIOS → SUBNET → VPC + LAMBDA TRIGGERS
-- Parámetro: $1 (accountId)

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
WHERE e.accountid = $1
  AND DATE(e.last_updated) = CURRENT_DATE

UNION ALL

-- LAMBDA con VPC pertenece a SUBNET
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
WHERE l.accountid = $1
  AND l.vpcconfig LIKE 'VPC:%'
  AND DATE(l.last_updated) = CURRENT_DATE

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
WHERE s.accountid = $1
  AND DATE(s.last_updated) = CURRENT_DATE
  AND DATE(v.last_updated) = CURRENT_DATE

UNION ALL

-- Lambda Triggers - Simplified parsing
SELECT 
    'SERVICE_INTEGRATION' as relationship_type,
    CASE 
        WHEN trigger_clean LIKE 'apigateway %' THEN 'APIGATEWAY_TO_LAMBDA'
        WHEN trigger_clean LIKE 's3 %' THEN 'S3_TO_LAMBDA'
        WHEN trigger_clean LIKE 'events %' THEN 'EVENTBRIDGE_TO_LAMBDA'
        WHEN trigger_clean LIKE 'sns %' THEN 'SNS_TO_LAMBDA'
        WHEN trigger_clean LIKE 'iot %' THEN 'IOT_TO_LAMBDA'
        WHEN trigger_clean LIKE 'cognito-idp %' THEN 'COGNITO_TO_LAMBDA'
        WHEN trigger_clean LIKE 'lex %' THEN 'LEX_TO_LAMBDA'
        WHEN trigger_clean LIKE 'lexv2 %' THEN 'LEXV2_TO_LAMBDA'
        WHEN trigger_clean = 'alexa-connectedhome' THEN 'ALEXA_TO_LAMBDA'
        WHEN trigger_clean = 'alexa-appkit' THEN 'ALEXA_TO_LAMBDA'
        WHEN trigger_clean LIKE 'cloudwatch %' THEN 'CLOUDWATCH_TO_LAMBDA'
        WHEN trigger_clean LIKE 'elasticloadbalancing %' THEN 'ELB_TO_LAMBDA'
        WHEN trigger_clean = 'cloudformation' THEN 'CLOUDFORMATION_TO_LAMBDA'
        WHEN trigger_clean = 's3' THEN 'S3_TO_LAMBDA'
        WHEN trigger_clean = 'events' THEN 'EVENTBRIDGE_TO_LAMBDA'
        ELSE 'OTHER_TO_LAMBDA'
    END as relationship_subtype,
    CASE 
        WHEN trigger_clean LIKE '%arn:aws:s3:::%' THEN 
            SPLIT_PART(SPLIT_PART(trigger_clean, 'arn:aws:s3:::', 2), ' ', 1)
        WHEN trigger_clean LIKE '%arn:aws:execute-api:%' THEN 
            SPLIT_PART(trigger_clean, ':', 6)
        WHEN trigger_clean LIKE '%arn:aws:events:%' THEN 
            SPLIT_PART(SPLIT_PART(trigger_clean, ':', 6), '/', 2)
        WHEN trigger_clean LIKE '%arn:aws:sns:%' THEN 
            SPLIT_PART(trigger_clean, ':', 6)
        WHEN trigger_clean LIKE '%arn:aws:iot:%' THEN 
            SPLIT_PART(SPLIT_PART(trigger_clean, ':', 6), '/', 2)
        WHEN trigger_clean LIKE '%arn:aws:cognito-idp:%' THEN 
            SPLIT_PART(trigger_clean, '/', 2)
        WHEN trigger_clean LIKE '%arn:aws:lex:%' THEN 
            SPLIT_PART(SPLIT_PART(trigger_clean, ':', 6), ':', 2)
        ELSE trigger_clean
    END as source_name,
    CASE 
        WHEN trigger_clean LIKE 'apigateway %' THEN 'APIGATEWAY'
        WHEN trigger_clean LIKE 's3 %' OR trigger_clean = 's3' THEN 'S3'
        WHEN trigger_clean LIKE 'events %' OR trigger_clean = 'events' THEN 'EVENTBRIDGE'
        WHEN trigger_clean LIKE 'sns %' THEN 'SNS'
        WHEN trigger_clean LIKE 'iot %' THEN 'IOT'
        WHEN trigger_clean LIKE 'cognito-idp %' THEN 'COGNITO'
        WHEN trigger_clean LIKE 'lex %' THEN 'LEX'
        WHEN trigger_clean LIKE 'lexv2 %' THEN 'LEXV2'
        WHEN trigger_clean = 'alexa-connectedhome' OR trigger_clean = 'alexa-appkit' THEN 'ALEXA'
        WHEN trigger_clean LIKE 'cloudwatch %' THEN 'CLOUDWATCH'
        WHEN trigger_clean LIKE 'elasticloadbalancing %' THEN 'ELB'
        WHEN trigger_clean = 'cloudformation' THEN 'CLOUDFORMATION'
        ELSE 'OTHER'
    END as source_type,
    CASE 
        WHEN trigger_clean LIKE '%arn:%' THEN 
            SPLIT_PART(trigger_clean, ' → ', 2)
        ELSE trigger_clean
    END as source_id,
    l.functionname as target_name,
    'LAMBDA' as target_type,
    l.functionid as target_id,
    'TRIGGERS' as relationship,
    l.region,
    l.accountid as account_id
FROM lambda_functions l
CROSS JOIN LATERAL (
    SELECT UNNEST(string_to_array(
        REPLACE(REPLACE(REPLACE(l.triggers, '["', ''), '"]', ''), '", "', '|'), 
        '|'
    )) as trigger_clean
) t
WHERE l.accountid = $1
  AND l.triggers IS NOT NULL 
  AND l.triggers != '' 
  AND l.triggers != '[]'
  AND l.triggers NOT IN ('["Sin triggers"]', '["None"]', '["Manual"]', '0')
  AND trigger_clean NOT IN ('Sin triggers', 'None', 'Manual', '0', '')
  AND DATE(l.last_updated) = CURRENT_DATE

UNION ALL

-- Lambda VPC relationships
SELECT 
    'NETWORK_INTEGRATION' as relationship_type,
    'LAMBDA_TO_VPC' as relationship_subtype,
    l.functionname as source_name,
    'LAMBDA' as source_type,
    l.functionid as source_id,
    SUBSTRING(l.vpcconfig FROM 'VPC:([^,]*)') as target_name,
    'VPC' as target_type,
    SUBSTRING(l.vpcconfig FROM 'VPC:([^,]*)') as target_id,
    'RUNS_IN' as relationship,
    l.region,
    l.accountid as account_id
FROM lambda_functions l
WHERE l.accountid = $1
  AND l.vpcconfig IS NOT NULL 
  AND l.vpcconfig LIKE 'VPC:%'
  AND l.vpcconfig != 'VPC:N/A'
  AND DATE(l.last_updated) = CURRENT_DATE

ORDER BY relationship_type, relationship_subtype, source_name;