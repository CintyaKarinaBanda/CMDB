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

-- Lambda Triggers - Todos los tipos
SELECT 
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' OR trigger_clean LIKE 'DynamoDB:%' OR trigger_clean LIKE 'Kinesis:%' OR 
             trigger_clean LIKE 'MSK:%' OR trigger_clean LIKE 'API Gateway%' OR trigger_clean LIKE 'S3:%' OR 
             trigger_clean LIKE 'EventBridge:%' OR trigger_clean LIKE 'SNS:%' OR trigger_clean LIKE 'IoT:%' OR 
             trigger_clean LIKE 'Cognito:%' OR trigger_clean LIKE 'Alexa:%' OR trigger_clean LIKE 'Lex:%' OR 
             trigger_clean LIKE 'DocumentDB:%' THEN 'SERVICE_INTEGRATION'
        ELSE 'ACCOUNT_OWNERSHIP'
    END as relationship_type,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' THEN 'SQS_TO_LAMBDA'
        WHEN trigger_clean LIKE 'DynamoDB:%' THEN 'DYNAMODB_TO_LAMBDA'
        WHEN trigger_clean LIKE 'Kinesis:%' THEN 'KINESIS_TO_LAMBDA'
        WHEN trigger_clean LIKE 'MSK:%' THEN 'MSK_TO_LAMBDA'
        WHEN trigger_clean LIKE 'API Gateway%' THEN 'APIGATEWAY_TO_LAMBDA'
        WHEN trigger_clean LIKE 'S3:%' THEN 'S3_TO_LAMBDA'
        WHEN trigger_clean LIKE 'EventBridge:%' THEN 'EVENTBRIDGE_TO_LAMBDA'
        WHEN trigger_clean LIKE 'SNS:%' THEN 'SNS_TO_LAMBDA'
        WHEN trigger_clean LIKE 'IoT:%' THEN 'IOT_TO_LAMBDA'
        WHEN trigger_clean LIKE 'Cognito:%' THEN 'COGNITO_TO_LAMBDA'
        WHEN trigger_clean LIKE 'Alexa:%' THEN 'ALEXA_TO_LAMBDA'
        WHEN trigger_clean LIKE 'Lex:%' THEN 'LEX_TO_LAMBDA'
        WHEN trigger_clean LIKE 'DocumentDB:%' THEN 'DOCUMENTDB_TO_LAMBDA'
        ELSE 'LAMBDA_TO_ACCOUNT'
    END as relationship_subtype,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' OR trigger_clean LIKE 'DynamoDB:%' OR trigger_clean LIKE 'Kinesis:%' OR 
             trigger_clean LIKE 'MSK:%' OR trigger_clean LIKE 'API Gateway%' OR trigger_clean LIKE 'S3:%' OR 
             trigger_clean LIKE 'EventBridge:%' OR trigger_clean LIKE 'SNS:%' OR trigger_clean LIKE 'IoT:%' OR 
             trigger_clean LIKE 'Cognito:%' OR trigger_clean LIKE 'Alexa:%' OR trigger_clean LIKE 'Lex:%' OR 
             trigger_clean LIKE 'DocumentDB:%' THEN COALESCE(NULLIF(SUBSTRING(trigger_clean FROM '.*:(.*)'), ''), trigger_clean)
        ELSE l.functionname
    END as source_name,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' THEN 'SQS'
        WHEN trigger_clean LIKE 'DynamoDB:%' THEN 'DYNAMODB'
        WHEN trigger_clean LIKE 'Kinesis:%' THEN 'KINESIS'
        WHEN trigger_clean LIKE 'MSK:%' THEN 'MSK'
        WHEN trigger_clean LIKE 'API Gateway%' THEN 'APIGATEWAY'
        WHEN trigger_clean LIKE 'S3:%' THEN 'S3'
        WHEN trigger_clean LIKE 'EventBridge:%' THEN 'EVENTBRIDGE'
        WHEN trigger_clean LIKE 'SNS:%' THEN 'SNS'
        WHEN trigger_clean LIKE 'IoT:%' THEN 'IOT'
        WHEN trigger_clean LIKE 'Cognito:%' THEN 'COGNITO'
        WHEN trigger_clean LIKE 'Alexa:%' THEN 'ALEXA'
        WHEN trigger_clean LIKE 'Lex:%' THEN 'LEX'
        WHEN trigger_clean LIKE 'DocumentDB:%' THEN 'DOCUMENTDB'
        ELSE 'LAMBDA'
    END as source_type,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' OR trigger_clean LIKE 'DynamoDB:%' OR trigger_clean LIKE 'Kinesis:%' OR 
             trigger_clean LIKE 'MSK:%' OR trigger_clean LIKE 'API Gateway%' OR trigger_clean LIKE 'S3:%' OR 
             trigger_clean LIKE 'EventBridge:%' OR trigger_clean LIKE 'SNS:%' OR trigger_clean LIKE 'IoT:%' OR 
             trigger_clean LIKE 'Cognito:%' OR trigger_clean LIKE 'Alexa:%' OR trigger_clean LIKE 'Lex:%' OR 
             trigger_clean LIKE 'DocumentDB:%' THEN COALESCE(NULLIF(SUBSTRING(trigger_clean FROM '.*:(.*)'), ''), trigger_clean)
        ELSE l.functionid
    END as source_id,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' OR trigger_clean LIKE 'DynamoDB:%' OR trigger_clean LIKE 'Kinesis:%' OR 
             trigger_clean LIKE 'MSK:%' OR trigger_clean LIKE 'API Gateway%' OR trigger_clean LIKE 'S3:%' OR 
             trigger_clean LIKE 'EventBridge:%' OR trigger_clean LIKE 'SNS:%' OR trigger_clean LIKE 'IoT:%' OR 
             trigger_clean LIKE 'Cognito:%' OR trigger_clean LIKE 'Alexa:%' OR trigger_clean LIKE 'Lex:%' OR 
             trigger_clean LIKE 'DocumentDB:%' THEN l.functionname
        ELSE 'ACCOUNT'
    END as target_name,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' OR trigger_clean LIKE 'DynamoDB:%' OR trigger_clean LIKE 'Kinesis:%' OR 
             trigger_clean LIKE 'MSK:%' OR trigger_clean LIKE 'API Gateway%' OR trigger_clean LIKE 'S3:%' OR 
             trigger_clean LIKE 'EventBridge:%' OR trigger_clean LIKE 'SNS:%' OR trigger_clean LIKE 'IoT:%' OR 
             trigger_clean LIKE 'Cognito:%' OR trigger_clean LIKE 'Alexa:%' OR trigger_clean LIKE 'Lex:%' OR 
             trigger_clean LIKE 'DocumentDB:%' THEN 'LAMBDA'
        ELSE 'ACCOUNT'
    END as target_type,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' OR trigger_clean LIKE 'DynamoDB:%' OR trigger_clean LIKE 'Kinesis:%' OR 
             trigger_clean LIKE 'MSK:%' OR trigger_clean LIKE 'API Gateway%' OR trigger_clean LIKE 'S3:%' OR 
             trigger_clean LIKE 'EventBridge:%' OR trigger_clean LIKE 'SNS:%' OR trigger_clean LIKE 'IoT:%' OR 
             trigger_clean LIKE 'Cognito:%' OR trigger_clean LIKE 'Alexa:%' OR trigger_clean LIKE 'Lex:%' OR 
             trigger_clean LIKE 'DocumentDB:%' THEN l.functionid
        ELSE l.accountid
    END as target_id,
    CASE 
        WHEN trigger_clean LIKE 'SQS:%' OR trigger_clean LIKE 'DynamoDB:%' OR trigger_clean LIKE 'Kinesis:%' OR 
             trigger_clean LIKE 'MSK:%' OR trigger_clean LIKE 'API Gateway%' OR trigger_clean LIKE 'S3:%' OR 
             trigger_clean LIKE 'EventBridge:%' OR trigger_clean LIKE 'SNS:%' OR trigger_clean LIKE 'IoT:%' OR 
             trigger_clean LIKE 'Cognito:%' OR trigger_clean LIKE 'Alexa:%' OR trigger_clean LIKE 'Lex:%' OR 
             trigger_clean LIKE 'DocumentDB:%' THEN 'TRIGGERS'
        ELSE 'BELONGS_TO'
    END as relationship,
    l.region,
    l.accountid as account_id
FROM lambda_functions l,
     UNNEST(string_to_array(TRIM(BOTH '[]"' FROM REPLACE(l.triggers, '"', '')), ',')) as trigger_raw(trigger_item)
CROSS JOIN LATERAL (
    SELECT TRIM(trigger_item) as trigger_clean
) t
WHERE l.accountid = $1
  AND l.triggers IS NOT NULL 
  AND l.triggers != '' 
  AND l.triggers != '[]'
  AND l.triggers != '["Manual"]'
  AND trigger_clean != ''
  AND trigger_clean != 'Manual'
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