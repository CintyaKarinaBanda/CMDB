from botocore.exceptions import ClientError
from datetime import datetime
import json
from services.utils import create_aws_client, get_db_connection, log_change

FIELD_EVENT_MAP = {
    "functionname": ["CreateFunction", "UpdateFunctionConfiguration"],
    "description": ["UpdateFunctionConfiguration"],
    "handler": ["UpdateFunctionConfiguration"],
    "runtime": ["UpdateFunctionConfiguration"],
    "memorysize": ["UpdateFunctionConfiguration"],
    "timeout": ["UpdateFunctionConfiguration"],
    "role": ["UpdateFunctionConfiguration"],
    "environment": ["UpdateFunctionConfiguration"],
    "vpcconfig": ["UpdateFunctionConfiguration"],
    "tags": ["TagResource", "UntagResource"]
}

def normalize_list_comparison(old_val, new_val):
    """Normaliza listas para comparación, ignorando orden"""
    if isinstance(new_val, list):
        old_list = old_val if isinstance(old_val, list) else str(old_val).split(',') if old_val else []
        return sorted(map(str, old_list)) == sorted(map(str, new_val))
    return str(old_val) == str(new_val)

def get_function_changed_by(function_name, field_name):
    conn = get_db_connection()
    if not conn:
        return "unknown"
    try:
        with conn.cursor() as cursor:
            events = FIELD_EVENT_MAP.get(field_name, [])
            placeholders = ','.join(['%s'] * len(events))
            sql = f"""
                SELECT user_name 
                FROM cloudtrail_events 
                WHERE resource_name = %s AND resource_type = 'LAMBDA'
                {"AND event_name IN (" + placeholders + ")" if events else ""}
                ORDER BY event_time DESC LIMIT 1
            """
            cursor.execute(sql, (function_name, *events) if events else (function_name,))
            row = cursor.fetchone()
            return row[0] if row else "unknown"
    except Exception:
        return "unknown"
    finally:
        conn.close()

def get_lambda_triggers(lambda_client, function_name):
    """Obtiene todos los triggers asociados a la función Lambda"""
    triggers = set()
    
    # Event source mappings
    try:
        response = lambda_client.list_event_source_mappings(FunctionName=function_name)
        print(f"Event source mappings for {function_name}: {response}")
        for mapping in response.get("EventSourceMappings", []):
            arn = mapping.get("EventSourceArn", "")
            state = mapping.get("State", "")
            if state == "Enabled" and arn:
                if "sqs" in arn.lower():
                    queue_name = arn.split(':')[-1]
                    triggers.add(f"SQS:{queue_name}")
                elif "dynamodb" in arn.lower():
                    table_name = arn.split('/')[-1]
                    triggers.add(f"DynamoDB:{table_name}")
                elif "kinesis" in arn.lower():
                    stream_name = arn.split('/')[-1]
                    triggers.add(f"Kinesis:{stream_name}")
                elif "kafka" in arn.lower():
                    cluster_name = arn.split('/')[-1]
                    triggers.add(f"MSK:{cluster_name}")
                else:
                    service_type = arn.split(':')[2] if ':' in arn else "Unknown"
                    resource_name = arn.split(':')[-1] if ':' in arn else arn
                    triggers.add(f"{service_type.upper()}:{resource_name}")
    except ClientError:
        pass

    # Function policy (API Gateway, S3, CloudWatch Events, etc.)
    try:
        policy_response = lambda_client.get_policy(FunctionName=function_name)
        policy = json.loads(policy_response.get("Policy", "{}"))
        
        for statement in policy.get("Statement", []):
            principal = statement.get("Principal", {})
            
            # Handle different principal formats
            if isinstance(principal, str):
                service = principal
            elif isinstance(principal, dict):
                service = principal.get("Service", "")
                aws_principal = principal.get("AWS", "")
                if aws_principal and not service:
                    # Could be cross-account access
                    account_id = aws_principal.split(':')[4] if ':' in str(aws_principal) else str(aws_principal)
                    triggers.add(f"Cross-Account:{account_id}")
                    continue
            else:
                continue
            
            # Extract source ARN from conditions
            condition = statement.get("Condition", {})
            source_arn = None
            for condition_type in ["ArnLike", "StringEquals", "StringLike", "ArnEquals"]:
                if condition_type in condition:
                    source_arn = (
                        condition[condition_type].get("AWS:SourceArn") or
                        condition[condition_type].get("aws:SourceArn")
                    )
                    if source_arn:
                        break
            
            # Identify service type and extract resource info
            if "apigateway" in service.lower():
                if source_arn and "execute-api" in source_arn:
                    api_parts = source_arn.split(":")
                    if len(api_parts) > 5:
                        api_id = api_parts[5].split("/")[0]
                        triggers.add(f"API Gateway:{api_id}")
                    else:
                        triggers.add("API Gateway")
                else:
                    triggers.add("API Gateway")
            elif "s3" in service.lower():
                if source_arn:
                    bucket_name = source_arn.replace("arn:aws:s3:::", "").split("/")[0]
                    triggers.add(f"S3:{bucket_name}")
                else:
                    triggers.add("S3")
            elif "events" in service.lower():
                if source_arn and "rule" in source_arn:
                    rule_name = source_arn.split("/")[-1]
                    triggers.add(f"EventBridge:{rule_name}")
                else:
                    triggers.add("EventBridge")
            elif "sns" in service.lower():
                if source_arn:
                    topic_name = source_arn.split(":")[-1]
                    triggers.add(f"SNS:{topic_name}")
                else:
                    triggers.add("SNS")
            elif "logs" in service.lower():
                if source_arn:
                    log_group = source_arn.split(":")[-1]
                    triggers.add(f"CloudWatch Logs:{log_group}")
                else:
                    triggers.add("CloudWatch Logs")
            elif "iot" in service.lower():
                triggers.add("IoT")
            elif "cognito" in service.lower():
                triggers.add("Cognito")
            elif "lex" in service.lower():
                triggers.add("Lex")
            elif "alexa" in service.lower():
                triggers.add("Alexa")
    except ClientError:
        pass

    # Check for CloudWatch Events/EventBridge rules that target this function
    try:
        events_client = lambda_client._client_config.region_name
        # This would require additional API calls to events service
        # For now, we rely on the policy-based detection above
        pass
    except:
        pass

    return sorted(list(triggers)) if triggers else ["None"]

def get_lambda_tags(lambda_client, function_arn):
    """Obtiene las tags asociadas a la función Lambda"""
    try:
        response = lambda_client.list_tags(Resource=function_arn)
        return response.get("Tags", {})
    except ClientError:
        return {}

def extract_lambda_data(function, lambda_client, account_name, account_id, region):
    function_name = function["FunctionName"]
    function_arn = function.get("FunctionArn", "")
    try:
        config = lambda_client.get_function_configuration(FunctionName=function_name)
    except ClientError:
        config = function  # fallback
    
    vpc_config = config.get("VpcConfig", {})
    vpc_info = (f"VPC:{vpc_config.get('VpcId', 'N/A')},Subnets:{len(vpc_config.get('SubnetIds', []))}"
                if vpc_config.get('VpcId') else "N/A")
    env_vars_count = len(config.get("Environment", {}).get("Variables", {}))
    triggers = get_lambda_triggers(lambda_client, function_name)
    tags = get_lambda_tags(lambda_client, function_arn)

    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "FunctionID": function_arn.split(":")[-1] if function_arn else function_name,
        "FunctionName": function_name,
        "Description": config.get("Description", "N/A"),
        "Handler": config.get("Handler", "N/A"),
        "Runtime": config.get("Runtime", "N/A"),
        "MemorySize": config.get("MemorySize", 0),
        "Timeout": config.get("Timeout", 0),
        "Role": config.get("Role", "N/A").split("/")[-1] if config.get("Role") else "N/A",
        "Environment": env_vars_count,
        "Triggers": json.dumps(triggers),  # Guardar como JSON
        "VPCConfig": vpc_info,
        "Region": region,
        "Tags": json.dumps(tags)
    }

def get_lambda_functions(region, credentials, account_id, account_name):
    lambda_client = create_aws_client("lambda", region, credentials)
    if not lambda_client:
        return []
    functions_info = []
    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page.get("Functions", []):
                try:
                    data = extract_lambda_data(function, lambda_client, account_name, account_id, region)
                    functions_info.append(data)
                except Exception:
                    continue
        return functions_info
    except ClientError:
        return []

def insert_or_update_lambda_data(lambda_data):
    if not lambda_data:
        return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    inserted = updated = processed = 0
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM lambda_functions")
            columns = [desc[0].lower() for desc in cursor.description]
            existing = {(row[columns.index("functionname")], row[columns.index("accountid")]): dict(zip(columns, row)) for row in cursor.fetchall()}

            for func in lambda_data:
                processed += 1
                key = (func["FunctionName"], func["AccountID"])
                values = (
                    func["AccountName"], func["AccountID"], func["FunctionID"], func["FunctionName"],
                    func["Description"], func["Handler"], func["Runtime"], func["MemorySize"],
                    func["Timeout"], func["Role"], func["Environment"], func["Triggers"],
                    func["VPCConfig"], func["Region"], func["Tags"]
                )

                if key not in existing:
                    cursor.execute("""
                        INSERT INTO lambda_functions
                        (AccountName, AccountID, FunctionID, FunctionName, Description, Handler,
                        Runtime, MemorySize, Timeout, Role, Environment, Triggers, VPCConfig, Region, Tags, last_updated)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """, values)
                    inserted += 1
                else:
                    cursor.execute("""
                        UPDATE lambda_functions
                        SET AccountName=%s, Description=%s, Handler=%s, Runtime=%s,
                            MemorySize=%s, Timeout=%s, Role=%s, Environment=%s,
                            Triggers=%s, VPCConfig=%s, Region=%s, Tags=%s, last_updated=NOW()
                        WHERE FunctionName=%s AND AccountID=%s
                    """, (
                        func["AccountName"], func["Description"], func["Handler"], func["Runtime"],
                        func["MemorySize"], func["Timeout"], func["Role"], func["Environment"],
                        func["Triggers"], func["VPCConfig"], func["Region"], func["Tags"],
                        func["FunctionName"], func["AccountID"]
                    ))
                    updated += 1
            conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()
