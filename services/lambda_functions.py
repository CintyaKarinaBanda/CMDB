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

def get_lambda_triggers(lambda_client, function_name, function_arn, region, credentials):
    """Obtiene todos los triggers asociados a la función Lambda"""
    triggers = set()
    
    # Event source mappings (código existente)
    try:
        response = lambda_client.list_event_source_mappings(FunctionName=function_name)
        for mapping in response.get("EventSourceMappings", []):
            arn = mapping.get("EventSourceArn", "")
            state = mapping.get("State", "")
            if state == "Enabled" and arn:
                if "sqs" in arn.lower():
                    triggers.add(f"SQS:{arn.split(':')[-1]}")
                elif "dynamodb" in arn.lower():
                    triggers.add(f"DynamoDB:{arn.split('/')[-1]}")
                elif "kinesis" in arn.lower():
                    triggers.add(f"Kinesis:{arn.split('/')[-1]}")
                else:
                    service_type = arn.split(':')[2] if ':' in arn else "Unknown"
                    triggers.add(f"{service_type.upper()}:{arn.split(':')[-1] if ':' in arn else arn}")
    except ClientError:
        pass

    # Function policy (código existente)
    try:
        policy_response = lambda_client.get_policy(FunctionName=function_name)
        policy = json.loads(policy_response.get("Policy", "{}"))
        
        for statement in policy.get("Statement", []):
            principal = statement.get("Principal", {})
            
            if isinstance(principal, str):
                service = principal
            elif isinstance(principal, dict):
                service = principal.get("Service", "")
            else:
                continue
            
            if "apigateway" in service.lower():
                triggers.add("API Gateway")
            elif "s3" in service.lower():
                triggers.add("S3")
            elif "events" in service.lower():
                triggers.add("EventBridge")
            elif "sns" in service.lower():
                triggers.add("SNS")
    except ClientError:
        pass

    # NUEVO: Verificar EventBridge Rules
    try:
        events_client = create_aws_client("events", region, credentials)
        if events_client:
            paginator = events_client.get_paginator('list_rules')
            for page in paginator.paginate():
                for rule in page.get('Rules', []):
                    if rule.get('State') == 'ENABLED':
                        try:
                            targets = events_client.list_targets_by_rule(Rule=rule['Name'])
                            for target in targets.get('Targets', []):
                                if target.get('Arn') == function_arn:
                                    triggers.add(f"EventBridge:{rule['Name']}")
                        except ClientError:
                            continue
    except:
        pass

    # NUEVO: Verificar API Gateway
    try:
        apigateway_client = create_aws_client("apigateway", region, credentials)
        if apigateway_client:
            apis = apigateway_client.get_rest_apis()
            for api in apis.get('items', []):
                api_id = api['id']
                try:
                    resources = apigateway_client.get_resources(restApiId=api_id)
                    for resource in resources.get('items', []):
                        for method_name, method in resource.get('resourceMethods', {}).items():
                            try:
                                method_details = apigateway_client.get_method(
                                    restApiId=api_id,
                                    resourceId=resource['id'],
                                    httpMethod=method_name
                                )
                                integration = method_details.get('methodIntegration', {})
                                if integration.get('uri', '').endswith(function_name):
                                    triggers.add(f"API Gateway:{api_id}")
                            except ClientError:
                                continue
                except ClientError:
                    continue
    except:
        pass

    return sorted(list(triggers)) if triggers else ["Manual/Unknown"]


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
