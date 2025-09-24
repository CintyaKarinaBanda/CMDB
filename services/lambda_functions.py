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

# amazonq-ignore-next-line
def normalize_list_comparison(old_val, new_val):
    """Normaliza listas para comparación, ignorando orden"""
    if isinstance(new_val, list):
        old_list = old_val if isinstance(old_val, list) else str(old_val).split(',') if old_val else []
        return sorted(map(str, old_list)) == sorted(map(str, new_val))
    return str(old_val) == str(new_val)

def get_function_changed_by(function_name, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'LAMBDA' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (function_name, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def get_lambda_triggers(lambda_client, function_name, function_arn, region, credentials):
    """Obtiene triggers de Lambda usando policy document"""
    triggers = []
    
    try:
        policy = lambda_client.get_policy(FunctionName=function_name)
        policy_doc = json.loads(policy['Policy'])
        
        for stmt in policy_doc.get('Statement', []):
            principal = stmt.get('Principal', {})
            service = principal.get('Service', 'N/A').split('.')[0] if isinstance(principal, dict) else 'N/A'
            arn = stmt.get('Condition', {}).get('ArnLike', {}).get('AWS:SourceArn', 'N/A')
            
            if service != 'N/A':
                trigger_info = f"{service} → {arn}" if arn != 'N/A' else service
                triggers.append(trigger_info)
                
    except lambda_client.exceptions.ResourceNotFoundException:
        triggers = ["Sin triggers"]
    except ClientError:
        triggers = ["Sin triggers"]
    
    return triggers if triggers else ["Sin triggers"]


def get_lambda_tags(lambda_client, function_arn):
    """Obtiene las tags asociadas a la función Lambda"""
    try:
        response = lambda_client.list_tags(Resource=function_arn)
        return response.get("Tags", {})
    # amazonq-ignore-next-line
    except ClientError:
        return {}

def extract_lambda_data(function, lambda_client, account_name, account_id, region, credentials):
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
    triggers = get_lambda_triggers(lambda_client, function_name, function_arn, region, credentials)
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
    print(f"[LAMBDA] Procesando cuenta: {account_name} ({account_id}) en región: {region}")
    lambda_client = create_aws_client("lambda", region, credentials)
    if not lambda_client:
        print(f"[LAMBDA] ERROR: No se pudo crear cliente para {account_name} en {region}")
        return []
    functions_info = []
    try:
        paginator = lambda_client.get_paginator('list_functions')
        function_count = 0
        for page in paginator.paginate():
            for function in page.get("Functions", []):
                try:
                    data = extract_lambda_data(function, lambda_client, account_name, account_id, region, credentials)
                    functions_info.append(data)
                    function_count += 1
                except Exception as e:
                    print(f"[LAMBDA] Error procesando función {function.get('FunctionName', 'unknown')}: {str(e)}")
                    continue
        print(f"[LAMBDA] Encontradas {function_count} funciones en {account_name} ({region})")
        return functions_info
    except ClientError as e:
        print(f"[LAMBDA] Error de cliente para {account_name} en {region}: {str(e)}")
        return []

def insert_or_update_lambda_data(lambda_data):
    if not lambda_data:
        print("[LAMBDA] No hay datos para procesar")
        return {"processed": 0, "inserted": 0, "updated": 0}
    print(f"[LAMBDA] Procesando {len(lambda_data)} funciones Lambda")
    conn = get_db_connection()
    if not conn:
        print("[LAMBDA] ERROR: Fallo en conexión a BD")
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    inserted = updated = processed = 0
    try:
        cursor = conn.cursor()
        
        # Obtener datos existentes usando clave compuesta (function_name, account_id, region)
        cursor.execute("SELECT * FROM lambda_functions")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {
            (row[columns.index("functionname")], row[columns.index("accountid")], row[columns.index("region")]): 
            dict(zip(columns, row)) for row in cursor.fetchall()
        }
        
        for func in lambda_data:
            function_name = func["FunctionName"]
            account_id = func["AccountID"]
            region = func["Region"]
            composite_key = (function_name, account_id, region)
            processed += 1
            
            insert_values = (
                func["AccountName"], func["AccountID"], func["FunctionName"],
                func["Description"], func["Handler"], func["Runtime"], func["MemorySize"],
                func["Timeout"], func["Role"], func["Environment"], func["Triggers"],
                func["VPCConfig"], func["Region"], func["Tags"]
            )
            
            if composite_key not in existing_data:
                cursor.execute("""
                    INSERT INTO lambda_functions (AccountName, AccountID, FunctionName, Description, Handler,
                    Runtime, MemorySize, Timeout, Role, Environment, Triggers, VPCConfig, Region, Tags, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, insert_values)
                inserted += 1
            else:
                db_row = existing_data[composite_key]
                updates = []
                values = []
                
                campos = {
                    "accountname": func["AccountName"],
                    "accountid": func["AccountID"],
                    "description": func["Description"],
                    "handler": func["Handler"],
                    "runtime": func["Runtime"],
                    "memorysize": func["MemorySize"],
                    "timeout": func["Timeout"],
                    "role": func["Role"],
                    "environment": func["Environment"],
                    "triggers": func["Triggers"],
                    "vpcconfig": func["VPCConfig"],
                    "region": func["Region"],
                    "tags": func["Tags"]
                }
                
                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_function_changed_by(function_name, datetime.now())
                        log_change('LAMBDA', function_name, col, old_val, new_val, changed_by, func["AccountID"], func["Region"])
                
                updates.append("last_updated = NOW()")
                
                if updates:
                    update_query = f"UPDATE lambda_functions SET {', '.join(updates)} WHERE functionname = %s AND accountid = %s AND region = %s"
                    values.extend([function_name, account_id, region])
                    cursor.execute(update_query, tuple(values))
                    updated += 1
                else:
                    cursor.execute("UPDATE lambda_functions SET last_updated = NOW() WHERE functionname = %s AND accountid = %s AND region = %s", [function_name, account_id, region])
        
        conn.commit()
        print(f"[LAMBDA] BD: {inserted} insertados, {updated} actualizados de {processed} procesados")
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        print(f"[LAMBDA] ERROR en BD: {str(e)}")
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()
