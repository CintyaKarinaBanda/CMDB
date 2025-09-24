from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_stepfunction_changed_by(stepfunction_arn, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'STEP-FUNCTIONS' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (stepfunction_arn, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_stepfunction_data(state_machine, stepfunctions_client, account_name, account_id, region):
    """Extrae datos relevantes de una Step Function"""
    state_machine_arn = state_machine["stateMachineArn"]
    
    # Obtener detalles adicionales
    try:
        details = stepfunctions_client.describe_state_machine(stateMachineArn=state_machine_arn)
        
        # Obtener tags
        tags_response = stepfunctions_client.list_tags_for_resource(resourceArn=state_machine_arn)
        tags = tags_response.get("tags", [])
        
        # Obtener versiones
        try:
            versions_response = stepfunctions_client.list_state_machine_versions(stateMachineArn=state_machine_arn)
            versions_count = len(versions_response.get("stateMachineVersions", []))
        except ClientError:
            versions_count = 1  # Al menos la versión actual
        
        # Obtener ejecuciones recientes para determinar triggers
        try:
            executions_response = stepfunctions_client.list_executions(
                stateMachineArn=state_machine_arn,
                maxResults=10
            )
            executions = executions_response.get("executions", [])
            triggers = len(set(exec.get("name", "").split("-")[0] for exec in executions if exec.get("name")))
            triggers = max(1, triggers)  # Al menos 1 trigger
        except ClientError:
            triggers = 1
        
        # Extraer información básica
        role_arn = details.get("roleArn", "N/A")
        role_name = role_arn.split("/")[-1] if role_arn != "N/A" else "N/A"
        
    except ClientError:
        versions_count = 1
        triggers = 1
        role_name = "N/A"
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "StepFunctionArn": state_machine_arn[:255],
        "InstanceId": state_machine_arn.split(":")[-1][:255],  # Nombre de la state machine
        "StepFunctionName": state_machine.get("name", "N/A")[:255],
        "Description": state_machine.get("definition", "N/A")[:500],  # Definición como descripción
        "Triggers": triggers,
        "Versions": versions_count,
        "RolesPermissions": role_name[:255],
        "Status": state_machine.get("status", "ACTIVE")[:50],
        "Region": region[:50]
    }

def get_stepfunctions_state_machines(region, credentials, account_id, account_name):
    """Obtiene Step Functions de una región."""
    stepfunctions_client = create_aws_client("stepfunctions", region, credentials)
    if not stepfunctions_client:
        return []

    try:
        paginator = stepfunctions_client.get_paginator('list_state_machines')
        stepfunctions_info = []

        for page in paginator.paginate():
            for state_machine in page.get("stateMachines", []):
                info = extract_stepfunction_data(state_machine, stepfunctions_client, account_name, account_id, region)
                stepfunctions_info.append(info)
        

        return stepfunctions_info
    except ClientError as e:
        pass
        return []

def insert_or_update_stepfunctions_data(stepfunctions_data):
    """Inserta o actualiza datos de Step Functions en la base de datos con seguimiento de cambios."""
    if not stepfunctions_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO stepfunctions (
            account_name, account_id, stepfunction_arn, instance_id, stepfunction_name,
            description, triggers, versions, roles_permissions, status, region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM stepfunctions")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("stepfunction_arn")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for stepfunction in stepfunctions_data:
            stepfunction_arn = stepfunction["StepFunctionArn"]
            processed += 1

            insert_values = (
                stepfunction["AccountName"], stepfunction["AccountID"], stepfunction["StepFunctionArn"],
                stepfunction["InstanceId"], stepfunction["StepFunctionName"], stepfunction["Description"],
                stepfunction["Triggers"], stepfunction["Versions"], stepfunction["RolesPermissions"],
                stepfunction["Status"], stepfunction["Region"]
            )

            if stepfunction_arn not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[stepfunction_arn]
                updates = []
                values = []

                campos = {
                    "account_name": stepfunction["AccountName"],
                    "account_id": stepfunction["AccountID"],
                    "stepfunction_arn": stepfunction["StepFunctionArn"],
                    "instance_id": stepfunction["InstanceId"],
                    "stepfunction_name": stepfunction["StepFunctionName"],
                    "description": stepfunction["Description"],
                    "triggers": stepfunction["Triggers"],
                    "versions": stepfunction["Versions"],
                    "roles_permissions": stepfunction["RolesPermissions"],
                    "status": stepfunction["Status"],
                    "region": stepfunction["Region"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_stepfunction_changed_by(
                            stepfunction_arn=stepfunction_arn,
                            update_date=datetime.now()
                        )
                        
                        log_change('STEP-FUNCTIONS', stepfunction_arn, col, old_val, new_val, changed_by, stepfunction["AccountID"], stepfunction["Region"])

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE stepfunctions SET {', '.join(updates)} WHERE stepfunction_arn = %s"
                    values.append(stepfunction_arn)
                    cursor.execute(update_query, tuple(values))
                    updated += 1
                else:
                    cursor.execute("UPDATE stepfunctions SET last_updated = CURRENT_TIMESTAMP WHERE stepfunction_arn = %s", [stepfunction_arn])

        conn.commit()
        return {
            "processed": processed,
            "inserted": inserted,
            "updated": updated
        }

    except Exception as e:
        conn.rollback()
        pass
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()