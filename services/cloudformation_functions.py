from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection

def get_stack_changed_by(stack_name, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'CLOUDFORMATION' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (stack_name, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"[ERROR] changed_by: {stack_name} - {str(e)}")
        return "unknown"
    finally:
        conn.close()

def extract_stack_data(stack, cloudformation_client, account_name, account_id, region):
    """Extrae datos relevantes de un stack de CloudFormation"""
    tags = stack.get("Tags", [])
    get_tag = lambda key: next((t["Value"] for t in tags if t["Key"] == key), "N/A")
    
    # Obtener información adicional del stack
    capabilities = stack.get("Capabilities", [])
    capabilities_str = ", ".join(capabilities) if capabilities else "N/A"
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "StackName": stack["StackName"][:255],
        "StackStatus": stack.get("StackStatus", "N/A")[:50],
        "CreationTime": stack.get("CreationTime"),
        "Description": (stack.get("Description", "N/A") or "N/A")[:500],
        "Capabilities": capabilities_str[:255],
        "Region": region[:50]
    }

def get_cloudformation_stacks(region, credentials, account_id, account_name):
    """Obtiene stacks de CloudFormation de una región."""
    cloudformation_client = create_aws_client("cloudformation", region, credentials)
    if not cloudformation_client:
        return []

    try:
        paginator = cloudformation_client.get_paginator('describe_stacks')
        stacks_info = []

        for page in paginator.paginate():
            for stack in page.get("Stacks", []):
                # Solo incluir stacks activos (no eliminados)
                if stack.get("StackStatus") != "DELETE_COMPLETE":
                    info = extract_stack_data(stack, cloudformation_client, account_name, account_id, region)
                    stacks_info.append(info)
        
        if stacks_info:
            print(f"INFO: CloudFormation en {region}: {len(stacks_info)} stacks encontrados")
        return stacks_info
    except ClientError as e:
        print(f"[ERROR] CloudFormation: {region}/{account_id} - {str(e)}")
        return []

def insert_or_update_cloudformation_data(cloudformation_data):
    """Inserta o actualiza datos de CloudFormation en la base de datos con seguimiento de cambios."""
    if not cloudformation_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO cloudformation (
            account_name, account_id, stack_name, stack_status, creation_time,
            description, capabilities, region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO cloudformation_changes_history (stack_name, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM cloudformation")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("stack_name")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for stack in cloudformation_data:
            stack_name = stack["StackName"]
            processed += 1

            insert_values = (
                stack["AccountName"], stack["AccountID"], stack["StackName"],
                stack["StackStatus"], stack["CreationTime"],
                stack["Description"], stack["Capabilities"], stack["Region"]
            )

            if stack_name not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[stack_name]
                updates = []
                values = []

                campos = {
                    "account_name": stack["AccountName"],
                    "account_id": stack["AccountID"],
                    "stack_name": stack["StackName"],
                    "stack_status": stack["StackStatus"],
                    "creation_time": stack["CreationTime"],
                    "description": stack["Description"],
                    "capabilities": stack["Capabilities"],
                    "region": stack["Region"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_stack_changed_by(
                            stack_name=stack_name,
                            update_date=datetime.now()
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (stack_name, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE cloudformation SET {', '.join(updates)} WHERE stack_name = %s"
                    values.append(stack_name)
                    cursor.execute(update_query, tuple(values))
                    updated += 1

        conn.commit()
        return {
            "processed": processed,
            "inserted": inserted,
            "updated": updated
        }

    except Exception as e:
        conn.rollback()
        print(f"[ERROR] DB: cloudformation_data - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()