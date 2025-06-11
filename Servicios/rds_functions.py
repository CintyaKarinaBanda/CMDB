from botocore.exceptions import ClientError
from datetime import datetime
from Servicios.utils import create_aws_client, get_db_connection, log, get_resource_changed_by

def extract_rds_data(db, account_name, account_id, region):
    """Extrae datos relevantes de una instancia RDS."""
    endpoint = db.get("Endpoint", {})
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "DbInstanceId": db["DBInstanceIdentifier"],
        "DbName": db.get("DBName", "N/A"),
        "EngineType": db["Engine"],
        "EngineVersion": db.get("EngineVersion", "N/A"),
        "StorageSize": db.get("AllocatedStorage", "N/A"),
        "InstanceType": db["DBInstanceClass"],
        "Status": db["DBInstanceStatus"],
        "Region": region,
        "Endpoint": endpoint.get("Address", "N/A"),
        "Port": endpoint.get("Port", "N/A"),
        "HasReplica": bool(db.get("ReadReplicaDBInstanceIdentifiers"))
    }

def get_rds_instances(region, credentials, account_id, account_name):
    """Obtiene instancias RDS de una región."""
    rds_client = create_aws_client("rds", region, credentials)
    if not rds_client:
        return []

    try:
        paginator = rds_client.get_paginator('describe_db_instances')
        instances_info = []

        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                instances_info.append(extract_rds_data(db, account_name, account_id, region))
        
        if instances_info:
            log(f"INFO: RDS en {region}: {len(instances_info)} instancias encontradas")
        return instances_info
    except ClientError as e:
        log(f"ERROR: Obtener instancias RDS en {region}: {str(e)}")
        return []

def insert_or_update_rds_data(rds_data):
    """Inserta o actualiza datos RDS en la base de datos."""
    if not rds_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    # Consultas SQL
    query_insert = """
        INSERT INTO rds (
            AccountName, AccountID, DbInstanceId, DbName, EngineType,
            EngineVersion, StorageSize, InstanceType, Status, Region,
            Endpoint, Port, HasReplica, last_updated
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
    """

    query_change_history = """
        INSERT INTO rds_changes_history (dbinstanceid, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted, updated, processed = 0, 0, 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM rds")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("dbinstanceid")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for rds in rds_data:
            instance_id = rds["DbInstanceId"]
            processed += 1

            # Valores para inserción
            insert_values = (
                rds["AccountName"], rds["AccountID"], rds["DbInstanceId"],
                rds["DbName"], rds["EngineType"], rds["EngineVersion"],
                rds["StorageSize"], rds["InstanceType"], rds["Status"],
                rds["Region"], rds["Endpoint"], rds["Port"], rds["HasReplica"]
            )

            if instance_id not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                # Actualizar solo campos modificados
                db_row = existing_data[instance_id]
                campos = {
                    "accountname": rds["AccountName"],
                    "accountid": rds["AccountID"],
                    "dbinstanceid": rds["DbInstanceId"],
                    "dbname": rds["DbName"],
                    "enginetype": rds["EngineType"],
                    "engineversion": rds["EngineVersion"],
                    "storagesize": rds["StorageSize"],
                    "instancetype": rds["InstanceType"],
                    "status": rds["Status"],
                    "region": rds["Region"],
                    "endpoint": rds["Endpoint"],
                    "port": rds["Port"],
                    "hasreplica": rds["HasReplica"]
                }

                updates, values = [], []
                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_resource_changed_by(
                            resource_id=instance_id,
                            resource_type="RDS",
                            update_date=datetime.now()
                        )
                        cursor.execute(query_change_history, (instance_id, col, str(old_val), str(new_val), changed_by))

                if updates:
                    updates.append("last_updated = CURRENT_TIMESTAMP")
                    update_query = f"UPDATE rds SET {', '.join(updates)} WHERE dbinstanceid = %s"
                    values.append(instance_id)
                    cursor.execute(update_query, tuple(values))
                    updated += 1

        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}

    except Exception as e:
        conn.rollback()
        log(f"ERROR: Operación BD para RDS: {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()