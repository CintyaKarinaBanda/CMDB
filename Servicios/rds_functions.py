import boto3
from botocore.exceptions import ClientError
import pg8000
import logging
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import DB_USER, DB_PASSWORD, DB_HOST, DB_NAME

# logger = logging.getLogger(__name__)

def create_rds_client(region, credentials):
    if not credentials or "error" in credentials:
        return None
    try:
        return boto3.client(
            "rds",
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
    except Exception as e:
        print(f"Error creating RDS client: {str(e)}")
        return None

def get_rds_instances(region, credentials, account_id, account_name):
    rds_client = create_rds_client(region, credentials)
    if not rds_client:
        return []

    try:
        paginator = rds_client.get_paginator('describe_db_instances')
        instances_info = []

        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                endpoint = db.get("Endpoint", {})
                instances_info.append({
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
                    "HasReplica": bool(db.get("ReadReplicaDBInstanceIdentifiers")),
                })
        return instances_info
    except ClientError as e:
        print(f"Error getting RDS instances for account {account_id}: {str(e)}")
        return []

def get_db_connection():
    try:
        return pg8000.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=5432,
            database=DB_NAME
        )
    except Exception as e:
        print(f"Database connection failed: {str(e)}")
        return None

def prepare_rds_data_for_db(rds_data):
    return [(
        item["AccountName"], item["AccountID"], item["DbInstanceId"],
        item["DbName"], item["EngineType"], item["EngineVersion"],
        item["StorageSize"], item["InstanceType"], item["Status"],
        item["Region"], item["Endpoint"], item["Port"],
        item["HasReplica"]
    ) for item in rds_data]

def insert_or_update_rds_data(rds_data, changed_by="system"):
    if not rds_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    connection = get_db_connection()
    if not connection:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        NSERT INTO rds (
            AccountName, AccountID, DbInstanceId, DbName, EngineType,
            EngineVersion, StorageSize, InstanceType, Status, Region,
            Endpoint, Port, HasReplica, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO rds_changes_history (instance_id, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """
    inserted = 0
    updated = 0
    processed = 0 

    try:
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM rds")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("DbInstanceId")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for rds in rds_data:
            DbInstanceId = rds["DbInstanceId"]
            processed += 1

            insert_values = (
                rds["AccountName"], rds["AccountID"], rds["DbInstanceId"],
                rds["DbName"], rds["EngineType"], rds["EngineVersion"],
                rds["StorageSize"], rds["InstanceType"], rds["Status"],
                rds["Region"], rds["Endpoint"], rds["Port"],
                rds["HasReplica"]
            )

            if DbInstanceId not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[DbInstanceId]
                updates = []
                values = []

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

                for campo, valor in campos.items():
                    if str(db_row.get(campo, "")).strip() != str(valor).strip():
                        updates.append(f"{campo} = %s")
                        values.append(valor)

                if updates:
                    values.append(DbInstanceId)
                    update_query = f"""
                        UPDATE rds
                        SET {', '.join(updates)},
                            last_updated = CURRENT_TIMESTAMP
                        WHERE dbinstanceid = %s
                    """

        connection.commit()

        return {
            "processed": processed,
            "inserted": processed,
            "updated": 0
        }
    except Exception as e:
        connection.rollback()
        print(f"Database operation failed: {str(e)}")
        return {
            "error": str(e),
            "processed": 0,
            "inserted": 0,
            "updated": 0
        }
    finally:
        connection.close()
