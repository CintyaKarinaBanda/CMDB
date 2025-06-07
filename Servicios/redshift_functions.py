import boto3
from botocore.exceptions import ClientError
import pg8000
import logging
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import DB_USER, DB_PASSWORD, DB_HOST, DB_NAME

# logger = logging.getLogger(__name__)

def create_redshift_client(region, credentials):
    if not credentials or "error" in credentials:
        return None
    try:
        return boto3.client(
            "redshift",
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
    except Exception as e:
        print(f"Error creating Redshift client: {str(e)}")
        return None

def get_redshift_clusters(region, credentials, account_id, account_name):
    redshift_client = create_redshift_client(region, credentials)
    if not redshift_client:
        return []

    try:
        paginator = redshift_client.get_paginator('describe_clusters')
        clusters_info = []

        for page in paginator.paginate():
            for cluster in page.get("Clusters", []):
                clusters_info.append({
                    "AccountID": account_id,
                    "AccountName": account_name,
                    "DatabaseId": cluster["ClusterIdentifier"],
                    "AppId": cluster.get("Tags", {}).get("AppId", "N/A"),
                    "DatabaseName": cluster.get("DBName", "N/A"),
                    "NodeType": cluster.get("NodeType", "N/A"),
                    "NodeCount": cluster.get("NumberOfNodes", "N/A"),
                    "EngineVersion": cluster.get("ClusterVersion", "N/A"),
                    "StorageSize": cluster.get("TotalStorageCapacityInMegaBytes", "N/A"),
                    "Status": cluster.get("ClusterStatus", "N/A"),
                    "Region": region,
                    "Endpoint": cluster.get("Endpoint", {}).get("Address", "N/A"),
                    "Port": cluster.get("Endpoint", {}).get("Port", "N/A"),
                    "Replication": cluster.get("ClusterSubnetGroupName", "N/A")  # Puedes ajustar este campo
                })
        return clusters_info
    except ClientError as e:
        print(f"Error getting Redshift clusters for account {account_id}: {str(e)}")
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

def prepare_redshift_data_for_db(redshift_data):
    return [(
        item["DatabaseId"], item["AppId"], item["DatabaseName"],
        item["NodeType"], item["NodeCount"], item["EngineVersion"],
        item["StorageSize"], item["Status"], item["Region"],
        item["Endpoint"], item["Port"], item["Replication"],
        item["AccountID"], item["AccountName"]
    ) for item in redshift_data]

def insert_or_update_redshift_data(redshift_data):
    if not redshift_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    connection = get_db_connection()
    if not connection:
        return {
            "error": "Database connection failed",
            "processed": 0,
            "inserted": 0,
            "updated": 0
        }

    try:
        upsert_query = """
            INSERT INTO redshift (
                database_id, app_id, database_name, node_type, node_count,
                engine_version, storage_size, status, region, endpoint,
                port, replication, account_id, account_name, last_updated
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, CURRENT_TIMESTAMP
            )
            ON CONFLICT (database_id)
            DO UPDATE SET
                app_id = EXCLUDED.app_id,
                database_name = EXCLUDED.database_name,
                node_type = EXCLUDED.node_type,
                node_count = EXCLUDED.node_count,
                engine_version = EXCLUDED.engine_version,
                storage_size = EXCLUDED.storage_size,
                status = EXCLUDED.status,
                region = EXCLUDED.region,
                endpoint = EXCLUDED.endpoint,
                port = EXCLUDED.port,
                replication = EXCLUDED.replication,
                account_id = EXCLUDED.account_id,
                account_name = EXCLUDED.account_name,
                last_updated = CURRENT_TIMESTAMP
            RETURNING database_id, last_updated;
        """

        cursor = connection.cursor()
        prepared_data = prepare_redshift_data_for_db(redshift_data)
        cursor.executemany(upsert_query, prepared_data)
        results = cursor.fetchall()
        connection.commit()

        processed = len(results)
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