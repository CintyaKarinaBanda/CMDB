from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection

FIELD_EVENT_MAP = {
    "database_name": ["CreateCluster", "ModifyCluster"],
    "node_type": ["CreateCluster", "ModifyCluster"],
    "node_count": ["ResizeCluster", "ModifyCluster"],
    "engine_version": ["ModifyCluster"],
    "storage_size": ["ModifyCluster"],
    "status": ["CreateCluster", "DeleteCluster", "PauseCluster", "ResumeCluster", "RebootCluster"],
    "endpoint": ["CreateCluster", "ModifyCluster"],
    "port": ["CreateCluster", "ModifyCluster"],
    "replication": ["CreateCluster", "ModifyCluster"]
}

def get_cluster_changed_by(cluster_id, field_name):
    """Busca el usuario que cambió un campo específico"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            possible_events = FIELD_EVENT_MAP.get(field_name, [])
            
            if possible_events:
                placeholders = ','.join(['%s'] * len(possible_events))
                query = f"""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = 'Redshift'
                    AND event_name IN ({placeholders})
                    ORDER BY event_time DESC LIMIT 1
                """
                cursor.execute(query, (cluster_id, *possible_events))
            else:
                cursor.execute("""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = 'Redshift'
                    ORDER BY event_time DESC LIMIT 1
                """, (cluster_id,))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_cluster_data(cluster, redshift_client, account_name, account_id, region):
    """Extrae datos relevantes de un cluster de Redshift"""
    tags = {tag.get('Key'): tag.get('Value') for tag in cluster.get('Tags', [])}
    
    return {
        "AccountID": account_id,
        "AccountName": account_name,
        "DatabaseId": cluster["ClusterIdentifier"],
        "AppId": tags.get("AppId", "N/A"),
        "DatabaseName": cluster.get("DBName", "N/A"),
        "NodeType": cluster.get("NodeType", "N/A"),
        "NodeCount": cluster.get("NumberOfNodes", 1),
        "EngineVersion": cluster.get("ClusterVersion", "N/A"),
        "StorageSize": cluster.get("TotalStorageCapacityInMegaBytes", 0),
        "Status": cluster.get("ClusterStatus", "N/A"),
        "Region": region,
        "Endpoint": cluster.get("Endpoint", {}).get("Address", "N/A"),
        "Port": cluster.get("Endpoint", {}).get("Port", 0),
        "Replication": cluster.get("ClusterSubnetGroupName", "N/A")
    }

def get_redshift_clusters(region, credentials, account_id, account_name):
    """Obtiene clusters de Redshift de una región."""
    redshift_client = create_aws_client("redshift", region, credentials)
    if not redshift_client:
        return []

    try:
        paginator = redshift_client.get_paginator('describe_clusters')
        clusters_info = []

        for page in paginator.paginate():
            for cluster in page.get("Clusters", []):
                info = extract_cluster_data(cluster, redshift_client, account_name, account_id, region)
                clusters_info.append(info)
        
        return clusters_info
    except ClientError as e:
        return []

def insert_or_update_redshift_data(redshift_data):
    """Inserta o actualiza datos de Redshift en la base de datos con seguimiento de cambios."""
    if not redshift_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO redshift (
            database_id, app_id, database_name, node_type, node_count,
            engine_version, storage_size, status, region, endpoint,
            port, replication, account_id, account_name, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO redshift_changes_history (cluster_id, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM redshift")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("database_id")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for cluster in redshift_data:
            database_id = cluster["DatabaseId"]
            processed += 1

            insert_values = (
                database_id, cluster["AppId"], cluster["DatabaseName"],
                cluster["NodeType"], cluster["NodeCount"], cluster["EngineVersion"],
                cluster["StorageSize"], cluster["Status"], cluster["Region"],
                cluster["Endpoint"], cluster["Port"], cluster["Replication"],
                cluster["AccountID"], cluster["AccountName"]
            )

            if database_id not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[database_id]
                updates = []
                values = []

                campos = {
                    "database_id": database_id,
                    "app_id": cluster["AppId"],
                    "database_name": cluster["DatabaseName"],
                    "node_type": cluster["NodeType"],
                    "node_count": cluster["NodeCount"],
                    "engine_version": cluster["EngineVersion"],
                    "storage_size": cluster["StorageSize"],
                    "status": cluster["Status"],
                    "region": cluster["Region"],
                    "endpoint": cluster["Endpoint"],
                    "port": cluster["Port"],
                    "replication": cluster["Replication"],
                    "account_id": cluster["AccountID"],
                    "account_name": cluster["AccountName"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_cluster_changed_by(
                            cluster_id=database_id,
                            field_name=col
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (database_id, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE redshift SET {', '.join(updates)} WHERE database_id = %s"
                    values.append(database_id)
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
        pass
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()