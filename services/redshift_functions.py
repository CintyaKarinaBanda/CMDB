from botocore.exceptions import ClientError
from services.utils import create_aws_client, get_db_connection, execute_db_query

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
                    "Replication": cluster.get("ClusterSubnetGroupName", "N/A")
                })
        
        if clusters_info:
            print(f"INFO: Redshift en {region}: {len(clusters_info)} clusters encontrados")
        return clusters_info
    except ClientError as e:
        print(f"ERROR: Obtener clusters Redshift en {region} para cuenta {account_id}: {str(e)}")
        return []

def insert_or_update_redshift_data(redshift_data):
    """Inserta o actualiza datos de Redshift en la base de datos."""
    if not redshift_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    # Preparar datos para inserción
    prepared_data = [(
        item["DatabaseId"], item["AppId"], item["DatabaseName"],
        item["NodeType"], item["NodeCount"], item["EngineVersion"],
        item["StorageSize"], item["Status"], item["Region"],
        item["Endpoint"], item["Port"], item["Replication"],
        item["AccountID"], item["AccountName"]
    ) for item in redshift_data]

    # Usar la función común para ejecutar la consulta
    result = execute_db_query("""
        INSERT INTO redshift (
            database_id, app_id, database_name, node_type, node_count,
            engine_version, storage_size, status, region, endpoint,
            port, replication, account_id, account_name, last_updated
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (database_id) DO UPDATE SET
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
        RETURNING database_id;
    """, prepared_data, many=True, fetch=True)

    if "error" in result:
        return {"error": result["error"], "processed": 0, "inserted": 0, "updated": 0}
    
    processed = len(result)
    return {"processed": processed, "inserted": processed, "updated": 0}