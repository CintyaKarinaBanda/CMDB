from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_cluster_changed_by(cluster_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'EMR' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (cluster_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_cluster_data(cluster, emr_client, account_name, account_id, region):
    """Extrae datos relevantes de un cluster de EMR"""
    cluster_id = cluster["Id"]
    
    # Obtener detalles adicionales del cluster
    try:
        cluster_details = emr_client.describe_cluster(ClusterId=cluster_id)
        cluster_info = cluster_details["Cluster"]
        
        # Información de aplicaciones
        applications = cluster_info.get("Applications", [])
        app_types = list(set([app.get("Name", "Unknown") for app in applications]))
        application_types = ", ".join(app_types[:5]) if app_types else "N/A"  # Máximo 5 aplicaciones
        
        # Versión del cluster (release label)
        version = cluster_info.get("ReleaseLabel", "N/A")
        
        # Estado del cluster
        state = cluster_info.get("Status", {}).get("State", "UNKNOWN")
        
        # Configuración de seguridad
        security_config = cluster_info.get("SecurityConfiguration", "N/A")
        ec2_attributes = cluster_info.get("Ec2InstanceAttributes", {})
        
        # Construir información de seguridad
        security_info = []
        if security_config != "N/A":
            security_info.append(f"Config: {security_config}")
        if ec2_attributes.get("IamInstanceProfile"):
            security_info.append(f"IAM: {ec2_attributes['IamInstanceProfile'].split('/')[-1]}")
        if ec2_attributes.get("EmrManagedMasterSecurityGroup"):
            security_info.append("Security Groups: Configured")
        
        security_configuration = ", ".join(security_info) if security_info else "Default"
        
    except ClientError:
        application_types = "N/A"
        version = "N/A"
        state = "UNKNOWN"
        security_configuration = "N/A"
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "ClusterId": cluster_id[:255],
        "ClusterName": cluster.get("Name", "N/A")[:255],
        "ApplicationTypes": application_types[:500],
        "Version": version[:100],
        "State": state[:50],
        "Region": region[:50],
        "SecurityConfiguration": security_configuration[:500]
    }

def get_emr_clusters(region, credentials, account_id, account_name):
    """Obtiene clusters de EMR de una región."""
    emr_client = create_aws_client("emr", region, credentials)
    if not emr_client:
        return []

    try:
        paginator = emr_client.get_paginator('list_clusters')
        clusters_info = []

        for page in paginator.paginate():
            for cluster in page.get("Clusters", []):
                info = extract_cluster_data(cluster, emr_client, account_name, account_id, region)
                clusters_info.append(info)
        
        return clusters_info
    except ClientError as e:
        pass
        return []

def insert_or_update_emr_data(emr_data):
    """Inserta o actualiza datos de EMR en la base de datos con seguimiento de cambios."""
    if not emr_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO emr (
            account_name, account_id, cluster_id, cluster_name, application_types,
            version, state, region, security_configuration, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM emr")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {(row[columns.index("cluster_id")], row[columns.index("account_id")]): dict(zip(columns, row)) for row in cursor.fetchall()}

        for cluster in emr_data:
            cluster_id = cluster["ClusterId"]
            processed += 1

            insert_values = (
                cluster["AccountName"], cluster["AccountID"], cluster["ClusterId"],
                cluster["ClusterName"], cluster["ApplicationTypes"], cluster["Version"],
                cluster["State"], cluster["Region"], cluster["SecurityConfiguration"]
            )

            if (cluster_id, cluster["AccountID"]) not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[(cluster_id, cluster["AccountID"])]
                updates = []
                values = []

                campos = {
                    "account_name": cluster["AccountName"],
                    "account_id": cluster["AccountID"],
                    "cluster_id": cluster["ClusterId"],
                    "cluster_name": cluster["ClusterName"],
                    "application_types": cluster["ApplicationTypes"],
                    "version": cluster["Version"],
                    "state": cluster["State"],
                    "region": cluster["Region"],
                    "security_configuration": cluster["SecurityConfiguration"]
                }

                # Verificar si cambió el account_id o cluster_id (campos de identificación)
                if (str(db_row.get('account_id')) != str(cluster["AccountID"]) or 
                    str(db_row.get('cluster_id')) != str(cluster["ClusterId"])):
                    # Si cambió la identificación, insertar como nuevo registro
                    cursor.execute(query_insert, insert_values)
                    inserted += 1
                    continue

                for col, new_val in campos.items():
                    # Saltar campos de identificación para actualizaciones
                    if col in ['account_id', 'cluster_id']:
                        continue
                    
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_cluster_changed_by(cluster_id, datetime.now())
                        log_change('EMR', cluster_id, col, old_val, new_val, changed_by, cluster["AccountID"], cluster["Region"])

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE emr SET {', '.join(updates)} WHERE cluster_id = %s AND account_id = %s"
                    values.extend([cluster_id, cluster["AccountID"]])
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