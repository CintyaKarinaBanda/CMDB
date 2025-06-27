from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection

FIELD_EVENT_MAP = {
    "clustername": ["CreateCluster", "UpdateClusterConfig"],
    "status": ["CreateCluster", "DeleteCluster", "UpdateClusterConfig"],
    "kubernetesversion": ["UpdateClusterVersion"],
    "provider": ["CreateCluster"],
    "clustersecuritygroup": ["UpdateClusterConfig"],
    "supportperiod": ["UpdateClusterConfig"],
    "addons": ["CreateAddon", "DeleteAddon", "UpdateAddon"],
    "tags": ["TagResource", "UntagResource"],
}

def get_cluster_changed_by(cluster_name, field_name):
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
                    WHERE resource_name = %s AND resource_type = 'EKS'
                    AND event_name IN ({placeholders})
                    ORDER BY event_time DESC LIMIT 1
                """
                cursor.execute(query, (cluster_name, *possible_events))
            else:
                cursor.execute("""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = 'EKS'
                    ORDER BY event_time DESC LIMIT 1
                """, (cluster_name,))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: changed_by {cluster_name}/{field_name} - {str(e)}")
        return "unknown"
    finally:
        conn.close()

def get_cluster_addons(eks_client, cluster_name):
    """Obtiene los addons del cluster"""
    try:
        response = eks_client.list_addons(clusterName=cluster_name)
        return response.get('addons', [])
    except ClientError:
        return []

def get_support_period_message(version, support_type):
    """Genera el mensaje completo de soporte como aparece en la consola"""
    if not version:
        return "Standard support"
    
    version_end_dates = {
        "1.31": "November 25, 2025",
        "1.30": "July 25, 2025", 
        "1.29": "March 25, 2025",
        "1.28": "November 25, 2024",
        "1.27": "July 25, 2024"
    }
    
    support_name = "Standard support" if support_type == "STANDARD" else "Extended support"
    end_date = version_end_dates.get(version, "TBD")
    
    if end_date != "TBD":
        return f"{support_name} - Your cluster's Kubernetes version ({version}) will reach the end of standard support on {end_date}. On that date, your cluster will enter the extended support period with additional fees."
    else:
        return f"{support_name} - Kubernetes version {version}"

def extract_eks_data(cluster, eks_client, account_name, account_id, region):
    cluster_name = cluster["name"]
    tags = cluster.get("tags", {})
    
    addons = get_cluster_addons(eks_client, cluster_name)
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "ClusterID": cluster.get("arn", "N/A").split("/")[-1] if cluster.get("arn") else cluster_name,
        "ClusterName": cluster_name,
        "Status": cluster.get("status", "N/A"),
        "KubernetesVersion": cluster.get("version", "N/A"),
        "Provider": "AWS",
        "ClusterSecurityGroup": cluster.get("resourcesVpcConfig", {}).get("clusterSecurityGroupId", "N/A"),
        "SupportPeriod": get_support_period_message(cluster.get("version", ""), cluster.get("supportType", "STANDARD")),
        "Addons": addons,
        "Tags": dict(tags) if tags else {}
    }

def get_eks_clusters(region, credentials, account_id, account_name):
    eks_client = create_aws_client("eks", region, credentials)
    if not eks_client:
        return []

    try:
        paginator = eks_client.get_paginator('list_clusters')
        clusters_info = []

        for page in paginator.paginate():
            cluster_names = page.get("clusters", [])
            
            for cluster_name in cluster_names:
                try:
                    cluster_detail = eks_client.describe_cluster(name=cluster_name)
                    cluster = cluster_detail.get("cluster", {})
                    info = extract_eks_data(cluster, eks_client, account_name, account_id, region)
                    clusters_info.append(info)
                except ClientError as e:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: EKS cluster {cluster_name} {region}/{account_id} - {str(e)}")
                    continue
        
        return clusters_info
    except ClientError as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: EKS {region}/{account_id} - {str(e)}")
        return []

def insert_or_update_eks_data(eks_data):
    if not eks_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO eks (
            AccountName, AccountID, ClusterID, ClusterName, Status,
            KubernetesVersion, Provider, ClusterSecurityGroup, SupportPeriod,
            Addons, Tags, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO eks_changes_history (cluster_name, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM eks")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("clustername")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for eks in eks_data:
            cluster_name = eks["ClusterName"]
            processed += 1

            insert_values = (
                eks["AccountName"], eks["AccountID"], eks["ClusterID"],
                eks["ClusterName"], eks["Status"], eks["KubernetesVersion"],
                eks["Provider"], eks["ClusterSecurityGroup"], eks["SupportPeriod"],
                eks["Addons"], eks["Tags"]
            )

            if cluster_name not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[cluster_name]
                updates = []
                values = []

                campos = {
                    "accountname": eks["AccountName"],
                    "accountid": eks["AccountID"],
                    "clusterid": eks["ClusterID"],
                    "clustername": eks["ClusterName"],
                    "status": eks["Status"],
                    "kubernetesversion": eks["KubernetesVersion"],
                    "provider": eks["Provider"],
                    "clustersecuritygroup": eks["ClusterSecurityGroup"],
                    "supportperiod": eks["SupportPeriod"],
                    "addons": eks["Addons"],
                    "tags": eks["Tags"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_cluster_changed_by(
                            cluster_name=cluster_name,
                            field_name=col
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (cluster_name, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE eks SET {', '.join(updates)} WHERE clustername = %s"
                    values.append(cluster_name)
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
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: DB eks_data - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()