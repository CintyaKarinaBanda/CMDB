from botocore.exceptions import ClientError
from datetime import datetime
import time
from services.utils import create_aws_client, get_db_connection, log_change, get_resource_changed_by

def get_local_time():
    return 'NOW()'

FIELD_EVENT_MAP = {
    "clustername": ["CreateCluster", "UpdateClusterConfig"],
    "status": ["CreateCluster", "DeleteCluster", "UpdateClusterConfig"],
    "kubernetesversion": ["UpdateClusterVersion"],
    "supportperiod": ["UpdateClusterConfig"],
    "addons": ["CreateAddon", "DeleteAddon", "UpdateAddon"],
    "tags": ["TagResource", "UntagResource"]
}

def normalize_list_comparison(old_val, new_val):
    """Normaliza listas para comparación, ignorando orden"""
    def normalize_to_list(val):
        if isinstance(val, list):
            return val
        elif isinstance(val, str):
            val = val.strip()
            if val in ['[]', '{}', '']:
                return []
            elif val.startswith('[') and val.endswith(']'):
                try:
                    import json
                    return json.loads(val)
                except:
                    return val[1:-1].split(',') if val != '[]' else []
            elif val.startswith('{') and val.endswith('}'):
                return val[1:-1].split(',') if val != '{}' else []
            else:
                return val.split(',') if val else []
        else:
            return [str(val)] if val else []
    
    old_list = normalize_to_list(old_val)
    new_list = normalize_to_list(new_val)
    
    return sorted([str(x).strip() for x in old_list if str(x).strip()]) == sorted([str(x).strip() for x in new_list if str(x).strip()])

def extract_eks_data(cluster, eks_client, account_name, account_id, region):
    try:
        addons = eks_client.list_addons(clusterName=cluster["name"]).get('addons', [])
    except:
        addons = []
    
    version = cluster.get("version", "")
    support_type = cluster.get("supportType", "STANDARD")
    dates = {"1.32": "Feb 25, 2026", "1.31": "Nov 25, 2025", "1.30": "Jul 25, 2025", "1.29": "Mar 25, 2025"}
    support_msg = f"{support_type.title()} - Ends {dates.get(version, 'N/A')}" if version else "Standard"
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "ClusterID": cluster.get("arn", cluster["name"]).split("/")[-1],
        "ClusterName": cluster["name"],
        "Status": cluster.get("status", "N/A"),
        "KubernetesVersion": version or "N/A",
        "Provider": "AWS",
        "ClusterSecurityGroup": cluster.get("resourcesVpcConfig", {}).get("clusterSecurityGroupId", "N/A"),
        "SupportPeriod": support_msg,
        "Addons": addons,
        "Tags": cluster.get("tags", {})
    }

def get_eks_clusters(region, credentials, account_id, account_name):
    eks_client = create_aws_client("eks", region, credentials)
    if not eks_client:
        return []
    try:
        clusters_info = []
        for page in eks_client.get_paginator('list_clusters').paginate():
            for cluster_name in page.get("clusters", []):
                try:
                    cluster = eks_client.describe_cluster(name=cluster_name).get("cluster", {})
                    clusters_info.append(extract_eks_data(cluster, eks_client, account_name, account_id, region))
                except:
                    continue
        return clusters_info
    except:
        return []

def insert_or_update_eks_data(eks_data):
    if not eks_data:
        return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}
    
    inserted = updated = processed = 0
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM eks")
        columns = [desc[0].lower() for desc in cursor.description]
        existing = {(row[columns.index("clustername")], row[columns.index("accountid")]): dict(zip(columns, row)) for row in cursor.fetchall()}
        
        for eks in eks_data:
            processed += 1
            cluster_name = eks["ClusterName"]
            values = (eks["AccountName"], eks["AccountID"], eks["ClusterID"], eks["ClusterName"], eks["Status"], eks["KubernetesVersion"], eks["Provider"], eks["ClusterSecurityGroup"], eks["SupportPeriod"], eks["Addons"], eks["Tags"])
            
            if (cluster_name, eks["AccountID"]) not in existing:
                cursor.execute("INSERT INTO eks (AccountName, AccountID, ClusterID, ClusterName, Status, KubernetesVersion, Provider, ClusterSecurityGroup, SupportPeriod, Addons, Tags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                inserted += 1
            else:
                db_row = existing[(cluster_name, eks["AccountID"])]
                updates = []
                vals = []
                campos = {"accountname": eks["AccountName"], "accountid": eks["AccountID"], "clusterid": eks["ClusterID"], "clustername": eks["ClusterName"], "status": eks["Status"], "kubernetesversion": eks["KubernetesVersion"], "provider": eks["Provider"], "clustersecuritygroup": eks["ClusterSecurityGroup"], "supportperiod": eks["SupportPeriod"], "addons": eks["Addons"], "tags": eks["Tags"]}
                
                if (str(db_row.get('accountid')) != str(eks["AccountID"]) or 
                    str(db_row.get('clustername')) != str(eks["ClusterName"])):
                    cursor.execute("INSERT INTO eks (AccountName, AccountID, ClusterID, ClusterName, Status, KubernetesVersion, Provider, ClusterSecurityGroup, SupportPeriod, Addons, Tags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                    inserted += 1
                    continue
                
                for col, new_val in campos.items():
                    if col in ['accountid', 'clustername']:
                        continue
                    
                    old_val = db_row.get(col)
                    if not normalize_list_comparison(old_val, new_val):
                        updates.append(f"{col} = %s")
                        vals.append(new_val)
                        changed_by = get_resource_changed_by(cluster_name, 'EKS', datetime.now(), col)
                        log_change('EKS', cluster_name, col, old_val, new_val, changed_by, eks["AccountID"], "us-east-1")
                
                if updates:
                    cursor.execute(f"UPDATE eks SET {', '.join(updates)}, last_updated = NOW() WHERE clustername = %s", vals + [cluster_name])
                    updated += 1
                else:
                    cursor.execute("UPDATE eks SET last_updated = NOW() WHERE clustername = %s", [cluster_name])
        
        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()