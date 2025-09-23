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
    cluster_name = cluster.get("name", "unknown")
    print(f"[EKS DEBUG] Extracting data for cluster {cluster_name}")
    
    try:
        addons_response = eks_client.list_addons(clusterName=cluster_name)
        addons = addons_response.get('addons', [])
        print(f"[EKS DEBUG] Cluster {cluster_name} addons: {addons}")
    except Exception as e:
        print(f"[EKS DEBUG] Error getting addons for {cluster_name}: {str(e)}")
        addons = []
    
    version = cluster.get("version", "")
    support_type = cluster.get("supportType", "STANDARD")
    dates = {"1.31": "Nov 25, 2025", "1.30": "Jul 25, 2025", "1.29": "Mar 25, 2025"}
    support_msg = f"{support_type.title()} - Ends {dates.get(version, 'N/A')}" if version else "Standard"
    
    print(f"[EKS DEBUG] Cluster {cluster_name} - Version: {version}, Status: {cluster.get('status')}, Support: {support_type}")
    
    extracted_data = {
        "AccountName": account_name,
        "AccountID": account_id,
        "ClusterID": cluster.get("arn", cluster_name).split("/")[-1],
        "ClusterName": cluster_name,
        "Status": cluster.get("status", "N/A"),
        "KubernetesVersion": version or "N/A",
        "Provider": "AWS",
        "ClusterSecurityGroup": cluster.get("resourcesVpcConfig", {}).get("clusterSecurityGroupId", "N/A"),
        "SupportPeriod": support_msg,
        "Addons": addons,
        "Tags": cluster.get("tags", {})
    }
    
    print(f"[EKS DEBUG] Extracted data for {cluster_name}: {extracted_data}")
    return extracted_data

def get_eks_clusters(region, credentials, account_id, account_name):
    print(f"[EKS DEBUG] Starting EKS scan for account {account_name} ({account_id}) in region {region}")
    
    eks_client = create_aws_client("eks", region, credentials)
    if not eks_client:
        print(f"[EKS DEBUG] Failed to create EKS client for {account_name} in {region}")
        return []
    
    try:
        clusters_info = []
        print(f"[EKS DEBUG] Getting paginator for list_clusters")
        
        paginator = eks_client.get_paginator('list_clusters')
        page_count = 0
        
        for page in paginator.paginate():
            page_count += 1
            clusters_in_page = page.get("clusters", [])
            print(f"[EKS DEBUG] Page {page_count}: Found {len(clusters_in_page)} clusters: {clusters_in_page}")
            
            for cluster_name in clusters_in_page:
                print(f"[EKS DEBUG] Processing cluster: {cluster_name}")
                try:
                    cluster_response = eks_client.describe_cluster(name=cluster_name)
                    cluster = cluster_response.get("cluster", {})
                    print(f"[EKS DEBUG] Cluster {cluster_name} details: status={cluster.get('status')}, version={cluster.get('version')}")
                    
                    cluster_data = extract_eks_data(cluster, eks_client, account_name, account_id, region)
                    clusters_info.append(cluster_data)
                    print(f"[EKS DEBUG] Successfully extracted data for cluster {cluster_name}")
                    
                except Exception as e:
                    print(f"[EKS DEBUG] Error processing cluster {cluster_name}: {str(e)}")
                    continue
        
        print(f"[EKS DEBUG] Total clusters found: {len(clusters_info)} in {page_count} pages")
        return clusters_info
        
    except Exception as e:
        print(f"[EKS DEBUG] Error in get_eks_clusters: {str(e)}")
        return []

def insert_or_update_eks_data(eks_data):
    print(f"[EKS DEBUG] Starting database operations with {len(eks_data) if eks_data else 0} clusters")
    
    if not eks_data:
        print(f"[EKS DEBUG] No EKS data to process")
        return {"processed": 0, "inserted": 0, "updated": 0}
    
    conn = get_db_connection()
    if not conn:
        print(f"[EKS DEBUG] Database connection failed")
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}
    
    inserted = updated = processed = 0
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM eks")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_rows = cursor.fetchall()
        existing = {(row[columns.index("clustername")], row[columns.index("accountid")]): dict(zip(columns, row)) for row in existing_rows}
        
        print(f"[EKS DEBUG] Found {len(existing)} existing EKS clusters in database")
        
        for eks in eks_data:
            processed += 1
            cluster_name = eks["ClusterName"]
            print(f"[EKS DEBUG] Processing cluster {cluster_name} for database operations")
            
            values = (eks["AccountName"], eks["AccountID"], eks["ClusterID"], eks["ClusterName"], eks["Status"], eks["KubernetesVersion"], eks["Provider"], eks["ClusterSecurityGroup"], eks["SupportPeriod"], eks["Addons"], eks["Tags"])
            
            if (cluster_name, eks["AccountID"]) not in existing:
                print(f"[EKS DEBUG] Inserting new cluster {cluster_name}")
                cursor.execute("INSERT INTO eks (AccountName, AccountID, ClusterID, ClusterName, Status, KubernetesVersion, Provider, ClusterSecurityGroup, SupportPeriod, Addons, Tags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                inserted += 1
            else:
                print(f"[EKS DEBUG] Checking for updates on existing cluster {cluster_name}")
                db_row = existing[(cluster_name, eks["AccountID"])]
                updates = []
                vals = []
                campos = {"accountname": eks["AccountName"], "accountid": eks["AccountID"], "clusterid": eks["ClusterID"], "clustername": eks["ClusterName"], "status": eks["Status"], "kubernetesversion": eks["KubernetesVersion"], "provider": eks["Provider"], "clustersecuritygroup": eks["ClusterSecurityGroup"], "supportperiod": eks["SupportPeriod"], "addons": eks["Addons"], "tags": eks["Tags"]}
                
                # Verificar si cambió el account_id o cluster_name (campos de identificación)
                if (str(db_row.get('accountid')) != str(eks["AccountID"]) or 
                    str(db_row.get('clustername')) != str(eks["ClusterName"])):
                    print(f"[EKS DEBUG] Identity changed for {cluster_name}, inserting as new record")
                    cursor.execute("INSERT INTO eks (AccountName, AccountID, ClusterID, ClusterName, Status, KubernetesVersion, Provider, ClusterSecurityGroup, SupportPeriod, Addons, Tags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                    inserted += 1
                    continue
                
                for col, new_val in campos.items():
                    # Saltar campos de identificación para actualizaciones
                    if col in ['accountid', 'clustername']:
                        continue
                    
                    old_val = db_row.get(col)
                    if not normalize_list_comparison(old_val, new_val):
                        print(f"[EKS DEBUG] Field {col} changed for {cluster_name}: {old_val} -> {new_val}")
                        updates.append(f"{col} = %s")
                        vals.append(new_val)
                        changed_by = get_resource_changed_by(cluster_name, 'EKS', datetime.now(), col)
                        log_change('EKS', cluster_name, col, old_val, new_val, changed_by, eks["AccountID"], "us-east-1")
                
                if updates:
                    print(f"[EKS DEBUG] Updating cluster {cluster_name} with {len(updates)} changes")
                    cursor.execute(f"UPDATE eks SET {', '.join(updates)}, last_updated = NOW() WHERE clustername = %s", vals + [cluster_name])
                    updated += 1
                else:
                    print(f"[EKS DEBUG] No changes for cluster {cluster_name}, updating last_updated only")
                    cursor.execute("UPDATE eks SET last_updated = NOW() WHERE clustername = %s", [cluster_name])
        
        conn.commit()
        print(f"[EKS DEBUG] Database operations completed: {processed} processed, {inserted} inserted, {updated} updated")
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        print(f"[EKS DEBUG] Database error: {str(e)}")
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()