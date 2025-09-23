from botocore.exceptions import ClientError
from datetime import datetime
import time
from services.utils import create_aws_client, get_db_connection, log_change

def get_local_time():
    return 'NOW()'

FIELD_EVENT_MAP = {
    "repositoryname": ["CreateRepository", "DeleteRepository"],
    "businessappid": ["TagResource", "UntagResource"],
    "repositorysize": ["PutImage", "BatchDeleteImage"],
    "imagetags": ["PutImage", "BatchDeleteImage"]
}

def normalize_list_comparison(old_val, new_val):
    """Normaliza listas para comparación, ignorando orden"""
    if isinstance(new_val, list) and isinstance(old_val, (list, str)):
        old_list = old_val if isinstance(old_val, list) else str(old_val).split(',') if old_val else []
        return sorted([str(x).strip() for x in old_list]) == sorted([str(x).strip() for x in new_val])
    return str(old_val) == str(new_val)

def get_repository_changed_by(repository_name, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'ECR' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (repository_name, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_ecr_data(repository, ecr_client, account_name, account_id, region):
    repo_name = repository["repositoryName"]
    
    # Get repository size
    try:
        stats = ecr_client.describe_repository_statistics(repositoryNames=[repo_name]).get('repositoryStatistics', [])
        repo_size = stats[0].get('repositorySizeInBytes', 0) if stats else 0
    except:
        repo_size = 0
    
    # Get image tags
    try:
        images = ecr_client.list_images(repositoryName=repo_name, maxResults=5).get('imageIds', [])
        image_tags = [img['imageTag'] for img in images if 'imageTag' in img]
    except:
        image_tags = []
    
    # Get repository tags
    try:
        tags = ecr_client.list_tags_for_resource(resourceArn=repository.get("repositoryArn", "")).get("tags", [])
        business_app_id = next((t["value"] for t in tags if t["key"] == "BusinessAppID"), "N/A")
    except:
        business_app_id = "N/A"
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "RepositoryName": repo_name,
        "Domain": repository.get("repositoryUri", "").split('.')[0] or account_id,
        "BusinessAppID": business_app_id,
        "RepositorySize": repo_size,
        "ArtifactType": "container",
        "ImageTags": image_tags
    }

def get_ecr_repositories(region, credentials, account_id, account_name):
    ecr_client = create_aws_client("ecr", region, credentials)
    if not ecr_client:
        return []
    try:
        repositories_info = []
        for page in ecr_client.get_paginator('describe_repositories').paginate():
            for repository in page.get("repositories", []):
                repositories_info.append(extract_ecr_data(repository, ecr_client, account_name, account_id, region))
        return repositories_info
    except:
        return []

def insert_or_update_ecr_data(ecr_data):
    if not ecr_data:
        return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}
    
    inserted = updated = processed = 0
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ecr")
        columns = [desc[0].lower() for desc in cursor.description]
        existing = {(row[columns.index("repositoryname")], row[columns.index("accountid")]): dict(zip(columns, row)) for row in cursor.fetchall()}
        
        for ecr in ecr_data:
            processed += 1
            repo_name = ecr["RepositoryName"]
            values = (ecr["AccountName"], ecr["AccountID"], ecr["RepositoryName"], ecr["Domain"], ecr["BusinessAppID"], ecr["RepositorySize"], ecr["ArtifactType"], ecr["ImageTags"])
            
            if (repo_name, ecr["AccountID"]) not in existing:
                cursor.execute("INSERT INTO ecr (AccountName, AccountID, RepositoryName, Domain, BusinessAppID, RepositorySize, ArtifactType, ImageTags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                inserted += 1
            else:
                db_row = existing[(repo_name, ecr["AccountID"])]
                updates = []
                vals = []
                campos = {"accountname": ecr["AccountName"], "accountid": ecr["AccountID"], "repositoryname": ecr["RepositoryName"], "domain": ecr["Domain"], "businessappid": ecr["BusinessAppID"], "repositorysize": ecr["RepositorySize"], "artifacttype": ecr["ArtifactType"], "imagetags": ecr["ImageTags"]}
                
                # Verificar si cambió el account_id o repository_name (campos de identificación)
                if (str(db_row.get('accountid')) != str(ecr["AccountID"]) or 
                    str(db_row.get('repositoryname')) != str(ecr["RepositoryName"])):
                    # Si cambió la identificación, insertar como nuevo registro
                    cursor.execute("INSERT INTO ecr (AccountName, AccountID, RepositoryName, Domain, BusinessAppID, RepositorySize, ArtifactType, ImageTags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                    inserted += 1
                    continue
                
                for col, new_val in campos.items():
                    # Saltar campos de identificación para actualizaciones
                    if col in ['accountid', 'repositoryname']:
                        continue
                    
                    old_val = db_row.get(col)
                    if not normalize_list_comparison(old_val, new_val):
                        updates.append(f"{col} = %s")
                        vals.append(new_val)
                        changed_by = get_repository_changed_by(repo_name, datetime.now())
                        log_change('ECR', repo_name, col, old_val, new_val, changed_by, ecr["AccountID"], "us-east-1")
                
                if updates:
                    cursor.execute(f"UPDATE ecr SET {', '.join(updates)}, last_updated = NOW() WHERE repositoryname = %s", vals + [repo_name])
                    updated += 1
                else:
                    cursor.execute("UPDATE ecr SET last_updated = NOW() WHERE repositoryname = %s", [repo_name])
        
        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()