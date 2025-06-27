from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection

FIELD_EVENT_MAP = {
    "repositoryname": ["CreateRepository", "DeleteRepository"],
    "domain": ["CreateRepository"],
    "businessappid": ["TagResource", "UntagResource"],
    "repositorysize": ["PutImage", "BatchDeleteImage"],
    "artifacttype": ["PutImage"],
    "imagetags": ["PutImage", "BatchDeleteImage", "TagResource", "UntagResource"]
}

def get_repository_changed_by(repository_name, field_name):
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
                    WHERE resource_name = %s AND resource_type = 'ECR'
                    AND event_name IN ({placeholders})
                    ORDER BY event_time DESC LIMIT 1
                """
                cursor.execute(query, (repository_name, *possible_events))
            else:
                cursor.execute("""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = 'ECR'
                    ORDER BY event_time DESC LIMIT 1
                """, (repository_name,))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: changed_by {repository_name}/{field_name} - {str(e)}")
        return "unknown"
    finally:
        conn.close()

def get_repository_size(ecr_client, repository_name):
    """Obtiene el tamaño del repositorio"""
    try:
        response = ecr_client.describe_repository_statistics(repositoryNames=[repository_name])
        stats = response.get('repositoryStatistics', [])
        if stats:
            return stats[0].get('repositorySizeInBytes', 0)
        return 0
    except ClientError:
        return 0

def get_image_tags(ecr_client, repository_name):
    """Obtiene las etiquetas de imágenes del repositorio"""
    try:
        response = ecr_client.list_images(repositoryName=repository_name, maxResults=10)
        tags = []
        for image in response.get('imageIds', []):
            if 'imageTag' in image:
                tags.append(image['imageTag'])
        return tags[:5]  # Limitar a 5 tags
    except ClientError:
        return []

def extract_ecr_data(repository, ecr_client, account_name, account_id, region):
    repository_name = repository["repositoryName"]
    repository_uri = repository.get("repositoryUri", "")
    
    # Extraer dominio del URI
    domain = repository_uri.split('.')[0] if repository_uri else account_id
    
    # Obtener estadísticas del repositorio
    repository_size = get_repository_size(ecr_client, repository_name)
    image_tags = get_image_tags(ecr_client, repository_name)
    
    # Obtener tags del repositorio
    tags = []
    try:
        response = ecr_client.list_tags_for_resource(resourceArn=repository.get("repositoryArn", ""))
        tags = response.get("tags", [])
    except ClientError:
        pass
    
    get_tag = lambda key: next((t["value"] for t in tags if t["key"] == key), "N/A")
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "RepositoryName": repository_name,
        "Domain": domain,
        "BusinessAppID": get_tag("BusinessAppID"),
        "RepositorySize": repository_size,
        "ArtifactType": "container",
        "ImageTags": image_tags
    }

def get_ecr_repositories(region, credentials, account_id, account_name):
    ecr_client = create_aws_client("ecr", region, credentials)
    if not ecr_client:
        return []

    try:
        paginator = ecr_client.get_paginator('describe_repositories')
        repositories_info = []

        for page in paginator.paginate():
            for repository in page.get("repositories", []):
                info = extract_ecr_data(repository, ecr_client, account_name, account_id, region)
                repositories_info.append(info)
        
        return repositories_info
    except ClientError as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: ECR {region}/{account_id} - {str(e)}")
        return []

def insert_or_update_ecr_data(ecr_data):
    if not ecr_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO ecr (
            AccountName, AccountID, RepositoryName, Domain, BusinessAppID,
            RepositorySize, ArtifactType, ImageTags, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO ecr_changes_history (repository_name, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM ecr")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("repositoryname")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for ecr in ecr_data:
            repository_name = ecr["RepositoryName"]
            processed += 1

            insert_values = (
                ecr["AccountName"], ecr["AccountID"], ecr["RepositoryName"],
                ecr["Domain"], ecr["BusinessAppID"], ecr["RepositorySize"],
                ecr["ArtifactType"], ecr["ImageTags"]
            )

            if repository_name not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[repository_name]
                updates = []
                values = []

                campos = {
                    "accountname": ecr["AccountName"],
                    "accountid": ecr["AccountID"],
                    "repositoryname": ecr["RepositoryName"],
                    "domain": ecr["Domain"],
                    "businessappid": ecr["BusinessAppID"],
                    "repositorysize": ecr["RepositorySize"],
                    "artifacttype": ecr["ArtifactType"],
                    "imagetags": ecr["ImageTags"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_repository_changed_by(
                            repository_name=repository_name,
                            field_name=col
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (repository_name, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE ecr SET {', '.join(updates)} WHERE repositoryname = %s"
                    values.append(repository_name)
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
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: DB ecr_data - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()