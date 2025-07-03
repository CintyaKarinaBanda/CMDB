from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_trail_changed_by(trail_name, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'CLOUDTRAIL' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (trail_name, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_trail_data(trail, cloudtrail_client, account_name, account_id, region):
    """Extrae datos relevantes de un trail de CloudTrail"""
    tags = []
    try:
        # Obtener tags del trail
        tags_response = cloudtrail_client.list_tags(ResourceIdList=[trail['TrailARN']])
        resource_tags = tags_response.get('ResourceTagList', [])
        if resource_tags:
            tags = resource_tags[0].get('TagsList', [])
    except ClientError:
        pass  # Ignorar si no se pueden obtener tags
    
    get_tag = lambda key: next((t["Value"] for t in tags if t["Key"] == key), "N/A")
    
    # Extraer información del bucket S3
    s3_bucket = trail.get('S3BucketName', 'N/A')
    s3_prefix = trail.get('S3KeyPrefix', '')
    log_location = f"s3://{s3_bucket}/{s3_prefix}" if s3_bucket != 'N/A' else 'N/A'
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "TrailName": trail["Name"][:255],
        "LogLocation": log_location[:500],
        "IsMultiRegion": "Yes" if trail.get("IsMultiRegionTrail", False) else "No",
        "IsOrganization": "Yes" if trail.get("IsOrganizationTrail", False) else "No",
        "IncludeGlobalEvents": "Yes" if trail.get("IncludeGlobalServiceEvents", True) else "No",
        "Region": region[:50]
    }

def get_cloudtrail_trails(region, credentials, account_id, account_name):
    """Obtiene trails de CloudTrail de una región."""
    cloudtrail_client = create_aws_client("cloudtrail", region, credentials)
    if not cloudtrail_client:
        return []

    try:
        # Obtener todos los trails
        response = cloudtrail_client.describe_trails()
        trails_info = []

        for trail in response.get("trailList", []):
            info = extract_trail_data(trail, cloudtrail_client, account_name, account_id, region)
            trails_info.append(info)
        

        return trails_info
    except ClientError as e:
        pass
        return []

def insert_or_update_cloudtrail_trails_data(cloudtrail_trails_data):
    """Inserta o actualiza datos de CloudTrail Trails en la base de datos con seguimiento de cambios."""
    if not cloudtrail_trails_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO cloudtrail_trails (
            account_name, account_id, trail_name, log_location, 
            is_multi_region, is_organization, include_global_events, region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """



    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM cloudtrail_trails")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("trail_name")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for trail in cloudtrail_trails_data:
            trail_name = trail["TrailName"]
            processed += 1

            insert_values = (
                trail["AccountName"], trail["AccountID"], trail["TrailName"],
                trail["LogLocation"], trail["IsMultiRegion"], trail["IsOrganization"], 
                trail["IncludeGlobalEvents"], trail["Region"]
            )

            if trail_name not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[trail_name]
                updates = []
                values = []

                campos = {
                    "account_name": trail["AccountName"],
                    "account_id": trail["AccountID"],
                    "trail_name": trail["TrailName"],
                    "log_location": trail["LogLocation"],
                    "is_multi_region": trail["IsMultiRegion"],
                    "is_organization": trail["IsOrganization"],
                    "include_global_events": trail["IncludeGlobalEvents"],
                    "region": trail["Region"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_trail_changed_by(
                            trail_name=trail_name,
                            update_date=datetime.now()
                        )
                        
                        log_change('CLOUDTRAIL', trail_name, col, old_val, new_val, changed_by, trail["AccountID"], trail["Region"])

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE cloudtrail_trails SET {', '.join(updates)} WHERE trail_name = %s"
                    values.append(trail_name)
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