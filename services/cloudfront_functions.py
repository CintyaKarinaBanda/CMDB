from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

FIELD_EVENT_MAP = {
    "distributionname": ["CreateTags", "DeleteTags"],
    "status": ["UpdateDistribution"],
    "domainname": ["UpdateDistribution"],
    "origins": ["UpdateDistribution"],
    "defaultcachebehavior": ["UpdateDistribution"],
    "cachebehaviors": ["UpdateDistribution"],
    "comment": ["UpdateDistribution"],
    "priceclass": ["UpdateDistribution"],
    "enabled": ["UpdateDistribution"],
    "webacl": ["UpdateDistribution"]
}

def get_distribution_changed_by(distribution_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'CloudFront' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (distribution_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception:
        return "unknown"
    finally:
        conn.close()

def get_origin_details(origins):
    """Extrae detalles de los orígenes de la distribución"""
    if not origins:
        return []
    
    origin_list = []
    for origin in origins:
        origin_info = {
            "id": origin.get("Id", ""),
            "domain": origin.get("DomainName", ""),
            "type": "S3" if ".s3." in origin.get("DomainName", "") else "Custom"
        }
        origin_list.append(origin_info)
    return origin_list

def get_cache_behavior_summary(behaviors):
    """Resume los comportamientos de caché"""
    if not behaviors:
        return "Default only"
    
    return f"Default + {len(behaviors)} custom behaviors"

def extract_distribution_data(distribution, account_name, account_id, region):
    """Extrae y formatea los datos de una distribución CloudFront"""
    config = distribution.get("DistributionConfig", {})
    tags = distribution.get("Tags", {}).get("Items", [])
    get_tag = lambda key: next((t["Value"] for t in tags if t["Key"] == key), "N/A")
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "DistributionID": distribution["Id"],
        "DistributionName": get_tag("Name"),
        "DomainName": distribution["DomainName"],
        "Status": distribution["Status"],
        "Region": region,
        "Origins": get_origin_details(config.get("Origins", {}).get("Items", [])),
        "DefaultCacheBehavior": {
            "target_origin": config.get("DefaultCacheBehavior", {}).get("TargetOriginId", ""),
            "viewer_protocol": config.get("DefaultCacheBehavior", {}).get("ViewerProtocolPolicy", "")
        },
        "CacheBehaviors": get_cache_behavior_summary(config.get("CacheBehaviors", {}).get("Items", [])),
        "Comment": config.get("Comment", ""),
        "PriceClass": config.get("PriceClass", "PriceClass_All"),
        "Enabled": config.get("Enabled", False),
        "WebACL": config.get("WebACLId", "N/A"),
        "LastModified": distribution.get("LastModifiedTime", datetime.now()).isoformat() if isinstance(distribution.get("LastModifiedTime"), datetime) else str(distribution.get("LastModifiedTime", ""))
    }

def get_cloudfront_distributions(region, credentials, account_id, account_name):
    """Obtiene todas las distribuciones CloudFront de una cuenta"""
    # CloudFront es un servicio global, solo se consulta desde us-east-1
    if region != "us-east-1":
        return []
    
    cloudfront_client = create_aws_client("cloudfront", region, credentials)
    if not cloudfront_client:
        return []
    
    try:
        distributions_info = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        
        for page in paginator.paginate():
            items = page.get("DistributionList", {}).get("Items", [])
            
            for distribution in items:
                try:
                    # Obtener tags para cada distribución
                    tags_response = cloudfront_client.list_tags_for_resource(
                        Resource=distribution["ARN"]
                    )
                    distribution["Tags"] = tags_response
                    
                    info = extract_distribution_data(distribution, account_name, account_id, region)
                    distributions_info.append(info)
                except ClientError:
                    # Si no se pueden obtener tags, continuar sin ellas
                    info = extract_distribution_data(distribution, account_name, account_id, region)
                    distributions_info.append(info)
        
        return distributions_info
    except ClientError:
        return []

def insert_or_update_cloudfront_data(cloudfront_data):
    """Inserta o actualiza datos de CloudFront en la base de datos"""
    if not cloudfront_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    insert_sql = """
        INSERT INTO cloudfront (
            AccountName, AccountID, DistributionID, DistributionName, DomainName,
            Status, Region, Origins, DefaultCacheBehavior, CacheBehaviors,
            Comment, PriceClass, Enabled, WebACL, LastModified, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, NOW()
        )
    """

    inserted = updated = processed = 0

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cloudfront")
        cols = [col[0].lower() for col in cursor.description]
        existing_rows = cursor.fetchall()
        existing = {
            row[cols.index("distributionid")]: dict(zip(cols, row))
            for row in existing_rows
        }

        for cf in cloudfront_data:
            processed += 1
            dist_id = cf["DistributionID"]
            insert_vals = (
                cf["AccountName"], cf["AccountID"], dist_id, cf["DistributionName"],
                cf["DomainName"], cf["Status"], cf["Region"], cf["Origins"],
                cf["DefaultCacheBehavior"], cf["CacheBehaviors"], cf["Comment"],
                cf["PriceClass"], cf["Enabled"], cf["WebACL"], cf["LastModified"]
            )

            db_row = existing.get(dist_id)

            if not db_row or db_row.get("accountid") != cf["AccountID"] or db_row.get("accountname") != cf["AccountName"]:
                cursor.execute(insert_sql, insert_vals)
                inserted += 1
            else:
                updates = []
                values = []
                
                campos = {
                    "accountname": cf["AccountName"],
                    "distributionname": cf["DistributionName"],
                    "domainname": cf["DomainName"],
                    "status": cf["Status"],
                    "region": cf["Region"],
                    "origins": cf["Origins"],
                    "defaultcachebehavior": cf["DefaultCacheBehavior"],
                    "cachebehaviors": cf["CacheBehaviors"],
                    "comment": cf["Comment"],
                    "priceclass": cf["PriceClass"],
                    "enabled": cf["Enabled"],
                    "webacl": cf["WebACL"],
                    "lastmodified": cf["LastModified"]
                }
                
                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_distribution_changed_by(dist_id, datetime.now())
                        log_change('CloudFront', dist_id, col, old_val, new_val, changed_by, cf["AccountID"], cf["Region"])
                
                updates.append("last_updated = NOW()")
                
                if updates:
                    update_query = f"UPDATE cloudfront SET {', '.join(updates)} WHERE distributionid = %s"
                    values.append(dist_id)
                    cursor.execute(update_query, tuple(values))
                    updated += 1

        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}

    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()