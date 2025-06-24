from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection

FIELD_EVENT_MAP = {
    "bucket_name": ["CreateBucket", "DeleteBucket"],
    "bucket_name_display": ["CreateTags", "DeleteTags", "PutBucketTagging"],
    "region": ["CreateBucket"],
    "status": ["CreateBucket", "DeleteBucket"],
    "owner": ["CreateTags", "DeleteTags", "PutBucketTagging"],
    "integrations": ["PutBucketNotification", "DeleteBucketNotification"],
    "network_config": ["PutBucketAcl", "PutPublicAccessBlock", "PutBucketPolicy"],
    "backup_recovery": ["PutBucketReplication", "DeleteBucketReplication", "PutBucketVersioning"],
    "encryption": ["PutBucketEncryption", "DeleteBucketEncryption"],
    "versioning": ["PutBucketVersioning"],
    "capacity": ["PutObject", "DeleteObject", "RestoreObject"]
}

def get_bucket_changed_by(bucket_name, field_name):
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
                    WHERE resource_name = %s AND resource_type = 'S3'
                    AND event_name IN ({placeholders})
                    ORDER BY event_time DESC LIMIT 1
                """
                cursor.execute(query, (bucket_name, *possible_events))
            else:
                cursor.execute("""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = 'S3'
                    ORDER BY event_time DESC LIMIT 1
                """, (bucket_name,))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: changed_by {bucket_name}/{field_name} - {str(e)}")
        return "unknown"
    finally:
        conn.close()

def get_bucket_size(s3_client, bucket_name):
    """Obtiene el tamaño total del bucket usando CloudWatch metrics"""
    try:
        from datetime import timedelta
        import boto3
        
        # Crear cliente CloudWatch en la misma región
        region = s3_client._client_config.region_name or 'us-east-1'
        cw_client = boto3.client('cloudwatch', region_name=region)
        
        # Obtener métricas de los últimos 2 días para asegurar datos
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=2)
        
        total_size = 0
        storage_types = ['StandardStorage', 'StandardIAStorage', 'ReducedRedundancyStorage', 
                        'GlacierStorage', 'DeepArchiveStorage', 'IntelligentTieringFAStorage',
                        'IntelligentTieringIAStorage', 'IntelligentTieringAAStorage',
                        'IntelligentTieringAIAStorage', 'IntelligentTieringDAAStorage']
        
        for storage_type in storage_types:
            try:
                response = cw_client.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName='BucketSizeBytes',
                    Dimensions=[
                        {'Name': 'BucketName', 'Value': bucket_name},
                        {'Name': 'StorageType', 'Value': storage_type}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Maximum']
                )
                
                if response['Datapoints']:
                    # Tomar el valor más reciente
                    latest_datapoint = max(response['Datapoints'], key=lambda x: x['Timestamp'])
                    total_size += int(latest_datapoint['Maximum'])
            except Exception:
                continue
        
        return total_size
    except Exception:
        return 0

def extract_bucket_data(bucket, s3_client, account_name, account_id, region):
    """Extrae datos relevantes del bucket"""
    bucket_name = bucket['Name']
    
    try:
        # Obtener tags
        try:
            tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = tags_response.get('TagSet', [])
        except ClientError:
            tags = []
        
        get_tag = lambda key: next((t["Value"] for t in tags if t["Key"] == key), "N/A")
        
        # Obtener configuraciones
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_status = versioning.get('Status', 'Disabled')
        except ClientError:
            versioning_status = "N/A"
        
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            encryption_config = "Enabled" if encryption.get('ServerSideEncryptionConfiguration') else "Disabled"
        except ClientError:
            encryption_config = "Disabled"
        
        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_region = location.get('LocationConstraint') or 'us-east-1'
        except ClientError:
            bucket_region = region
        
        # Obtener configuración de red/acceso público
        try:
            public_access = s3_client.get_public_access_block(Bucket=bucket_name)
            network_config = "Private" if public_access.get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls') else "Public"
        except ClientError:
            network_config = "Unknown"
        
        # Obtener notificaciones (integraciones)
        try:
            notifications = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            integrations = []
            if notifications.get('LambdaConfigurations'):
                integrations.append("Lambda")
            if notifications.get('QueueConfigurations'):
                integrations.append("SQS")
            if notifications.get('TopicConfigurations'):
                integrations.append("SNS")
            integrations_str = ",".join(integrations) if integrations else "None"
        except ClientError:
            integrations_str = "None"
        
        # Obtener replicación (backup)
        try:
            replication = s3_client.get_bucket_replication(Bucket=bucket_name)
            backup_recovery = "Enabled" if replication.get('ReplicationConfiguration') else "Disabled"
        except ClientError:
            backup_recovery = "Disabled"
        
        capacity = get_bucket_size(s3_client, bucket_name)
        
        return {
            "AccountName": account_name,
            "AccountID": account_id,
            "BucketName": bucket_name,
            "BucketNameDisplay": get_tag("Name") if get_tag("Name") != "N/A" else bucket_name,
            "Region": bucket_region,
            "Status": "Active",
            "Owner": get_tag("Owner"),
            "Integrations": integrations_str,
            "NetworkConfig": network_config,
            "BackupRecovery": backup_recovery,
            "Encryption": encryption_config,
            "Versioning": versioning_status,
            "Capacity": capacity
        }
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Extract bucket {bucket_name} - {str(e)}")
        return None

def get_s3_buckets(region, credentials, account_id, account_name):
    """Obtiene buckets S3 de una cuenta"""
    s3_client = create_aws_client("s3", region, credentials)
    if not s3_client:
        return []

    try:
        response = s3_client.list_buckets()
        buckets_info = []

        for bucket in response.get('Buckets', []):
            info = extract_bucket_data(bucket, s3_client, account_name, account_id, region)
            if info:
                buckets_info.append(info)
        
        if buckets_info:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: S3 {region}: {len(buckets_info)} buckets encontrados")
        return buckets_info
    except ClientError as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: S3 {region}/{account_id} - {str(e)}")
        return []

def insert_or_update_s3_data(s3_data):
    """Inserta o actualiza datos de S3 con seguimiento de cambios"""
    if not s3_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO s3 (
            account_name, account_id, bucket_name, bucket_name_display,
            region, status, owner, integrations, network_config,
            backup_recovery, encryption, versioning, capacity, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO s3_changes_history (bucket_name, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM s3")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("bucket_name")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for bucket in s3_data:
            bucket_name = bucket["BucketName"]
            processed += 1

            insert_values = (
                bucket["AccountName"], bucket["AccountID"], bucket["BucketName"],
                bucket["BucketNameDisplay"], bucket["Region"],
                bucket["Status"], bucket["Owner"], bucket["Integrations"],
                bucket["NetworkConfig"], bucket["BackupRecovery"], bucket["Encryption"],
                bucket["Versioning"], bucket["Capacity"]
            )

            if bucket_name not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[bucket_name]
                updates = []
                values = []

                campos = {
                    "account_name": bucket["AccountName"],
                    "account_id": bucket["AccountID"],
                    "bucket_name": bucket["BucketName"],
                    "bucket_name_display": bucket["BucketNameDisplay"],
                    "region": bucket["Region"],
                    "status": bucket["Status"],
                    "owner": bucket["Owner"],
                    "integrations": bucket["Integrations"],
                    "network_config": bucket["NetworkConfig"],
                    "backup_recovery": bucket["BackupRecovery"],
                    "encryption": bucket["Encryption"],
                    "versioning": bucket["Versioning"],
                    "capacity": bucket["Capacity"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_bucket_changed_by(
                            bucket_name=bucket_name,
                            field_name=col
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (bucket_name, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE s3 SET {', '.join(updates)} WHERE bucket_name = %s"
                    values.append(bucket_name)
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
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: DB s3_data - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()