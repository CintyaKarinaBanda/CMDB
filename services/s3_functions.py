from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from services.utils import create_aws_client, get_db_connection

def get_bucket_changed_by(bucket_name, field_name):
    conn = get_db_connection()
    if not conn: return "unknown"
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_name FROM cloudtrail_events WHERE resource_name = %s AND resource_type = 'S3' ORDER BY event_time DESC LIMIT 1", (bucket_name,))
        result = cursor.fetchone()
        return result[0] if result else "unknown"
    except: return "unknown"
    finally: conn.close()

def get_bucket_size(bucket_name, cw_client):
    if not cw_client: return "N/A-o"
    
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=7)
        
        storage_types = ['StandardStorage', 'StandardIAStorage', 'ReducedRedundancyStorage', 'GlacierStorage']
        total_bytes = 0
        
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
                
                datapoints = response.get('Datapoints', [])
                if datapoints:
                    latest = max(datapoints, key=lambda x: x['Timestamp'])
                    print(f"Datapoints for {bucket_name} ({storage_type}):")
                    print(latest)
                    total_bytes += int(latest.get('Maximum', 0))
            except Exception as e:
                print(f"Error storage {storage_type} para {bucket_name}: {e}")
                continue
        
        if total_bytes == 0: return "0-0 B"
        if total_bytes >= 1024**4: return f"{total_bytes / (1024**4):.2f} TB"
        elif total_bytes >= 1024**3: return f"{total_bytes / (1024**3):.2f} GB"
        elif total_bytes >= 1024**2: return f"{total_bytes / (1024**2):.2f} MB"
        elif total_bytes >= 1024: return f"{total_bytes / 1024:.2f} KB"
        else: return f"{total_bytes} B"
        
    except Exception as e:
        print(f"Error bucket size {bucket_name}: {e}")
        return "N/A"

def extract_bucket_data(bucket, s3_client, account_name, account_id, region, cw_client):
    bucket_name = bucket['Name']
    try:
        try:
            tags = s3_client.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
        except ClientError:
            tags = []
        
        get_tag = lambda key: next((t["Value"] for t in tags if t["Key"] == key), "N/A")
        
        try:
            versioning_status = s3_client.get_bucket_versioning(Bucket=bucket_name).get('Status', 'Disabled')
        except ClientError:
            versioning_status = "N/A"
        
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            encryption_config = "Enabled" if encryption.get('ServerSideEncryptionConfiguration') else "Disabled"
        except ClientError:
            encryption_config = "Disabled"
        
        try:
            bucket_region = s3_client.get_bucket_location(Bucket=bucket_name).get('LocationConstraint') or 'us-east-1'
        except ClientError:
            bucket_region = region
        
        try:
            public_access = s3_client.get_public_access_block(Bucket=bucket_name)
            network_config = "Private" if public_access.get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls') else "Public"
        except ClientError:
            network_config = "Unknown"
        
        try:
            notifications = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            integrations = []
            if notifications.get('LambdaConfigurations'): integrations.append("Lambda")
            if notifications.get('QueueConfigurations'): integrations.append("SQS")
            if notifications.get('TopicConfigurations'): integrations.append("SNS")
            integrations_str = ",".join(integrations) if integrations else "None"
        except ClientError:
            integrations_str = "None"
        
        try:
            replication = s3_client.get_bucket_replication(Bucket=bucket_name)
            backup_recovery = "Enabled" if replication.get('ReplicationConfiguration') else "Disabled"
        except ClientError:
            backup_recovery = "Disabled"
        
        capacity = get_bucket_size(bucket_name, cw_client)
        
        return {
            "AccountName": account_name, "AccountID": account_id, "BucketName": bucket_name,
            "BucketNameDisplay": get_tag("Name") if get_tag("Name") != "N/A" else bucket_name,
            "Region": bucket_region, "Status": "Active", "Owner": get_tag("Owner"),
            "Integrations": integrations_str, "NetworkConfig": network_config,
            "BackupRecovery": backup_recovery, "Encryption": encryption_config,
            "Versioning": versioning_status, "Capacity": capacity
        }
    except Exception as e:
        print(f"ERROR: Extract bucket {bucket_name} - {str(e)}")
        return None

def get_s3_buckets(region, credentials, account_id, account_name):
    print(f"INFO: get_s3_buckets {account_name} {region}")
    s3_client = create_aws_client("s3", region, credentials)
    if not s3_client: return []
    
    # Crear cliente CloudWatch una sola vez para todas las métricas
    cw_client = create_aws_client("cloudwatch", "us-east-1", credentials)
    if not cw_client:
        print(f"WARN: No se pudo crear cliente CloudWatch para {account_name}")

    try:
        # Validar credenciales con una llamada simple
        try:
            s3_client.list_buckets()
        except Exception as e:
            print(f"ERROR: Credenciales inválidas para {account_name}: {e}")
            return []
        
        conn = get_db_connection()
        existing_buckets = set()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT bucket_name FROM s3")
            existing_buckets = {row[0] for row in cursor.fetchall()}
            conn.close()
        
        response = s3_client.list_buckets()
        buckets_info = []
        
        for bucket in response.get('Buckets', []):
            if bucket['Name'] not in existing_buckets:
                info = extract_bucket_data(bucket, s3_client, account_name, account_id, region, cw_client)
                if info: buckets_info.append(info)
        
        if buckets_info:
            print(f"INFO: S3 {region}: {len(buckets_info)} buckets nuevos encontrados")
        return buckets_info
    except Exception as e:
        print(f"ERROR: get_s3_buckets {account_name}: {e}")
        return []

def insert_or_update_s3_data(s3_data):
    if not s3_data: return {"processed": 0, "inserted": 0, "updated": 0}
    
    conn = get_db_connection()
    if not conn: return {"error": "DB connection failed"}
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM s3")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("bucket_name")]: dict(zip(columns, row)) for row in cursor.fetchall()}
        
        inserted = updated = 0
        
        for bucket in s3_data:
            bucket_name = bucket["BucketName"]
            
            if bucket_name not in existing_data:
                cursor.execute("""
                    INSERT INTO s3 (account_name, account_id, bucket_name, bucket_name_display,
                    region, status, owner, integrations, network_config, backup_recovery, 
                    encryption, versioning, capacity, last_updated) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (
                    bucket["AccountName"], bucket["AccountID"], bucket["BucketName"],
                    bucket["BucketNameDisplay"], bucket["Region"], bucket["Status"],
                    bucket["Owner"], bucket["Integrations"], bucket["NetworkConfig"],
                    bucket["BackupRecovery"], bucket["Encryption"], bucket["Versioning"], bucket["Capacity"]
                ))
                inserted += 1
            else:
                # Actualizar capacity siempre, incluso si es N/A
                cursor.execute("UPDATE s3 SET capacity = %s, last_updated = CURRENT_TIMESTAMP WHERE bucket_name = %s", 
                             (bucket["Capacity"], bucket_name))
                updated += 1
        
        conn.commit()
        return {"processed": len(s3_data), "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}
    finally:
        conn.close()