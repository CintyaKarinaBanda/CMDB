from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from services.utils import create_aws_client, get_db_connection
import boto3

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

def get_bucket_size(s3_client, bucket_name):
    try:
        cw_client = boto3.client('cloudwatch', region_name=s3_client._client_config.region_name or 'us-east-1')
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=2)
        
        storage_types = ['StandardStorage', 'StandardIAStorage', 'ReducedRedundancyStorage', 
                        'GlacierStorage', 'DeepArchiveStorage', 'IntelligentTieringFAStorage']
        
        total_bytes = 0
        for storage_type in storage_types:
            try:
                response = cw_client.get_metric_statistics(
                    Namespace='AWS/S3', MetricName='BucketSizeBytes',
                    Dimensions=[{'Name': 'BucketName', 'Value': bucket_name}, {'Name': 'StorageType', 'Value': storage_type}],
                    StartTime=start_time, EndTime=end_time, Period=86400, Statistics=['Average']
                )
                if response['Datapoints']:
                    total_bytes += int(max(response['Datapoints'], key=lambda x: x['Timestamp'])['Average'])
            except: continue
        
        if total_bytes >= 1024**3: return f"{total_bytes / (1024**3):.2f} GB"
        elif total_bytes >= 1024**2: return f"{total_bytes / (1024**2):.2f} MB"
        elif total_bytes >= 1024: return f"{total_bytes / 1024:.2f} KB"
        else: return f"{total_bytes} B"
    except: return "0 B"

def extract_bucket_data(bucket, s3_client, account_name, account_id, region):
    bucket_name = bucket['Name']
    try:
        tags = s3_client.get_bucket_tagging(Bucket=bucket_name).get('TagSet', []) if True else []
        get_tag = lambda key: next((t["Value"] for t in tags if t["Key"] == key), "N/A")
        
        versioning_status = s3_client.get_bucket_versioning(Bucket=bucket_name).get('Status', 'Disabled') if True else "N/A"
        encryption_config = "Enabled" if s3_client.get_bucket_encryption(Bucket=bucket_name).get('ServerSideEncryptionConfiguration') else "Disabled" if True else "Disabled"
        bucket_region = s3_client.get_bucket_location(Bucket=bucket_name).get('LocationConstraint') or 'us-east-1' if True else region
        network_config = "Private" if s3_client.get_public_access_block(Bucket=bucket_name).get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls') else "Public" if True else "Unknown"
        
        notifications = s3_client.get_bucket_notification_configuration(Bucket=bucket_name) if True else {}
        integrations = []
        if notifications.get('LambdaConfigurations'): integrations.append("Lambda")
        if notifications.get('QueueConfigurations'): integrations.append("SQS")
        if notifications.get('TopicConfigurations'): integrations.append("SNS")
        integrations_str = ",".join(integrations) if integrations else "None"
        
        backup_recovery = "Enabled" if s3_client.get_bucket_replication(Bucket=bucket_name).get('ReplicationConfiguration') else "Disabled" if True else "Disabled"
        
        return {
            "AccountName": account_name, "AccountID": account_id, "BucketName": bucket_name,
            "BucketNameDisplay": get_tag("Name") if get_tag("Name") != "N/A" else bucket_name,
            "Region": bucket_region, "Status": "Active", "Owner": get_tag("Owner"),
            "Integrations": integrations_str, "NetworkConfig": network_config,
            "BackupRecovery": backup_recovery, "Encryption": encryption_config,
            "Versioning": versioning_status, "Capacity": get_bucket_size(s3_client, bucket_name)
        }
    except Exception: return None

def get_s3_buckets(region, credentials, account_id, account_name):
    s3_client = create_aws_client("s3", region, credentials)
    if not s3_client: return []

    try:
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
                info = extract_bucket_data(bucket, s3_client, account_name, account_id, region)
                if info: buckets_info.append(info)
        
        return buckets_info
    except: return []


def insert_or_update_s3_data(s3_data):
    if not s3_data: return {"processed": 0, "inserted": 0, "updated": 0}
    
    conn = get_db_connection()
    if not conn: return {"error": "DB connection failed"}
    
    try:
        cursor = conn.cursor()
        inserted = 0
        
        for bucket in s3_data:
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
        
        conn.commit()
        return {"processed": len(s3_data), "inserted": inserted, "updated": 0}
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}
    finally:
        conn.close()