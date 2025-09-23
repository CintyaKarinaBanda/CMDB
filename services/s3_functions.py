from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import time
from services.utils import create_aws_client, get_db_connection, log_change

def get_bucket_changed_by(bucket_name, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'S3' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (bucket_name, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def get_bucket_size(bucket_name, cw_client):
    if not cw_client:
        pass
        return "N/A"

    try:
        start, end = datetime.utcnow() - timedelta(days=7), datetime.utcnow()
        storage_types = [
            'StandardStorage', 'StandardIAStorage', 
            'ReducedRedundancyStorage', 'GlacierStorage'
        ]
        total_bytes = 0

        for st in storage_types:
            try:
                resp = cw_client.get_metric_statistics(
                    Namespace='AWS/S3', MetricName='BucketSizeBytes',
                    Dimensions=[{'Name': 'BucketName', 'Value': bucket_name}, {'Name': 'StorageType', 'Value': st}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Maximum']
                )
                datapoints = resp.get('Datapoints', [])
                if datapoints:
                    latest = max(datapoints, key=lambda x: x['Timestamp'])
                    total_bytes += int(latest.get('Maximum', 0))
            except Exception as e:
                pass

        if total_bytes == 0: return "0 B"
        for unit, size in [("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)]:
            if total_bytes >= size:
                return f"{total_bytes / size:.2f} {unit}"
        return f"{total_bytes} B"
    except Exception as e:
        pass
        return "N/A"

def extract_bucket_data(bucket, s3, account_name, account_id, region, cw_client):
    name = bucket['Name']
    tag_val = lambda k, tags: next((t["Value"] for t in tags if t["Key"] == k), "N/A")

    try:
        def try_get(fn, key, default="N/A", inner=lambda x: x):
            try: return inner(fn(Bucket=name).get(key, default))
            except ClientError: return default

        tags = try_get(s3.get_bucket_tagging, 'TagSet', [], lambda x: x)
        versioning = try_get(s3.get_bucket_versioning, 'Status', 'Disabled')
        encryption = try_get(s3.get_bucket_encryption, 'ServerSideEncryptionConfiguration', None)
        encryption_config = "Enabled" if encryption else "Disabled"
        bucket_region = try_get(s3.get_bucket_location, 'LocationConstraint') or 'us-east-1'

        network_config = "Unknown"
        try:
            pab = s3.get_public_access_block(Bucket=name)
            network_config = "Private" if pab.get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls') else "Public"
        except ClientError: pass

        integrations = []
        try:
            notify = s3.get_bucket_notification_configuration(Bucket=name)
            if notify.get('LambdaConfigurations'): integrations.append("Lambda")
            if notify.get('QueueConfigurations'): integrations.append("SQS")
            if notify.get('TopicConfigurations'): integrations.append("SNS")
        except ClientError: pass
        integrations_str = ",".join(integrations) if integrations else "None"

        backup_recovery = "Disabled"
        try:
            rep = s3.get_bucket_replication(Bucket=name)
            if rep.get('ReplicationConfiguration'): backup_recovery = "Enabled"
        except ClientError: pass

        capacity = get_bucket_size(name, cw_client)
        display_name = tag_val("Name", tags) or name

        return {
            "AccountName": account_name, "AccountID": account_id, "BucketName": name,
            "BucketNameDisplay": display_name, "Region": bucket_region, "Status": "Active",
            "Owner": tag_val("Owner", tags), "Integrations": integrations_str,
            "NetworkConfig": network_config, "BackupRecovery": backup_recovery,
            "Encryption": encryption_config, "Versioning": versioning, "Capacity": capacity
        }
    except Exception as e:
        pass
        return None

def get_s3_buckets(region, credentials, account_id, account_name):
    s3 = create_aws_client("s3", region, credentials)
    if not s3: return []
    cw = create_aws_client("cloudwatch", "us-east-1", credentials)

    try:
        try: s3.list_buckets()
        except Exception as e:
            pass
            return []

        response = s3.list_buckets()
        return [
            info for b in response.get('Buckets', [])
            if (info := extract_bucket_data(b, s3, account_name, account_id, region, cw))
        ]
    except Exception as e:
        pass
        return []

def insert_or_update_s3_data(s3_data):
    if not s3_data: return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn: return {"error": "DB connection failed"}

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM s3")
        cols = [d[0].lower() for d in cur.description]
        existing = {(r[cols.index("bucket_name")], r[cols.index("account_id")]): dict(zip(cols, r)) for r in cur.fetchall()}

        ins, upd = 0, 0
        for b in s3_data:
            bn = b["BucketName"]
            if (bn, b["AccountID"]) not in existing:
                cur.execute("""
                    INSERT INTO s3 (account_name, account_id, bucket_name, bucket_name_display,
                    region, status, owner, integrations, network_config, backup_recovery,
                    encryption, versioning, capacity, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    b["AccountName"], b["AccountID"], bn, b["BucketNameDisplay"], b["Region"],
                    b["Status"], b["Owner"], b["Integrations"], b["NetworkConfig"],
                    b["BackupRecovery"], b["Encryption"], b["Versioning"], b["Capacity"]
                ))
                ins += 1
            else:
                old_data = existing[(bn, b["AccountID"])]
                updates = []
                vals = []
                
                # Comparar y registrar cambios
                fields_map = {
                    "owner": b["Owner"],
                    "integrations": b["Integrations"],
                    "network_config": b["NetworkConfig"],
                    "backup_recovery": b["BackupRecovery"],
                    "encryption": b["Encryption"],
                    "versioning": b["Versioning"],
                    "capacity": b["Capacity"]
                }
                
                for field, new_val in fields_map.items():
                    old_val = old_data.get(field)
                    if str(old_val) != str(new_val):
                        updates.append(f"{field} = %s")
                        vals.append(new_val)
                        changed_by = get_bucket_changed_by(bn, datetime.now())
                        log_change('S3', bn, field, old_val, new_val, changed_by, b["AccountID"], b["Region"])
                
                if updates:
                    updates.append("last_updated = NOW()")
                    cur.execute(f"UPDATE s3 SET {', '.join(updates)} WHERE bucket_name = %s", vals + [bn])
                    upd += 1
                else:
                    cur.execute("UPDATE s3 SET last_updated = NOW() WHERE bucket_name = %s", [bn])

        conn.commit()
        return {"processed": len(s3_data), "inserted": ins, "updated": upd}
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}
    finally:
        conn.close()
