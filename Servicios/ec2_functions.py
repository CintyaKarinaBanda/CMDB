from botocore.exceptions import ClientError
from datetime import datetime
from Servicios.utils import create_aws_client, get_db_connection

def get_instance_changed_by(instance_id, update_date):
    """Get the user who last modified an instance."""
    if not (conn := get_db_connection()):
        print("DB connection error for changed_by lookup")
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM ec2_cloudtrail_events
                WHERE resource_name = %s AND ABS(EXTRACT(EPOCH FROM (event_time - %s)) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (instance_id, update_date, update_date))
            return cursor.fetchone()[0] or "unknown"
    except Exception as e:
        print(f"Changed_by lookup error: {str(e)}")
        return "unknown"
    finally:
        conn.close()

def get_resource_name(ec2_client, resource_type, resource_id, name_tag='Name'):
    """Generic function to get resource names with tags."""
    try:
        describe_func = getattr(ec2_client, f'describe_{resource_type}s')
        resource = describe_func(**{f'{resource_type}Ids': [resource_id]})[f'{resource_type}s'][0]
        if tag_value := next((t['Value'] for t in resource.get('Tags', []) if t['Key'] == name_tag), None):
            return f"{resource_id} ({tag_value})"
        return resource_id
    except ClientError:
        print(f"Failed to get {resource_type} name for {resource_id}")
        return resource_id

def get_platform_details(ec2_client, instance_id):
    """Get instance platform details."""
    try:
        instance = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        return instance.get('PlatformDetails') or 'Windows' if instance.get('Platform') == 'windows' else 'Linux/UNIX'
    except ClientError as e:
        print(f"Platform details error: {str(e)}")
        return 'Unavailable'

def extract_instance_data(instance, ec2_client, account_info):
    """Extract and format EC2 instance data."""
    tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
    return {
        **account_info,
        'InstanceID': instance['InstanceId'],
        'InstanceName': tags.get('Name', 'N/A'),
        'InstanceType': instance['InstanceType'],
        'State': instance['State']['Name'],
        'AvailabilityZone': instance['Placement']['AvailabilityZone'],
        'VPC': get_resource_name(ec2_client, 'vpc', instance['VpcId']) if instance.get('VpcId') else 'N/A',
        'Subnet': instance.get('SubnetId', 'N/A'),
        'OSImageID': instance.get('ImageId', 'N/A'),
        'OSDetails': get_platform_details(ec2_client, instance['InstanceId']),
        'IAMRole': instance.get('IamInstanceProfile', {}).get('Arn', 'N/A').split('/')[-1],
        'SecurityGroups': [sg['GroupName'] for sg in instance.get('SecurityGroups', [])],
        'KeyName': instance.get('KeyName', 'N/A'),
        'PublicIP': instance.get('PublicIpAddress', 'N/A'),
        'PrivateIP': instance.get('PrivateIpAddress', 'N/A'),
        'StorageVolumes': [bdm['Ebs']['VolumeId'] for bdm in instance.get('BlockDeviceMappings', []) if 'Ebs' in bdm]
    }

def get_ec2_instances(region, credentials, account_id, account_name):
    """Retrieve all EC2 instances in a region."""
    if not (ec2_client := create_aws_client('ec2', region, credentials)):
        return []
    try:
        account_info = {'AccountName': account_name, 'AccountID': account_id, 'Region': region}
        return [
            extract_instance_data(instance, ec2_client, account_info)
            for page in ec2_client.get_paginator('describe_instances').paginate()
            for reservation in page.get('Reservations', [])
            for instance in reservation.get('Instances', [])
        ]
    except ClientError as e:
        print(f"EC2 instances error: {str(e)}")
        return []

def insert_or_update_ec2_data(ec2_data, region, credentials=None):
    """Update database with EC2 instance information."""
    if not ec2_data or not (conn := get_db_connection()):
        return {'error': 'No data or DB connection failed', 'processed': 0}

    fields = [
        'AccountName', 'AccountID', 'InstanceID', 'InstanceName', 'InstanceType',
        'State', 'Region', 'AvailabilityZone', 'VPC', 'Subnet', 'OSImageID',
        'OSDetails', 'IAMRole', 'SecurityGroups', 'KeyName', 'PublicIP',
        'PrivateIP', 'StorageVolumes'
    ]

    try:
        with conn.cursor() as cursor:
            # Verify database schema
            cursor.execute("""
                SELECT column_name, data_type FROM information_schema.columns 
                WHERE table_name = 'ec2'
            """)
            db_columns = {row[0].lower(): row[1] for row in cursor.fetchall()}

            cursor.execute("SELECT instanceid FROM ec2")
            existing_ids = {row[0] for row in cursor.fetchall()}

            inserted, updated = 0, 0
            for ec2 in ec2_data:
                values = [ec2[f] for f in fields]
                
                if ec2['InstanceID'] not in existing_ids:
                    cursor.execute(
                        f"INSERT INTO ec2 ({','.join(fields)}, last_updated) VALUES ({','.join(['%s']*len(fields))}, CURRENT_TIMESTAMP)",
                        values
                    )
                    inserted += 1
                else:
                    updates = []
                    history_values = []
                    for col in fields:
                        db_col = col.lower()
                        if db_col not in db_columns:
                            continue
                            
                        new_val = str(ec2[col])
                        old_val = cursor.execute(
                            f"SELECT {db_col} FROM ec2 WHERE instanceid = %s",
                            (ec2['InstanceID'],)
                        ).fetchone()[0]
                        
                        if str(old_val) != new_val:
                            updates.append(f"{db_col} = %s")
                            history_values.append((
                                ec2['InstanceID'], db_col, old_val, new_val,
                                get_instance_changed_by(ec2['InstanceID'], datetime.now())
                            ))
                    
                    if updates:
                        cursor.executemany(
                            "INSERT INTO ec2_changes_history VALUES (%s, %s, %s, %s, %s)",
                            history_values
                        )
                        cursor.execute(
                            f"UPDATE ec2 SET {','.join(updates)}, last_updated = CURRENT_TIMESTAMP WHERE instanceid = %s",
                            [ec2[f] for f in fields if f.lower() in updates] + [ec2['InstanceID']]
                        )
                        updated += 1

            conn.commit()
            return {'processed': len(ec2_data), 'inserted': inserted, 'updated': updated}
    except Exception as e:
        conn.rollback()
        print(f"DB operation failed: {str(e)}")
        return {'error': str(e), 'processed': 0}
    finally:
        conn.close()