from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

FIELD_EVENT_MAP = {
    "instancename": ["CreateTags", "DeleteTags"],
    "instancetype": ["ModifyInstanceAttribute"],
    "state": ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"],
    "iamrole": ["AssociateIamInstanceProfile", "DisassociateIamInstanceProfile"],
    "securitygroups": ["ModifyInstanceAttribute", "AuthorizeSecurityGroupIngress", "StartInstances", "StopInstances", "TerminateInstances"],
    "publicip": ["AssociateAddress", "DisassociateAddress", "StartInstances", "StopInstances", "TerminateInstances"],
    "privateip": ["ModifyInstanceAttribute", "StartInstances", "StopInstances", "TerminateInstances"],
    "vpc": ["ModifyInstanceAttribute", "StartInstances", "StopInstances", "TerminateInstances"],
    "subnet": ["ModifyInstanceAttribute", "StartInstances", "StopInstances", "TerminateInstances"],
    "storagevolumes": ["AttachVolume", "DetachVolume"]
}

def normalize_list_comparison(old_val, new_val):
    """Normaliza listas para comparación, ignorando orden"""
    if isinstance(new_val, list) and isinstance(old_val, (list, str)):
        old_list = old_val if isinstance(old_val, list) else str(old_val).split(',') if old_val else []
        return sorted([str(x).strip() for x in old_list]) == sorted([str(x).strip() for x in new_val])
    return str(old_val) == str(new_val)

def get_instance_changed_by(instance_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'EC2' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (instance_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

"""
def get_instance_changed_by(instance_id, update_date=None):
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_name = %s AND resource_type = 'EC2'
                ORDER BY event_time DESC LIMIT 1
            "", (instance_id,))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: changed_by {instance_id} - {str(e)}")
        return "unknown"
    finally:
        conn.close()
"""

def get_vpc_name(ec2_client, vpc_id):
    try:
        vpc = ec2_client.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        tag = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), None)
        return f"{vpc_id} ({tag})" if tag else vpc_id
    except ClientError:
        pass
        return vpc_id

def get_platform_details(ec2_client, instance_id):
    try:
        instance = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        if instance.get('Platform') == 'windows':
            return instance.get('PlatformDetails', 'Windows')
        if 'PlatformDetails' in instance:
            return instance['PlatformDetails']
        image_id = instance.get('ImageId')
        if image_id:
            try:
                image = ec2_client.describe_images(ImageIds=[image_id])['Images'][0]
                return image.get('Description', 'Linux/UNIX')
            except ClientError:
                pass
        return 'Linux/UNIX'
    except ClientError as e:
        pass
        return 'Unavailable'

def extract_instance_data(instance, ec2_client, account_name, account_id, region):
    tags = instance.get("Tags", [])
    get_tag = lambda key: next((t["Value"] for t in tags if t["Key"] == key), "N/A")
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "InstanceID": instance["InstanceId"],
        "InstanceName": get_tag("Name"),
        "InstanceType": instance["InstanceType"],
        "State": instance["State"]["Name"],
        "Region": region,
        "AvailabilityZone": instance["Placement"]["AvailabilityZone"],
        "VPC": get_vpc_name(ec2_client, instance.get("VpcId", "")) if instance.get("VpcId") else "N/A",
        "Subnet": instance.get("SubnetId", "N/A"),
        "OSImageID": instance.get("ImageId", "N/A"),
        "OSDetails": get_platform_details(ec2_client, instance["InstanceId"]),
        "IAMRole": instance.get("IamInstanceProfile", {}).get("Arn", "N/A").split("/")[-1],
        "SecurityGroups": [sg["GroupName"] for sg in instance.get("SecurityGroups", [])],
        "KeyName": instance.get("KeyName", "N/A"),
        "PublicIP": instance.get("PublicIpAddress", "N/A"),
        "PrivateIP": instance.get("PrivateIpAddress", "N/A"),
        "StorageVolumes": [bdm["Ebs"]["VolumeId"] for bdm in instance.get("BlockDeviceMappings", []) if "Ebs" in bdm]
    }

def get_ec2_instances(region, credentials, account_id, account_name):
    ec2_client = create_aws_client("ec2", region, credentials)
    if not ec2_client:
        return []
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        instances_info = []
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    info = extract_instance_data(instance, ec2_client, account_name, account_id, region)
                    instances_info.append(info)
        return instances_info
    except ClientError as e:
        return []

def insert_or_update_ec2_data(ec2_data):
    if not ec2_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    insert_sql = """
        INSERT INTO ec2 (
            AccountName, AccountID, InstanceID, InstanceName, InstanceType,
            State, Region, AvailabilityZone, VPC, Subnet, OSImageID,
            OSDetails, IAMRole, SecurityGroups, KeyName, PublicIP,
            PrivateIP, StorageVolumes, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, NOW()
        )
    """

    inserted = updated = processed = 0

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ec2")
        cols = [col[0].lower() for col in cursor.description]
        existing_rows = cursor.fetchall()
        existing = {
            row[cols.index("instanceid")]: dict(zip(cols, row))
            for row in existing_rows
        }

        for ec2 in ec2_data:
            processed += 1
            iid = ec2["InstanceID"]
            insert_vals = (
                ec2["AccountName"], ec2["AccountID"], iid, ec2["InstanceName"],
                ec2["InstanceType"], ec2["State"], ec2["Region"], ec2["AvailabilityZone"],
                ec2["VPC"], ec2["Subnet"], ec2["OSImageID"], ec2["OSDetails"],
                ec2["IAMRole"], ec2["SecurityGroups"], ec2["KeyName"],
                ec2["PublicIP"], ec2["PrivateIP"], ec2["StorageVolumes"]
            )

            db_row = existing.get(iid)

            if not db_row or db_row.get("accountid") != ec2["AccountID"] or db_row.get("accountname") != ec2["AccountName"]:
                cursor.execute(insert_sql, insert_vals)
                inserted += 1
            else:
                updates = []
                values = []
                
                campos = {
                    "accountname": ec2["AccountName"],
                    "instancename": ec2["InstanceName"],
                    "instancetype": ec2["InstanceType"],
                    "state": ec2["State"],
                    "region": ec2["Region"],
                    "availabilityzone": ec2["AvailabilityZone"],
                    "vpc": ec2["VPC"],
                    "subnet": ec2["Subnet"],
                    "osimageid": ec2["OSImageID"],
                    "osdetails": ec2["OSDetails"],
                    "iamrole": ec2["IAMRole"],
                    "securitygroups": ec2["SecurityGroups"],
                    "keyname": ec2["KeyName"],
                    "publicip": ec2["PublicIP"],
                    "privateip": ec2["PrivateIP"],
                    "storagevolumes": ec2["StorageVolumes"]
                }
                
                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    
                    # Comparación especial para listas
                    if col in ['securitygroups', 'storagevolumes']:
                        if not normalize_list_comparison(old_val, new_val):
                            updates.append(f"{col} = %s")
                            values.append(new_val)
                            changed_by = get_instance_changed_by(iid, datetime.now())
                            log_change('EC2', iid, col, old_val, new_val, changed_by, ec2["AccountID"], ec2["Region"])
                    else:
                        if str(old_val) != str(new_val):
                            updates.append(f"{col} = %s")
                            values.append(new_val)
                            changed_by = get_instance_changed_by(iid, datetime.now())
                            log_change('EC2', iid, col, old_val, new_val, changed_by, ec2["AccountID"], ec2["Region"])
                
                updates.append("last_updated = NOW()")
                
                if updates:
                    update_query = f"UPDATE ec2 SET {', '.join(updates)} WHERE instanceid = %s"
                    values.append(iid)
                    cursor.execute(update_query, tuple(values))
                    updated += 1

        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}

    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()
