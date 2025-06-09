from botocore.exceptions import ClientError
from datetime import datetime
from Servicios.utils import create_aws_client, get_db_connection

def get_instance_changed_by(instance_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_category = 'EC2' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (instance_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"Error al buscar changed_by: {str(e)}")
        return "unknown"
    finally:
        conn.close()

def get_vpc_name(ec2_client, vpc_id):
    try:
        vpc = ec2_client.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        tag = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), None)
        return f"{vpc_id} ({tag})" if tag else vpc_id
    except ClientError:
        print(f"Failed to get VPC name for {vpc_id}")
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
                print(f"Failed to get image details for {image_id}")
        return 'Linux/UNIX'
    except ClientError as e:
        print(f"Error getting platform details: {str(e)}")
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
        print(f"Error getting EC2 instances: {str(e)}")
        return []

def insert_or_update_ec2_data(ec2_data):
    if not ec2_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO ec2 (
            AccountName, AccountID, InstanceID, InstanceName, InstanceType,
            State, Region, AvailabilityZone, VPC, Subnet, OSImageID,
            OSDetails, IAMRole, SecurityGroups, KeyName, PublicIP,
            PrivateIP, StorageVolumes, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO ec2_changes_history (instance_id, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM ec2")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("instanceid")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for ec2 in ec2_data:
            instance_id = ec2["InstanceID"]
            processed += 1

            insert_values = (
                ec2["AccountName"], ec2["AccountID"], ec2["InstanceID"], ec2["InstanceName"],
                ec2["InstanceType"], ec2["State"], ec2["Region"], ec2["AvailabilityZone"],
                ec2["VPC"], ec2["Subnet"], ec2["OSImageID"], ec2["OSDetails"],
                ec2["IAMRole"], ec2["SecurityGroups"], ec2["KeyName"],
                ec2["PublicIP"], ec2["PrivateIP"], ec2["StorageVolumes"]
            )

            if instance_id not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[instance_id]
                updates = []
                values = []

                campos = {
                    "accountname": ec2["AccountName"],
                    "accountid": ec2["AccountID"],
                    "instanceid": ec2["InstanceID"],
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
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_instance_changed_by(
                            instance_id=instance_id,
                            update_date=datetime.now()
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (instance_id, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE ec2 SET {', '.join(updates)} WHERE instanceid = %s"
                    values.append(instance_id)
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
        print(f"DB operation failed: {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()