from botocore.exceptions import ClientError
from datetime import datetime
from Servicios.utils import create_aws_client, get_db_connection

def get_instance_changed_by(instance_id, update_date):
    conn = get_db_connection()
    if not conn:
        print("Error al conectar a la base de datos para buscar changed_by")
        return "unknown"

    query = """
        SELECT user_name, event_time, event_name
        FROM ec2_cloudtrail_events
        WHERE resource_name = %s
          AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
        ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC
        LIMIT 1
    """

    try:
        with conn.cursor() as cursor:
            cursor.execute(query, (instance_id, update_date, update_date))
            if result := cursor.fetchone():
                user_name, event_time, event_name = result
                print(f"CloudTrail: Cambio en {instance_id} por {user_name} ({event_name}) en {event_time}")
                return user_name
    except Exception as e:
        print(f"Error al buscar changed_by: {e}")
    finally:
        conn.close()

    return "unknown"

def get_vpc_name(ec2_client, vpc_id):
    try:
        vpc = ec2_client.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        name = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), None)
        return f"{vpc_id} ({name})" if name else vpc_id
    except ClientError:
        print(f"Error al obtener nombre de VPC: {vpc_id}")
        return vpc_id

def get_platform_details(ec2_client, instance_id):
    try:
        instance = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        if (platform := instance.get('Platform')) == 'windows':
            return instance.get('PlatformDetails', 'Windows')
        if details := instance.get('PlatformDetails'):
            return details
        if image_id := instance.get('ImageId'):
            try:
                image = ec2_client.describe_images(ImageIds=[image_id])['Images'][0]
                return image.get('Description', 'Linux/UNIX')
            except ClientError:
                print(f"Error al obtener imagen: {image_id}")
        return 'Linux/UNIX'
    except ClientError as e:
        print(f"Error obteniendo detalles de plataforma: {e}")
        return 'Unavailable'

def extract_instance_data(instance, ec2_client, account_name, account_id, region):
    tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
    get_tag = lambda key: tags.get(key, "N/A")
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "InstanceID": instance["InstanceId"],
        "InstanceName": get_tag("Name"),
        "InstanceType": instance["InstanceType"],
        "State": instance["State"]["Name"],
        "Region": region,
        "AvailabilityZone": instance["Placement"]["AvailabilityZone"],
        "VPC": get_vpc_name(ec2_client, instance["VpcId"]) if "VpcId" in instance else "N/A",
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
    if not (ec2_client := create_aws_client("ec2", region, credentials)):
        return []

    try:
        paginator = ec2_client.get_paginator('describe_instances')
        return [
            extract_instance_data(instance, ec2_client, account_name, account_id, region)
            for page in paginator.paginate()
            for reservation in page.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
    except ClientError as e:
        print(f"Error obteniendo instancias EC2: {e}")
        return []

def insert_or_update_ec2_data(ec2_data, region, credentials=None):
    if not ec2_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    if not (conn := get_db_connection()):
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

    processed = inserted = updated = 0

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ec2")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {
            row[columns.index("instanceid")]: dict(zip(columns, row))
            for row in cursor.fetchall()
        }

        for ec2 in ec2_data:
            processed += 1
            instance_id = ec2["InstanceID"]
            insert_values = tuple(ec2[k] for k in [
                "AccountName", "AccountID", "InstanceID", "InstanceName", "InstanceType",
                "State", "Region", "AvailabilityZone", "VPC", "Subnet", "OSImageID",
                "OSDetails", "IAMRole", "SecurityGroups", "KeyName", "PublicIP",
                "PrivateIP", "StorageVolumes"
            ])

            if instance_id not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[instance_id]
                updates, values = [], []
                for col, new_val in ((k.lower(), v) for k, v in ec2.items()):
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_instance_changed_by(instance_id, datetime.now())
                        cursor.execute(query_change_history, (instance_id, col, str(old_val), str(new_val), changed_by))

                if updates:
                    updates.append("last_updated = CURRENT_TIMESTAMP")
                    values.append(instance_id)
                    update_query = f"UPDATE ec2 SET {', '.join(updates)} WHERE instanceid = %s"
                    cursor.execute(update_query, tuple(values))
                    updated += 1

        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        print(f"DB operation failed: {e}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()
