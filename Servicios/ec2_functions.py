from botocore.exceptions import ClientError
from datetime import datetime
from Servicios.utils import create_aws_client, get_db_connection

def get_instance_changed_by(instance_id, update_date):
    """Obtiene el usuario que realizó el último cambio en una instancia."""
    if not (conn := get_db_connection()):
        print("Error al conectar a la base de datos para buscar changed_by")
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM ec2_cloudtrail_events
                WHERE resource_name = %s AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (instance_id, update_date, update_date))
            if result := cursor.fetchone():
                print(f"CloudTrail: Cambio en {instance_id} realizado por {result[0]}")
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"Error al buscar changed_by: {str(e)}")
        return "unknown"
    finally:
        conn.close()

def get_vpc_name(ec2_client, vpc_id):
    """Obtiene el nombre de un VPC a partir de su ID."""
    try:
        vpc = ec2_client.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        if tag := next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), None):
            return f"{vpc_id} ({tag})"
        return vpc_id
    except ClientError:
        print(f"Failed to get VPC name for {vpc_id}")
        return vpc_id

def get_platform_details(ec2_client, instance_id):
    """Obtiene detalles de la plataforma de una instancia EC2."""
    try:
        instance = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        if platform := instance.get('PlatformDetails'):
            return platform
        if instance.get('Platform') == 'windows':
            return 'Windows'
        if image_id := instance.get('ImageId'):
            try:
                return ec2_client.describe_images(ImageIds=[image_id])['Images'][0].get('Description', 'Linux/UNIX')
            except ClientError:
                print(f"Failed to get image details for {image_id}")
        return 'Linux/UNIX'
    except ClientError as e:
        print(f"Error getting platform details: {str(e)}")
        return 'Unavailable'

def extract_instance_data(instance, ec2_client, account_name, account_id, region):
    """Extrae y formatea los datos de una instancia EC2."""
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "InstanceID": instance["InstanceId"],
        "InstanceName": tags.get("Name", "N/A"),
        "InstanceType": instance["InstanceType"],
        "State": instance["State"]["Name"],
        "Region": region,
        "AvailabilityZone": instance["Placement"]["AvailabilityZone"],
        "VPC": get_vpc_name(ec2_client, instance["VpcId"]) if instance.get("VpcId") else "N/A",
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
    """Obtiene todas las instancias EC2 en una región."""
    if not (ec2_client := create_aws_client("ec2", region, credentials)):
        return []
    try:
        return [
            extract_instance_data(instance, ec2_client, account_name, account_id, region)
            for page in ec2_client.get_paginator('describe_instances').paginate()
            for reservation in page.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
    except ClientError as e:
        print(f"Error getting EC2 instances: {str(e)}")
        return []

def insert_or_update_ec2_data(ec2_data, region, credentials=None):
    """Actualiza la base de datos con información de instancias EC2."""
    if not ec2_data or not (conn := get_db_connection()):
        return {"error": "No data or DB connection failed", "processed": 0}

    fields = [
        "AccountName", "AccountID", "InstanceID", "InstanceName", "InstanceType",
        "State", "Region", "AvailabilityZone", "VPC", "Subnet", "OSImageID",
        "OSDetails", "IAMRole", "SecurityGroups", "KeyName", "PublicIP",
        "PrivateIP", "StorageVolumes"
    ]
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM ec2")
            columns = [desc[0].lower() for desc in cursor.description]
            existing = {row[columns.index("instanceid")]: dict(zip(columns, row)) for row in cursor.fetchall()}

            inserted, updated = 0, 0
            for ec2 in ec2_data:
                instance_id = ec2["InstanceID"]
                values = [ec2[f] for f in fields]
                
                if instance_id not in existing:
                    cursor.execute(
                        f"INSERT INTO ec2 ({','.join(fields)}, last_updated) VALUES ({','.join(['%s']*len(fields))}, CURRENT_TIMESTAMP)",
                        values
                    )
                    inserted += 1
                else:
                    updates = []
                    history = []
                    for col in fields:
                        new_val, old_val = str(ec2[col]), str(existing[instance_id][col.lower()])
                        if new_val != old_val:
                            updates.append(f"{col.lower()} = %s")
                            history.append((
                                instance_id, col.lower(), old_val, new_val,
                                get_instance_changed_by(instance_id, datetime.now())
                            ))
                    
                    if updates:
                        cursor.executemany(
                            "INSERT INTO ec2_changes_history VALUES (%s, %s, %s, %s, %s)",
                            history
                        )
                        cursor.execute(
                            f"UPDATE ec2 SET {','.join(updates)}, last_updated = CURRENT_TIMESTAMP WHERE instanceid = %s",
                            [v for v in values if str(v) != str(existing[instance_id][v.lower()]) + [instance_id]]
                        )
                        updated += 1

            conn.commit()
            return {"processed": len(ec2_data), "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        print(f"DB operation failed: {str(e)}")
        return {"error": str(e), "processed": 0}
    finally:
        conn.close()