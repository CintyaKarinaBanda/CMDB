from botocore.exceptions import ClientError
from datetime import datetime
from Servicios.utils import create_aws_client, get_db_connection, log

def get_vpc_changed_by(vpc_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'VPC' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (vpc_id, update_date, update_date))
            
            return cursor.fetchone()[0] if cursor.fetchone() else "unknown"
    except Exception as e:
        log(f"ERROR: Buscar changed_by para VPC {vpc_id}: {str(e)}")
        return "unknown"
    finally:
        conn.close()

def get_vpc_resources(ec2_client, vpc_id):
    """Obtiene recursos asociados a una VPC"""
    vpc_filter = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
    
    # Obtener todos los recursos en una sola función
    resources = {
        "subnets": [s['SubnetId'] for s in ec2_client.describe_subnets(Filters=vpc_filter).get('Subnets', [])],
        "security_groups": [sg['GroupId'] for sg in ec2_client.describe_security_groups(Filters=vpc_filter).get('SecurityGroups', [])],
        "network_acls": [acl['NetworkAclId'] for acl in ec2_client.describe_network_acls(Filters=vpc_filter).get('NetworkAcls', [])],
        "internet_gateways": [igw['InternetGatewayId'] for igw in ec2_client.describe_internet_gateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]).get('InternetGateways', [])],
        "vpn_connections": [vpn['VpnConnectionId'] for vpn in ec2_client.describe_vpn_connections(Filters=vpc_filter).get('VpnConnections', [])],
        "vpc_endpoints": [ep['VpcEndpointId'] for ep in ec2_client.describe_vpc_endpoints(Filters=vpc_filter).get('VpcEndpoints', [])],
        "vpc_peerings": [pc['VpcPeeringConnectionId'] for pc in ec2_client.describe_vpc_peering_connections(
            Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [vpc_id]}]).get('VpcPeeringConnections', [])],
        "route_tables": [rt['RouteTableId'] for rt in ec2_client.describe_route_tables(Filters=vpc_filter).get('RouteTables', [])]
    }
    
    # Obtener zonas de disponibilidad
    resources["availability_zones"] = list(set(subnet['AvailabilityZone'] 
                                           for subnet in ec2_client.describe_subnets(Filters=vpc_filter).get('Subnets', [])))
    
    return resources

def get_vpc_details(region, credentials, account_id, account_name):
    ec2_client = create_aws_client("ec2", region, credentials)
    if not ec2_client:
        return []

    try:
        vpcs = ec2_client.describe_vpcs().get('Vpcs', [])
        vpcs_info = []

        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            resources = get_vpc_resources(ec2_client, vpc_id)
            
            vpcs_info.append({
                "AccountName": account_name,
                "AccountID": account_id,
                "VpcId": vpc_id,
                "VpcName": next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), "N/A"),
                "CidrBlock": vpc['CidrBlock'],
                "State": vpc['State'],
                "Region": region,
                "Subnets": resources["subnets"],
                "SecurityGroups": resources["security_groups"],
                "NetworkAcls": resources["network_acls"],
                "InternetGateways": resources["internet_gateways"],
                "VpnConnections": resources["vpn_connections"],
                "VpcEndpoints": resources["vpc_endpoints"],
                "VpcPeerings": resources["vpc_peerings"],
                "Tags": vpc.get('Tags', []),
                "AvailabilityZones": resources["availability_zones"],
                "RouteRules": resources["route_tables"]
            })
        
        if vpcs_info:
            log(f"INFO: VPC en {region}: {len(vpcs_info)} VPCs encontradas")
        return vpcs_info
    
    except ClientError as e:
        log(f"ERROR: Obtener VPCs en {region} para cuenta {account_id}: {str(e)}")
        return []

def insert_or_update_vpc_data(vpc_data):
    if not vpc_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "Database connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO vpcs (
            vpc_id, vpc_name, cidr_block, state, region, subnets, security_groups, 
            network_acls, internet_gateways, vpn_connections, vpc_endpoints, vpc_peerings, 
            tags, availability_zones, route_rules, account_name, account_id, last_updated
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
    """

    query_change_history = """
        INSERT INTO vpc_changes_history (vpc_id, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted, updated, processed = 0, 0, 0

    try:
        cursor = conn.cursor()

        # Verificar y crear tabla de historial si es necesario
        cursor.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'vpc_changes_history')")
        if not cursor.fetchone()[0]:
            cursor.execute("""
                CREATE TABLE vpc_changes_history (
                    id SERIAL PRIMARY KEY, vpc_id VARCHAR(255) NOT NULL, field_name VARCHAR(255) NOT NULL,
                    old_value TEXT, new_value TEXT, changed_by VARCHAR(255),
                    change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            log("INFO: Tabla vpc_changes_history creada")

        # Obtener datos existentes
        cursor.execute("SELECT * FROM vpcs")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("vpc_id")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for vpc in vpc_data:
            vpc_id = vpc["VpcId"]
            processed += 1

            # Preparar valores para inserción/actualización
            vpc_values = (
                vpc["VpcId"], vpc["VpcName"], vpc["CidrBlock"], vpc["State"], vpc["Region"], 
                vpc["Subnets"], vpc["SecurityGroups"], vpc["NetworkAcls"], vpc["InternetGateways"], 
                vpc["VpnConnections"], vpc["VpcEndpoints"], vpc["VpcPeerings"], vpc["Tags"], 
                vpc["AvailabilityZones"], vpc["RouteRules"], vpc["AccountName"], vpc["AccountID"]
            )

            if vpc_id not in existing_data:
                cursor.execute(query_insert, vpc_values)
                inserted += 1
            else:
                # Actualizar solo campos modificados
                db_row = existing_data[vpc_id]
                campos = {
                    "vpc_id": vpc["VpcId"], "vpc_name": vpc["VpcName"], "cidr_block": vpc["CidrBlock"],
                    "state": vpc["State"], "region": vpc["Region"], "subnets": vpc["Subnets"],
                    "security_groups": vpc["SecurityGroups"], "network_acls": vpc["NetworkAcls"],
                    "internet_gateways": vpc["InternetGateways"], "vpn_connections": vpc["VpnConnections"],
                    "vpc_endpoints": vpc["VpcEndpoints"], "vpc_peerings": vpc["VpcPeerings"],
                    "tags": vpc["Tags"], "availability_zones": vpc["AvailabilityZones"],
                    "route_rules": vpc["RouteRules"], "account_name": vpc["AccountName"],
                    "account_id": vpc["AccountID"]
                }

                updates, values = [], []
                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_vpc_changed_by(vpc_id=vpc_id, update_date=datetime.now())
                        cursor.execute(query_change_history, (vpc_id, col, str(old_val), str(new_val), changed_by))

                if updates:
                    updates.append("last_updated = CURRENT_TIMESTAMP")
                    update_query = f"UPDATE vpcs SET {', '.join(updates)} WHERE vpc_id = %s"
                    values.append(vpc_id)
                    cursor.execute(update_query, tuple(values))
                    updated += 1

        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}

    except Exception as e:
        conn.rollback()
        log(f"ERROR: Operación BD para VPC: {str(e)}")
        return {"error": str(e), "processed": processed, "inserted": inserted, "updated": updated}
    finally:
        conn.close()