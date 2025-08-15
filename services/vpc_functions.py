from botocore.exceptions import ClientError
from datetime import datetime
import time
from services.utils import create_aws_client, get_db_connection, log_change

FIELD_EVENT_MAP = {
    "vpc_name": ["CreateTags", "DeleteTags"],
    "state": ["CreateVpc", "DeleteVpc"],
    "subnets": ["CreateSubnet", "DeleteSubnet"],
    "security_groups": ["CreateSecurityGroup", "DeleteSecurityGroup"],
    "network_acls": ["CreateNetworkAcl", "DeleteNetworkAcl"],
    "internet_gateways": ["CreateInternetGateway", "AttachInternetGateway", "DetachInternetGateway"],
    "vpn_connections": ["CreateVpnConnection", "DeleteVpnConnection"],
    "vpc_endpoints": ["CreateVpcEndpoint", "DeleteVpcEndpoint"],
    "vpc_peerings": ["CreateVpcPeeringConnection", "DeleteVpcPeeringConnection"],
    "route_rules": ["CreateRouteTable", "DeleteRouteTable"]
}

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
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()



def get_vpc_details(region, credentials, account_id, account_name):
    ec2_client = create_aws_client("ec2", region, credentials)
    if not ec2_client:
        return []

    try:
        vpcs = ec2_client.describe_vpcs().get('Vpcs', [])
        vpcs_info = []

        for vpc in vpcs:
            subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
            subnet_ids = [subnet['SubnetId'] for subnet in subnets.get('Subnets', [])]
            
            security_groups = ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
            sg_ids = [sg['GroupId'] for sg in security_groups.get('SecurityGroups', [])]
            
            network_acls = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
            acl_ids = [acl['NetworkAclId'] for acl in network_acls.get('NetworkAcls', [])]
            
            igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc['VpcId']]}])
            igw_ids = [igw['InternetGatewayId'] for igw in igws.get('InternetGateways', [])]
            
            vpn_connections = ec2_client.describe_vpn_connections(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
            vpn_ids = [vpn['VpnConnectionId'] for vpn in vpn_connections.get('VpnConnections', [])]
            
            vpc_endpoints = ec2_client.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
            endpoint_ids = [endpoint['VpcEndpointId'] for endpoint in vpc_endpoints.get('VpcEndpoints', [])]
            
            vpc_peerings = ec2_client.describe_vpc_peering_connections(Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [vpc['VpcId']]}])
            peering_ids = [peering['VpcPeeringConnectionId'] for peering in vpc_peerings.get('VpcPeeringConnections', [])]
            
            route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
            route_table_ids = [rt['RouteTableId'] for rt in route_tables.get('RouteTables', [])]
            
            azs = list(set(subnet['AvailabilityZone'] for subnet in subnets.get('Subnets', [])))
            
            vpcs_info.append({
                "AccountName": account_name,
                "AccountID": account_id,
                "VpcId": vpc['VpcId'],
                "VpcName": next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), "N/A"),
                "CidrBlock": vpc['CidrBlock'],
                "State": vpc['State'],
                "Region": region,
                "Subnets": subnet_ids,
                "SecurityGroups": sg_ids,
                "NetworkAcls": acl_ids,
                "InternetGateways": igw_ids,
                "VpnConnections": vpn_ids,
                "VpcEndpoints": endpoint_ids,
                "VpcPeerings": peering_ids,
                "Tags": vpc.get('Tags', []),
                "AvailabilityZones": azs,
                "RouteRules": route_table_ids
            })
        
        return vpcs_info
    
    except ClientError as e:
        return []

def insert_or_update_vpc_data(vpc_data):
    if not vpc_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {
            "error": "Database connection failed",
            "processed": 0,
            "inserted": 0,
            "updated": 0
        }

    query_insert = """
        INSERT INTO vpcs (
            vpc_id, vpc_name, cidr_block, state,
            region, subnets, security_groups, network_acls, internet_gateways,
            vpn_connections, vpc_endpoints, vpc_peerings, tags, 
            availability_zones, route_rules, account_name, account_id, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO vpc_changes_history (vpc_id, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Verificar si la tabla de historial existe, si no, crearla
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'vpc_changes_history'
            )
        """)
        if not cursor.fetchone()[0]:
            cursor.execute("""
                CREATE TABLE vpc_changes_history (
                    id SERIAL PRIMARY KEY,
                    vpc_id VARCHAR(255) NOT NULL,
                    field_name VARCHAR(255) NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    changed_by VARCHAR(255),
                    change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM vpcs")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {(row[columns.index("vpc_id")], row[columns.index("account_id")]): dict(zip(columns, row)) for row in cursor.fetchall()}

        for vpc in vpc_data:
            vpc_id = vpc["VpcId"]
            processed += 1

            insert_values = (
                vpc["VpcId"], vpc["VpcName"], vpc["CidrBlock"], vpc["State"],
                vpc["Region"], vpc["Subnets"], vpc["SecurityGroups"], vpc["NetworkAcls"],
                vpc["InternetGateways"], vpc["VpnConnections"], vpc["VpcEndpoints"],
                vpc["VpcPeerings"], vpc["Tags"], vpc["AvailabilityZones"],
                vpc["RouteRules"], vpc["AccountName"], vpc["AccountID"]
            )

            if (vpc_id, vpc["AccountID"]) not in existing_data:
                cursor.execute(query_insert.replace('CURRENT_TIMESTAMP', 'NOW()'), insert_values)
                inserted += 1
            else:
                db_row = existing_data[(vpc_id, vpc["AccountID"])]
                updates = []
                values = []

                campos = {
                    "vpc_id": vpc["VpcId"],
                    "vpc_name": vpc["VpcName"],
                    "cidr_block": vpc["CidrBlock"],
                    "state": vpc["State"],
                    "region": vpc["Region"],
                    "subnets": vpc["Subnets"],
                    "security_groups": vpc["SecurityGroups"],
                    "network_acls": vpc["NetworkAcls"],
                    "internet_gateways": vpc["InternetGateways"],
                    "vpn_connections": vpc["VpnConnections"],
                    "vpc_endpoints": vpc["VpcEndpoints"],
                    "vpc_peerings": vpc["VpcPeerings"],
                    "tags": vpc["Tags"],
                    "availability_zones": vpc["AvailabilityZones"],
                    "route_rules": vpc["RouteRules"],
                    "account_name": vpc["AccountName"],
                    "account_id": vpc["AccountID"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    # Normalizar listas para VPC
                    if col in ['subnets', 'security_groups', 'network_acls', 'internet_gateways', 'vpc_endpoints', 'vpc_peerings', 'route_rules'] and isinstance(new_val, list):
                        old_normalized = sorted([str(x) for x in (old_val if isinstance(old_val, list) else [])])
                        new_normalized = sorted([str(x) for x in new_val])
                        if old_normalized != new_normalized:
                            updates.append(f"{col} = %s")
                            values.append(new_val)
                            changed_by = get_vpc_changed_by(vpc_id, datetime.now())
                            log_change('VPC', vpc_id, col, old_val, new_val, changed_by, vpc["AccountID"], vpc["Region"])
                    elif str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_vpc_changed_by(vpc_id, datetime.now())
                        log_change('VPC', vpc_id, col, old_val, new_val, changed_by, vpc["AccountID"], vpc["Region"])

                updates.append("last_updated = NOW()")

                if updates:
                    update_query = f"UPDATE vpcs SET {', '.join(updates)} WHERE vpc_id = %s"
                    values.append(vpc_id)
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
        pass
        return {
            "error": str(e),
            "processed": processed,
            "inserted": inserted,
            "updated": updated
        }
    finally:
        conn.close()