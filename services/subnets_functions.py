from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection

FIELD_EVENT_MAP = {
    "vpcname": ["CreateTags", "DeleteTags"],
    "state": ["CreateSubnet", "DeleteSubnet"],
    "securitygroups": ["ModifyNetworkInterfaceAttribute", "AuthorizeSecurityGroupIngress"],
    "acls": ["CreateNetworkAcl", "DeleteNetworkAcl", "ReplaceNetworkAclAssociation"],
    "internetgateways": ["CreateInternetGateway", "AttachInternetGateway", "DetachInternetGateway"],
    "vpnconnections": ["CreateVpnConnection", "DeleteVpnConnection"],
    "vpceendpoints": ["CreateVpcEndpoint", "DeleteVpcEndpoint"],
    "vpcpeerings": ["CreateVpcPeeringConnection", "DeleteVpcPeeringConnection"],
    "routetables": ["CreateRouteTable", "AssociateRouteTable", "DisassociateRouteTable"],
    "subnetname": ["CreateTags", "DeleteTags"]
}

def get_subnet_changed_by(subnet_id, field_name):
    """Busca el usuario que cambió un campo específico"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            possible_events = FIELD_EVENT_MAP.get(field_name, [])
            
            if possible_events:
                placeholders = ','.join(['%s'] * len(possible_events))
                query = f"""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = 'EC2'
                    AND event_name IN ({placeholders})
                    ORDER BY event_time DESC LIMIT 1
                """
                cursor.execute(query, (subnet_id, *possible_events))
            else:
                cursor.execute("""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = 'EC2'
                    ORDER BY event_time DESC LIMIT 1
                """, (subnet_id,))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def get_subnets_details(region, credentials, account_id, account_name):
    ec2 = create_aws_client("ec2", region, credentials)
    if not ec2:
        return []

    try:
        # Obtener datos básicos
        subnets = ec2.describe_subnets().get('Subnets', [])
        vpcs = {vpc['VpcId']: next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), 'N/A') 
                for vpc in ec2.describe_vpcs().get("Vpcs", [])}
        
        # Obtener recursos relacionados
        acls = ec2.describe_network_acls().get("NetworkAcls", [])
        igws = ec2.describe_internet_gateways().get("InternetGateways", [])
        vpns = ec2.describe_vpn_connections().get("VpnConnections", [])
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
        route_tables = ec2.describe_route_tables().get("RouteTables", [])

        # Mapear recursos por VPC/subnet para acceso rápido
        vpc_igws = {att['VpcId']: igw['InternetGatewayId'] 
                   for igw in igws for att in igw.get('Attachments', [])}
        vpc_vpns = {vpn.get('VpcId'): vpn['VpnConnectionId'] for vpn in vpns if vpn.get('VpcId')}
        subnet_acls = {}
        for acl in acls:
            for assoc in acl.get('Associations', []):
                if subnet_id := assoc.get('SubnetId'):
                    subnet_acls[subnet_id] = acl['NetworkAclId']
        
        subnet_routes = {}
        for rt in route_tables:
            for assoc in rt.get('Associations', []):
                if subnet_id := assoc.get('SubnetId'):
                    subnet_routes[subnet_id] = rt['RouteTableId']

        subnet_info = []
        for subnet in subnets:
            subnet_id = subnet['SubnetId']
            vpc_id = subnet['VpcId']

            # Obtener grupos de seguridad
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])
            sg_ids = list({sg['GroupId'] for eni in enis['NetworkInterfaces'] for sg in eni.get('Groups', [])})

            # Obtener endpoints
            subnet_endpoints = [ep['VpcEndpointId'] for ep in endpoints if subnet_id in ep.get('SubnetIds', [])]

            # Obtener peerings
            vpc_peerings = [pc['VpcPeeringConnectionId'] for pc in peerings 
                           if pc['RequesterVpcInfo']['VpcId'] == vpc_id or pc['AccepterVpcInfo']['VpcId'] == vpc_id]

            subnet_info.append({
                "SubnetId": subnet_id,
                "VpcId": vpc_id,
                "VpcName": vpcs.get(vpc_id, "N/A"),
                "CidrBlock": subnet['CidrBlock'],
                "AvailabilityZone": subnet['AvailabilityZone'],
                "State": subnet['State'],
                "SecurityGroups": ",".join(sg_ids),
                "ACLs": subnet_acls.get(subnet_id, ""),
                "InternetGateways": vpc_igws.get(vpc_id, ""),
                "VPNConnections": vpc_vpns.get(vpc_id, ""),
                "VPCEndpoints": ",".join(subnet_endpoints),
                "VPCPeerings": ",".join(vpc_peerings),
                "RouteTables": subnet_routes.get(subnet_id, ""),
                "SubnetName": next((tag['Value'] for tag in subnet.get('Tags', []) if tag['Key'] == 'Name'), "N/A"),
                "AccountID": account_id,
                "AccountName": account_name,
                "Region": region
            })

        return subnet_info

    except ClientError as e:
        return []

def insert_or_update_subnet_data(subnet_data):
    if not subnet_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO subnets (
            subnetid, vpcid, vpcname, cidrblock, availabilityzone, state,
            securitygroups, acls, internetgateways, vpnconnections, vpceendpoints,
            vpcpeerings, routetables, subnetname, accountid, accountname, region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    query_change_history = """
        INSERT INTO subnet_changes_history (subnet_id, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM subnets")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("subnetid")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for subnet in subnet_data:
            subnet_id = subnet["SubnetId"]
            processed += 1

            insert_values = (
                subnet["SubnetId"], subnet["VpcId"], subnet["VpcName"], subnet["CidrBlock"],
                subnet["AvailabilityZone"], subnet["State"], subnet["SecurityGroups"],
                subnet["ACLs"], subnet["InternetGateways"], subnet["VPNConnections"],
                subnet["VPCEndpoints"], subnet["VPCPeerings"], subnet["RouteTables"],
                subnet["SubnetName"], subnet["AccountID"], subnet["AccountName"], subnet["Region"]
            )

            if subnet_id not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[subnet_id]
                updates = []
                values = []

                campos = {
                    "subnetid": subnet["SubnetId"],
                    "vpcid": subnet["VpcId"],
                    "vpcname": subnet["VpcName"],
                    "cidrblock": subnet["CidrBlock"],
                    "availabilityzone": subnet["AvailabilityZone"],
                    "state": subnet["State"],
                    "securitygroups": subnet["SecurityGroups"],
                    "acls": subnet["ACLs"],
                    "internetgateways": subnet["InternetGateways"],
                    "vpnconnections": subnet["VPNConnections"],
                    "vpceendpoints": subnet["VPCEndpoints"],
                    "vpcpeerings": subnet["VPCPeerings"],
                    "routetables": subnet["RouteTables"],
                    "subnetname": subnet["SubnetName"],
                    "accountid": subnet["AccountID"],
                    "accountname": subnet["AccountName"],
                    "region": subnet["Region"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_subnet_changed_by(
                            subnet_id=subnet_id,
                            field_name=col
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (subnet_id, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE subnets SET {', '.join(updates)} WHERE subnetid = %s"
                    values.append(subnet_id)
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
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()