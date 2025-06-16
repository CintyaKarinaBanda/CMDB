from botocore.exceptions import ClientError
from services.utils import create_aws_client, get_db_connection

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

        if subnet_info:
            print(f"INFO: Subnets en {region}: {len(subnet_info)} subredes encontradas")
        return subnet_info

    except ClientError as e:
        print(f"ERROR: Obtener subnets en {region} para cuenta {account_id}: {str(e)}")
        return []

def insert_or_update_subnet_data(subnet_data):
    if not subnet_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "Database connection failed", "processed": 0, "inserted": 0, "updated": 0}

    try:
        # Usar una sola consulta para insertar/actualizar
        upsert_query = """
            INSERT INTO subnets (
                subnetid, vpcid, vpcname, cidrblock, availabilityzone, state,
                securitygroups, acls, internetgateways, vpnconnections, vpceendpoints,
                vpcpeerings, routetables, subnetname, accountid, accountname, region, last_updated
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (subnetid) DO UPDATE SET
                vpcid = EXCLUDED.vpcid, vpcname = EXCLUDED.vpcname, cidrblock = EXCLUDED.cidrblock,
                availabilityzone = EXCLUDED.availabilityzone, state = EXCLUDED.state,
                securitygroups = EXCLUDED.securitygroups, acls = EXCLUDED.acls,
                internetgateways = EXCLUDED.internetgateways, vpnconnections = EXCLUDED.vpnconnections,
                vpceendpoints = EXCLUDED.vpceendpoints, vpcpeerings = EXCLUDED.vpcpeerings,
                routetables = EXCLUDED.routetables, subnetname = EXCLUDED.subnetname,
                accountid = EXCLUDED.accountid, accountname = EXCLUDED.accountname,
                region = EXCLUDED.region, last_updated = CURRENT_TIMESTAMP
            RETURNING subnetid;
        """

        cursor = conn.cursor()
        
        # Preparar datos para inserción
        prepared_data = [(
            item["SubnetId"], item["VpcId"], item["VpcName"], item["CidrBlock"],
            item["AvailabilityZone"], item["State"], item["SecurityGroups"],
            item["ACLs"], item["InternetGateways"], item["VPNConnections"],
            item["VPCEndpoints"], item["VPCPeerings"], item["RouteTables"],
            item["SubnetName"], item["AccountID"], item["AccountName"], item["Region"]
        ) for item in subnet_data]
        
        cursor.executemany(upsert_query, prepared_data)
        results = cursor.fetchall()
        conn.commit()

        processed = len(results)
        return {"processed": processed, "inserted": processed, "updated": 0}
    except Exception as e:
        conn.rollback()
        print(f"ERROR: Operación BD para subnets: {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()