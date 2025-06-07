from botocore.exceptions import ClientError
import boto3
import pg8000
import logging
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import DB_USER, DB_PASSWORD, DB_HOST, DB_NAME

# logger = logging.getLogger(__name__)

def create_ec2_client(region, credentials):
    if not credentials or "error" in credentials:
        return None
    try:
        return boto3.client(
            "ec2",
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
    except Exception as e:
        print(f"Error creating EC2 client: {str(e)}")
        return None

def get_subnets_details(region, credentials, account_id, account_name):
    ec2 = create_ec2_client(region, credentials)
    if not ec2:
        return []

    try:
        subnets = ec2.describe_subnets().get('Subnets', [])
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        vpc_names = {vpc['VpcId']: next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), 'N/A') for vpc in vpcs}
        acls = ec2.describe_network_acls().get("NetworkAcls", [])
        igws = ec2.describe_internet_gateways().get("InternetGateways", [])
        vpns = ec2.describe_vpn_connections().get("VpnConnections", [])
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
        route_tables = ec2.describe_route_tables().get("RouteTables", [])

        subnet_info = []

        for subnet in subnets:
            subnet_id = subnet['SubnetId']
            vpc_id = subnet['VpcId']

            # Grupos de seguridad
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])
            sg_ids = list({sg['GroupId'] for eni in enis['NetworkInterfaces'] for sg in eni.get('Groups', [])})

            # ACLs
            acl_ids = [acl['NetworkAclId'] for acl in acls if any(assoc.get('SubnetId') == subnet_id for assoc in acl.get('Associations', []))]

            # Internet Gateways
            igw_ids = [igw['InternetGatewayId'] for igw in igws if any(att['VpcId'] == vpc_id for att in igw.get('Attachments', []))]

            # VPNs
            vpn_ids = [vpn['VpnConnectionId'] for vpn in vpns if vpn.get('VpcId') == vpc_id]

            # VPC Endpoints
            endpoint_ids = [ep['VpcEndpointId'] for ep in endpoints if subnet_id in ep.get('SubnetIds', [])]

            # VPC Peering
            peering_ids = [pc['VpcPeeringConnectionId'] for pc in peerings if pc['RequesterVpcInfo']['VpcId'] == vpc_id or pc['AccepterVpcInfo']['VpcId'] == vpc_id]

            # Route Tables
            route_ids = [rt['RouteTableId'] for rt in route_tables if any(assoc.get('SubnetId') == subnet_id for assoc in rt.get('Associations', []))]

            subnet_info.append({
                "SubnetId": subnet_id,
                "VpcId": vpc_id,
                "VpcName": vpc_names.get(vpc_id, "N/A"),
                "CidrBlock": subnet['CidrBlock'],
                "AvailabilityZone": subnet['AvailabilityZone'],
                "State": subnet['State'],
                "SecurityGroups": ",".join(sg_ids),
                "ACLs": ",".join(acl_ids),
                "InternetGateways": ",".join(igw_ids),
                "VPNConnections": ",".join(vpn_ids),
                "VPCEndpoints": ",".join(endpoint_ids),
                "VPCPeerings": ",".join(peering_ids),
                "RouteTables": ",".join(route_ids),
                "SubnetName": next((tag['Value'] for tag in subnet.get('Tags', []) if tag['Key'] == 'Name'), "N/A"),
                "AccountID": account_id,
                "AccountName": account_name,
                "Region": region
            })

        return subnet_info

    except ClientError as e:
        print(f"Error getting subnet details for account {account_id}: {str(e)}")
        return []

def get_db_connection():
    try:
        return pg8000.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=5432,
            database=DB_NAME
        )
    except Exception as e:
        print(f"Database connection failed: {str(e)}")
        return None

def prepare_subnet_data_for_db(subnet_data):
    return [(
        item["SubnetId"],
        item["VpcId"],
        item["VpcName"],
        item["CidrBlock"],
        item["AvailabilityZone"],
        item["State"],
        item["SecurityGroups"],
        item["ACLs"],
        item["InternetGateways"],
        item["VPNConnections"],
        item["VPCEndpoints"],
        item["VPCPeerings"],
        item["RouteTables"],
        item["SubnetName"],
        item["AccountID"],
        item["AccountName"],
        item["Region"]
    ) for item in subnet_data]

def insert_or_update_subnet_data(subnet_data):
    if not subnet_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    connection = get_db_connection()
    if not connection:
        return {
            "error": "Database connection failed",
            "processed": 0,
            "inserted": 0,
            "updated": 0
        }

    try:
        upsert_query = """
            INSERT INTO subnets (
                subnetid, vpcid, vpcname, cidrblock, availabilityzone, state,
                securitygroups, acls, internetgateways, vpnconnections, vpceendpoints,
                vpcpeerings, routetables, subnetname, accountid, accountname, region, last_updated
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
            )
            ON CONFLICT (subnetid)
            DO UPDATE SET
                vpcid = EXCLUDED.vpcid,
                vpcname = EXCLUDED.vpcname,
                cidrblock = EXCLUDED.cidrblock,
                availabilityzone = EXCLUDED.availabilityzone,
                state = EXCLUDED.state,
                securitygroups = EXCLUDED.securitygroups,
                acls = EXCLUDED.acls,
                internetgateways = EXCLUDED.internetgateways,
                vpnconnections = EXCLUDED.vpnconnections,
                vpceendpoints = EXCLUDED.vpceendpoints,
                vpcpeerings = EXCLUDED.vpcpeerings,
                routetables = EXCLUDED.routetables,
                subnetname = EXCLUDED.subnetname,
                accountid = EXCLUDED.accountid,
                accountname = EXCLUDED.accountname,
                region = EXCLUDED.region,
                last_updated = CURRENT_TIMESTAMP
            RETURNING subnetid, last_updated;
        """

        cursor = connection.cursor()
        prepared_data = prepare_subnet_data_for_db(subnet_data)
        cursor.executemany(upsert_query, prepared_data)
        results = cursor.fetchall()
        connection.commit()

        processed = len(results)
        return {"processed": processed, "inserted": processed, "updated": 0}
    except Exception as e:
        connection.rollback()
        print(f"Database operation failed: {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        connection.close()
