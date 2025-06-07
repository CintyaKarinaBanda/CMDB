import boto3
from botocore.exceptions import ClientError
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

def get_vpc_details(region, credentials, account_id, account_name):
    ec2_client = create_ec2_client(region, credentials)
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
        print(f"Error getting VPCs for account {account_id}: {str(e)}")
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

def prepare_vpc_data_for_db(vpc_data):
    return [(
        item["VpcId"],
        item.get("VpcName"),
        item.get("CidrBlock"),
        item.get("State"),
        item.get("Region"),
        item.get("Subnets", []),
        item.get("SecurityGroups", []),
        item.get("NetworkAcls", []),
        item.get("InternetGateways", []),
        item.get("VpnConnections", []),
        item.get("VpcEndpoints", []),
        item.get("VpcPeerings", []),
        item.get("Tags", {}),  # sigue en JSON
        item.get("AvailabilityZones", []),
        item.get("RouteRules", 0),
        item.get("AccountName"),
        item.get("AccountID")
    ) for item in vpc_data]

def insert_or_update_vpc_data(vpc_data):
    if not vpc_data:
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
            ON CONFLICT (vpc_id)
            DO UPDATE SET
                vpc_name = EXCLUDED.vpc_name,
                cidr_block = EXCLUDED.cidr_block,
                state = EXCLUDED.state,
                region = EXCLUDED.region,
                subnets = EXCLUDED.subnets,
                security_groups = EXCLUDED.security_groups,
                network_acls = EXCLUDED.network_acls,
                internet_gateways = EXCLUDED.internet_gateways,
                vpn_connections = EXCLUDED.vpn_connections,
                vpc_endpoints = EXCLUDED.vpc_endpoints,
                vpc_peerings = EXCLUDED.vpc_peerings,
                tags = EXCLUDED.tags,
                availability_zones = EXCLUDED.availability_zones,
                route_rules = EXCLUDED.route_rules,
                account_name = EXCLUDED.account_name,
                account_id = EXCLUDED.account_id,
                last_updated = CURRENT_TIMESTAMP
            RETURNING vpc_id, last_updated;
        """

        cursor = connection.cursor()
        prepared_data = prepare_vpc_data_for_db(vpc_data)
        cursor.executemany(upsert_query, prepared_data)
        results = cursor.fetchall()
        connection.commit()

        processed = len(results)
        return {
            "processed": processed,
            "inserted": processed,
            "updated": 0
        }
    except Exception as e:
        connection.rollback()
        print(f"Database operation failed: {str(e)}")
        return {
            "error": str(e),
            "processed": 0,
            "inserted": 0,
            "updated": 0
        }
    finally:
        connection.close()