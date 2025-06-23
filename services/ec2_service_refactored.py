from botocore.exceptions import ClientError
from .shared.base_service import BaseService
from .utils import create_aws_client

class EC2Service(BaseService):
    """Servicio EC2 refactorizado usando BaseService"""
    
    def __init__(self):
        super().__init__("EC2", "EC2")
    
    def get_vpc_name(self, ec2_client, vpc_id):
        try:
            vpc = ec2_client.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
            tag = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), None)
            return f"{vpc_id} ({tag})" if tag else vpc_id
        except ClientError:
            self.logger.log_client_error("VPC", vpc_id, "Failed to get VPC name")
            return vpc_id

    def get_platform_details(self, ec2_client, instance_id):
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
                    self.logger.log_client_error("ImageID", image_id, "Failed to get image details")
            return 'Linux/UNIX'
        except ClientError:
            self.logger.log_client_error("Platform", instance_id, "Failed to get platform details")
            return 'Unavailable'

    def extract_instance_data(self, instance, ec2_client, account_name, account_id, region):
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
            "VPC": self.get_vpc_name(ec2_client, instance.get("VpcId", "")) if instance.get("VpcId") else "N/A",
            "Subnet": instance.get("SubnetId", "N/A"),
            "OSImageID": instance.get("ImageId", "N/A"),
            "OSDetails": self.get_platform_details(ec2_client, instance["InstanceId"]),
            "IAMRole": instance.get("IamInstanceProfile", {}).get("Arn", "N/A").split("/")[-1],
            "SecurityGroups": [sg["GroupName"] for sg in instance.get("SecurityGroups", [])],
            "KeyName": instance.get("KeyName", "N/A"),
            "PublicIP": instance.get("PublicIpAddress", "N/A"),
            "PrivateIP": instance.get("PrivateIpAddress", "N/A"),
            "StorageVolumes": [bdm["Ebs"]["VolumeId"] for bdm in instance.get("BlockDeviceMappings", []) if "Ebs" in bdm]
        }

    def get_instances(self, region, credentials, account_id, account_name):
        ec2_client = create_aws_client("ec2", region, credentials)
        if not ec2_client:
            return []
        try:
            paginator = ec2_client.get_paginator('describe_instances')
            instances_info = []
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        info = self.extract_instance_data(instance, ec2_client, account_name, account_id, region)
                        instances_info.append(info)
            
            if instances_info:
                self.log_info(region, len(instances_info))
            return instances_info
        except ClientError as e:
            self.log_error(region, account_id, e)
            return []

    def insert_or_update_instances(self, ec2_data):
        config = {
            'table_name': 'ec2',
            'history_table': 'ec2_changes_history',
            'id_field': 'instance_id',
            'resource_id_key': 'InstanceID',
            'insert_query': """
                INSERT INTO ec2 (
                    AccountName, AccountID, InstanceID, InstanceName, InstanceType,
                    State, Region, AvailabilityZone, VPC, Subnet, OSImageID,
                    OSDetails, IAMRole, SecurityGroups, KeyName, PublicIP,
                    PrivateIP, StorageVolumes, last_updated
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
                )
            """,
            'get_insert_values': lambda item: (
                item["AccountName"], item["AccountID"], item["InstanceID"], item["InstanceName"],
                item["InstanceType"], item["State"], item["Region"], item["AvailabilityZone"],
                item["VPC"], item["Subnet"], item["OSImageID"], item["OSDetails"],
                item["IAMRole"], item["SecurityGroups"], item["KeyName"],
                item["PublicIP"], item["PrivateIP"], item["StorageVolumes"]
            ),
            'get_field_mapping': lambda item: {
                "accountname": item["AccountName"],
                "accountid": item["AccountID"],
                "instanceid": item["InstanceID"],
                "instancename": item["InstanceName"],
                "instancetype": item["InstanceType"],
                "state": item["State"],
                "region": item["Region"],
                "availabilityzone": item["AvailabilityZone"],
                "vpc": item["VPC"],
                "subnet": item["Subnet"],
                "osimageid": item["OSImageID"],
                "osdetails": item["OSDetails"],
                "iamrole": item["IAMRole"],
                "securitygroups": item["SecurityGroups"],
                "keyname": item["KeyName"],
                "publicip": item["PublicIP"],
                "privateip": item["PrivateIP"],
                "storagevolumes": item["StorageVolumes"]
            }
        }
        
        return self.insert_or_update_data(ec2_data, config)