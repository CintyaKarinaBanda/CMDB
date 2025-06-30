# cloudtrail_simple.py
import json
from datetime import datetime, timedelta
import time
from services.utils import create_aws_client

def convert_to_local_time(utc_time):
    if isinstance(utc_time, str):
        utc_time = datetime.fromisoformat(utc_time.replace('Z', '+00:00'))
    # Convert UTC to local timestamp
    utc_timestamp = utc_time.timestamp()
    return datetime.fromtimestamp(utc_timestamp)

IMPORTANT_EVENTS = {
    "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances", "ModifyInstanceAttribute", "CreateTags", "DeleteTags", "RunInstances", "AttachVolume", "DetachVolume", "CreateVolume", "DeleteVolume", "ModifyVolume",
    "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance", "RebootDBInstance", "StartDBInstance", "StopDBInstance", "CreateDBSnapshot", "DeleteDBSnapshot", "RestoreDBInstanceFromDBSnapshot", "AddTagsToResource", "RemoveTagsFromResource",
    "CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "CreateSubnet", "DeleteSubnet", "ModifySubnetAttribute", "CreateRouteTable", "DeleteRouteTable", "CreateInternetGateway", "DeleteInternetGateway", "AttachInternetGateway", "DetachInternetGateway",
    "CreateNatGateway", "DeleteNatGateway", "CreateCluster", "DeleteCluster", "ModifyCluster", "RebootCluster", "ResizeCluster", "PauseCluster", "ResumeCluster", "RestoreFromClusterSnapshot", "CreateClusterSnapshot", "DeleteClusterSnapshot",
    "CreateBucket", "DeleteBucket", "PutBucketTagging", "PutBucketEncryption", "PutBucketVersioning", "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketNotification", "PutPublicAccessBlock", "PutBucketReplication", "DeleteBucketReplication", "PutBucketAcl",
    "UpdateClusterConfig", "UpdateClusterVersion", "CreateAddon", "DeleteAddon", "UpdateAddon", "TagResource", "UntagResource",
    "CreateRepository", "DeleteRepository", "PutImage", "BatchDeleteImage", "PutRepositoryPolicy", "DeleteRepositoryPolicy",
    "CreateKey", "ScheduleKeyDeletion", "CancelKeyDeletion", "EnableKey", "DisableKey", "UpdateKeyDescription", "PutKeyPolicy", "CreateAlias", "DeleteAlias", "UpdateAlias",
    "CreateFunction", "DeleteFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "CreateEventSourceMapping", "DeleteEventSourceMapping", "UpdateEventSourceMapping", "PutFunctionConcurrency", "DeleteFunctionConcurrency"
}

EVENT_SOURCES = ["ec2.amazonaws.com", "rds.amazonaws.com", "redshift.amazonaws.com", "s3.amazonaws.com", "eks.amazonaws.com", "ecr.amazonaws.com", "kms.amazonaws.com", "lambda.amazonaws.com"]
SERVICE_FIELDS = {
    "ec2.amazonaws.com": ["instanceId", "volumeId", "vpcId", "subnetId", "groupId"],
    "rds.amazonaws.com": ["dBInstanceIdentifier", "dBClusterIdentifier"],
    "redshift.amazonaws.com": ["clusterIdentifier"],
    "s3.amazonaws.com": ["bucketName", "bucket"],
    "eks.amazonaws.com": ["name", "clusterName"],
    "ecr.amazonaws.com": ["repositoryName"],
    "kms.amazonaws.com": ["keyId"],
    "lambda.amazonaws.com": ["functionName"]
}
RESPONSE_FIELDS = ["instanceId", "dBInstanceIdentifier", "clusterIdentifier", "vpcId", "subnetId", "bucketName", "name", "keyId", "functionName"]
RESOURCE_TYPES = {"ec2.amazonaws.com": "EC2", "rds.amazonaws.com": "RDS", "redshift.amazonaws.com": "Redshift", "s3.amazonaws.com": "S3", "eks.amazonaws.com": "EKS", "ecr.amazonaws.com": "ECR", "kms.amazonaws.com": "KMS", "lambda.amazonaws.com": "LAMBDA"}

def extract_resource_name(event_detail):
    req = event_detail.get("requestParameters", {})
    resp = event_detail.get("responseElements", {})
    event_source = event_detail.get("eventSource", "")
    
    # Check resource sets first
    for set_name in ["resourcesSet", "instancesSet"]:
        if set_name in req:
            items = req[set_name].get("items", [])
            if items:
                return items[0].get("resourceId" if set_name == "resourcesSet" else "instanceId", "unknown")
    
    # Check service-specific fields
    for field in SERVICE_FIELDS.get(event_source, []):
        if field in req and req[field]:
            return req[field]
    
    # Check response elements
    for field in RESPONSE_FIELDS:
        if field in resp and resp[field]:
            return resp[field]
    
    # Generic search
    for key, value in {**req, **resp}.items():
        if isinstance(value, str) and value and (key.lower().endswith('id') or 'identifier' in key.lower() or key.lower().endswith('name')):
            if key not in ['requestId', 'eventId', 'eventName', 'userName', 'principalId']:
                return value
    
    return "unknown"

def is_valid_resource(resource_name, event_source):
    return resource_name and resource_name != "unknown" and (resource_name.startswith(("i-", "vpc-", "subnet-", "vol-", "snap-", "igw-", "nat-", "rtb-")) or event_source in ["rds.amazonaws.com", "redshift.amazonaws.com", "s3.amazonaws.com", "eks.amazonaws.com", "ecr.amazonaws.com", "kms.amazonaws.com", "lambda.amazonaws.com"])

def extract_changes(event_detail):
    req = event_detail.get("requestParameters", {})
    event_name = event_detail.get("eventName", "")
    event_source = event_detail.get("eventSource", "")
    changes = {}
    
    # Common patterns
    if event_name in ["CreateTags", "DeleteTags"] and "tagSet" in req:
        tags = [f"{tag.get('key', '')}={tag.get('value', '')}" for tag in req["tagSet"].get("items", [])]
        if tags: changes["tags"] = ", ".join(tags)
    elif event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"] and "instancesSet" in req:
        instances = [item["instanceId"] for item in req["instancesSet"].get("items", []) if "instanceId" in item]
        if instances: changes.update({"instances": ", ".join(instances), "action": event_name.replace("Instances", "").lower()})
    elif event_name == "RunInstances":
        for field in ["instanceType", "imageId", "subnetId", "minCount"]: 
            if req.get(field): changes[field.replace("minCount", "instance_count")] = req[field]
    elif event_name == "CreateDBInstance":
        for field in ["dBInstanceClass", "engine", "engineVersion", "allocatedStorage"]: 
            if req.get(field): changes[field.lower().replace("dbinstance", "db_instance")] = req[field]
    elif event_name in ["CreateCluster", "DeleteCluster"] and event_source == "eks.amazonaws.com":
        changes["cluster_name"] = req.get("name")
        if event_name == "CreateCluster": changes.update({"kubernetes_version": req.get("version"), "role_arn": req.get("roleArn")})
        else: changes["action"] = "delete"
    elif event_name in ["CreateRepository", "DeleteRepository", "PutImage"]:
        changes["repository_name"] = req.get("repositoryName")
        changes["action"] = {"CreateRepository": "create", "DeleteRepository": "delete", "PutImage": "push"}.get(event_name, "")
        if event_name == "PutImage": changes["image_tag"] = req.get("imageTag")
    elif event_name in ["CreateKey", "ScheduleKeyDeletion", "EnableKey", "DisableKey"]:
        changes["key_id"] = req.get("keyId")
        changes["action"] = {"CreateKey": "create", "ScheduleKeyDeletion": "schedule_delete", "EnableKey": "enable", "DisableKey": "disable"}.get(event_name, "")
    elif event_name == "UpdateKeyDescription":
        changes["key_id"] = req.get("keyId")
        changes["description"] = req.get("description")
    elif event_name in ["CreateFunction", "DeleteFunction"]:
        changes["function_name"] = req.get("functionName")
        changes["action"] = {"CreateFunction": "create", "DeleteFunction": "delete"}.get(event_name, "")
        if event_name == "CreateFunction": changes.update({"runtime": req.get("runtime"), "handler": req.get("handler"), "memory": req.get("memorySize")})
    elif event_name == "UpdateFunctionConfiguration":
        changes["function_name"] = req.get("functionName")
        for field in ["runtime", "handler", "memorySize", "timeout", "description"]: 
            if req.get(field): changes[field] = req[field]
    elif event_name == "UpdateFunctionCode":
        changes["function_name"] = req.get("functionName")
        changes["action"] = "update_code"
    elif event_name == "ModifyVpcAttribute":
        changes["vpc_id"] = req.get("vpcId")
        changes["attribute"] = req.get("attribute")
        if "value" in req: changes["new_value"] = str(req["value"])
        if "enableDnsHostnames" in req: changes["dns_hostnames"] = req["enableDnsHostnames"]["value"]
        if "enableDnsSupport" in req: changes["dns_support"] = req["enableDnsSupport"]["value"]
    elif event_name == "AttachVolume":
        changes["volume_id"] = req.get("volumeId")
        changes["instance_id"] = req.get("instanceId")
        changes["device"] = req.get("device")
        changes["action"] = "attach"
    elif event_name == "DetachVolume":
        changes["volume_id"] = req.get("volumeId")
        changes["instance_id"] = req.get("instanceId")
        changes["device"] = req.get("device")
        changes["force"] = req.get("force", False)
        changes["action"] = "detach"
    
    return json.dumps(changes) if changes else None

def extract_basic_info(event_detail):
    user = event_detail.get("userIdentity", {})
    return {
        "event_name": event_detail.get("eventName", "unknown"),
        "user_name": user.get("userName") or user.get("principalId", "unknown"),
        "resource_name": extract_resource_name(event_detail),
        "changes": extract_changes(event_detail)
    }

def get_all_cloudtrail_events(region, credentials, account_id, account_name):
    client = create_aws_client("cloudtrail", region, credentials)
    if not client:
        return {"error": "No se pudo crear el cliente de CloudTrail", "events": []}
    
    all_events = []
    start_time = datetime.utcnow() - timedelta(days=1)
    
    for source in EVENT_SOURCES:
        next_token = None
        while True:
            params = {"LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": source}], "StartTime": start_time, "EndTime": datetime.utcnow(), "MaxResults": 50}
            if next_token: params["NextToken"] = next_token
            
            response = client.lookup_events(**params)
            next_token = response.get("NextToken")
            
            for event in response.get("Events", []):
                try:
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                    if detail.get("eventName") in IMPORTANT_EVENTS:
                        basic_info = extract_basic_info(detail)
                        if is_valid_resource(basic_info["resource_name"], detail.get("eventSource", source)):
                            all_events.append({"event_id": event.get("EventId"), "event_time": convert_to_local_time(event.get("EventTime")), **basic_info, "region": region, "event_source": detail.get("eventSource", source), "account_id": account_id, "account_name": account_name})
                except: continue
            
            if not next_token: break
    
    return {"events": all_events}

def insert_or_update_cloudtrail_events(events_data):
    if not events_data:
        return {"processed": 0, "inserted": 0}
    
    from services.utils import get_db_connection
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0}
    
    try:
        cursor = conn.cursor()
        batch_data = [(event["event_id"], event["event_time"], event["event_name"], event["user_name"], event["resource_name"], RESOURCE_TYPES.get(event["event_source"], "Unknown"), event["region"], event["event_source"], event["account_id"], event["account_name"], event.get("changes")) for event in events_data]
        
        batch_data = [(event["event_id"], event["event_time"], event["event_name"], event["user_name"], event["resource_name"], RESOURCE_TYPES.get(event["event_source"], "Unknown"), event["region"], event["event_source"], event["account_id"], event["account_name"], event.get("changes")) for event in events_data]
        cursor.executemany("INSERT INTO cloudtrail_events (event_id, event_time, event_name, user_name, resource_name, resource_type, region, event_source, account_id, account_name, changes, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()) ON CONFLICT (event_id) DO NOTHING", batch_data)
        
        inserted = cursor.rowcount
        conn.commit()
        return {"processed": len(events_data), "inserted": inserted}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0}
    finally:
        conn.close()
