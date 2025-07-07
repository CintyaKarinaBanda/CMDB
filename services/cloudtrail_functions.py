import json
from datetime import datetime, timedelta
from services.utils import create_aws_client

def convert_to_utc_time(utc_time):
    if isinstance(utc_time, str):
        utc_time = datetime.fromisoformat(utc_time.replace('Z', '+00:00'))
    return utc_time.replace(tzinfo=None)

IMPORTANT_EVENTS = {
    "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances", "ModifyInstanceAttribute", "CreateTags", "DeleteTags", "RunInstances", "AttachVolume", "DetachVolume", "CreateVolume", "DeleteVolume", "ModifyVolume",
    "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance", "RebootDBInstance", "StartDBInstance", "StopDBInstance", "CreateDBSnapshot", "DeleteDBSnapshot", "RestoreDBInstanceFromDBSnapshot", "AddTagsToResource", "RemoveTagsFromResource",
    "CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "CreateSubnet", "DeleteSubnet", "ModifySubnetAttribute", "CreateRouteTable", "DeleteRouteTable", "CreateInternetGateway", "DeleteInternetGateway", "AttachInternetGateway", "DetachInternetGateway",
    "CreateNatGateway", "DeleteNatGateway", "CreateCluster", "DeleteCluster", "ModifyCluster", "RebootCluster", "ResizeCluster", "PauseCluster", "ResumeCluster", "RestoreFromClusterSnapshot", "CreateClusterSnapshot", "DeleteClusterSnapshot",
    "CreateBucket", "DeleteBucket", "PutBucketTagging", "PutBucketEncryption", "PutBucketVersioning", "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketNotification", "PutPublicAccessBlock", "PutBucketReplication", "DeleteBucketReplication", "PutBucketAcl",
    "UpdateClusterConfig", "UpdateClusterVersion", "CreateAddon", "DeleteAddon", "UpdateAddon", "TagResource", "UntagResource",
    "CreateRepository", "DeleteRepository", "PutImage", "BatchDeleteImage", "PutRepositoryPolicy", "DeleteRepositoryPolicy",
    "CreateKey", "ScheduleKeyDeletion", "CancelKeyDeletion", "EnableKey", "DisableKey", "UpdateKeyDescription", "PutKeyPolicy", "CreateAlias", "DeleteAlias", "UpdateAlias",
    "CreateFunction", "DeleteFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration", "PublishVersion", "CreateEventSourceMapping", "DeleteEventSourceMapping", "UpdateEventSourceMapping", "PutFunctionConcurrency", "DeleteFunctionConcurrency",
    "CreateRestApi", "DeleteRestApi", "UpdateRestApi", "CreateDeployment", "DeleteDeployment", "CreateStage", "DeleteStage", "UpdateStage", "CreateApi", "DeleteApi", "UpdateApi", "CreateRoute", "DeleteRoute", "UpdateRoute", "CreateIntegration", "DeleteIntegration", "UpdateIntegration",
    "CreateJob", "DeleteJob", "UpdateJob", "StartJobRun", "StopJobRun", "CreateCrawler", "DeleteCrawler", "UpdateCrawler", "StartCrawler", "StopCrawler", "CreateDatabase", "DeleteDatabase", "UpdateDatabase", "CreateTable", "DeleteTable", "UpdateTable",
    "CreateStack", "DeleteStack", "UpdateStack", "CreateChangeSet", "DeleteChangeSet", "ExecuteChangeSet", "CancelUpdateStack", "ContinueUpdateRollback", "UpdateTerminationProtection", "SetStackPolicy",
    "CreateTrail", "DeleteTrail", "UpdateTrail", "StartLogging", "StopLogging", "PutEventSelectors", "PutInsightSelectors",
    "CreateAssociation", "DeleteAssociation", "UpdateAssociation", "CreateDocument", "DeleteDocument", "UpdateDocument", "SendCommand", "PutComplianceItems",
    "StartQueryExecution", "StopQueryExecution", "CreateWorkGroup", "DeleteWorkGroup", "UpdateWorkGroup", "CreateDataCatalog", "DeleteDataCatalog", "UpdateDataCatalog", "BatchCreateNamedQuery", "BatchDeleteNamedQuery",
    "CreateStateMachine", "DeleteStateMachine", "UpdateStateMachine", "StartExecution", "StopExecution", "CreateActivity", "DeleteActivity",
    "CreateServer", "DeleteServer", "UpdateServer", "StartServer", "StopServer", "CreateUser", "DeleteUser", "UpdateUser",
    "CreatePipeline", "DeletePipeline", "UpdatePipeline", "StartPipelineExecution", "StopPipelineExecution", "RetryStageExecution",
    "RunJobFlow", "TerminateJobFlows", "ModifyInstanceGroups", "AddInstanceGroups", "SetTerminationProtection", "AddJobFlowSteps"
}

EVENT_SOURCES = ["ec2.amazonaws.com", "rds.amazonaws.com", "redshift.amazonaws.com", "s3.amazonaws.com", "eks.amazonaws.com", "ecr.amazonaws.com", "kms.amazonaws.com", "lambda.amazonaws.com", "apigateway.amazonaws.com", "glue.amazonaws.com", "cloudformation.amazonaws.com", "ssm.amazonaws.com", "athena.amazonaws.com", "states.amazonaws.com", "transfer.amazonaws.com", "codepipeline.amazonaws.com", "elasticmapreduce.amazonaws.com"]

SERVICE_FIELDS = {
    "ec2.amazonaws.com": ["instanceId", "volumeId", "vpcId", "subnetId", "groupId"],
    "rds.amazonaws.com": ["dBInstanceIdentifier", "dBClusterIdentifier"],
    "redshift.amazonaws.com": ["clusterIdentifier"],
    "s3.amazonaws.com": ["bucketName", "bucket"],
    "eks.amazonaws.com": ["name", "clusterName"],
    "ecr.amazonaws.com": ["repositoryName"],
    "kms.amazonaws.com": ["keyId"],
    "lambda.amazonaws.com": ["functionName"],
    "apigateway.amazonaws.com": ["restApiId", "apiId", "id"],
    "glue.amazonaws.com": ["jobName", "name", "crawlerName", "databaseName", "tableName"],
    "cloudformation.amazonaws.com": ["stackName", "changeSetName"],
    "cloudtrail.amazonaws.com": ["trailName", "name"],
    "ssm.amazonaws.com": ["associationId", "documentName", "instanceId"],
    "athena.amazonaws.com": ["queryExecutionId", "workGroupName", "dataCatalogName"],
    "states.amazonaws.com": ["stateMachineArn", "executionArn", "activityArn"],
    "transfer.amazonaws.com": ["serverId", "userName", "workflowId"],
    "codepipeline.amazonaws.com": ["pipelineName", "executionId", "stageName"],
    "elasticmapreduce.amazonaws.com": ["clusterId", "jobFlowId", "stepId"]
}

RESOURCE_TYPES = {"ec2.amazonaws.com": "EC2", "rds.amazonaws.com": "RDS", "redshift.amazonaws.com": "Redshift", "s3.amazonaws.com": "S3", "eks.amazonaws.com": "EKS", "ecr.amazonaws.com": "ECR", "kms.amazonaws.com": "KMS", "lambda.amazonaws.com": "LAMBDA", "apigateway.amazonaws.com": "API-GATEWAY", "glue.amazonaws.com": "GLUE", "cloudformation.amazonaws.com": "CLOUDFORMATION", "cloudtrail.amazonaws.com": "CLOUDTRAIL", "ssm.amazonaws.com": "SSM", "athena.amazonaws.com": "ATHENA", "states.amazonaws.com": "STEP-FUNCTIONS", "transfer.amazonaws.com": "TRANSFER-FAMILY", "codepipeline.amazonaws.com": "CODEPIPELINE", "elasticmapreduce.amazonaws.com": "EMR"}

def extract_resource_name(event_detail):
    req = event_detail.get("requestParameters", {})
    resp = event_detail.get("responseElements", {})
    event_source = event_detail.get("eventSource", "")
    
    # Check resource sets
    for set_name in ["resourcesSet", "instancesSet"]:
        if set_name in req and req[set_name].get("items"):
            return req[set_name]["items"][0].get("resourceId" if set_name == "resourcesSet" else "instanceId", "unknown")
    
    # Check service fields
    for field in SERVICE_FIELDS.get(event_source, []):
        if req.get(field): return req[field]
    
    # Check response fields
    for field in ["instanceId", "dBInstanceIdentifier", "clusterIdentifier", "vpcId", "subnetId", "bucketName", "name", "keyId", "functionName"]:
        if resp.get(field): return resp[field]
    
    # Generic search
    for key, value in {**req, **resp}.items():
        if isinstance(value, str) and value and (key.lower().endswith(('id', 'name')) or 'identifier' in key.lower()):
            if key not in ['requestId', 'eventId', 'eventName', 'userName', 'principalId']:
                return value
    
    return "unknown"

def is_valid_resource(resource_name, event_source):
    return (resource_name and resource_name != "unknown" and 
            (resource_name.startswith(("i-", "vpc-", "subnet-", "vol-", "snap-", "igw-", "nat-", "rtb-")) or 
             event_source in ["rds.amazonaws.com", "redshift.amazonaws.com", "s3.amazonaws.com", "eks.amazonaws.com", "ecr.amazonaws.com", "kms.amazonaws.com", "lambda.amazonaws.com"]))

def extract_changes(event_detail):
    req = event_detail.get("requestParameters", {})
    event_name = event_detail.get("eventName", "")
    changes = {}
    
    # Pattern matching for common events
    patterns = {
        # Tags
        ("CreateTags", "DeleteTags"): lambda: {"tags": ", ".join([f"{t.get('key','')}={t.get('value','')}" for t in req.get("tagSet", {}).get("items", [])])},
        # Instance actions
        ("StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"): lambda: {"instances": ", ".join([i["instanceId"] for i in req.get("instancesSet", {}).get("items", [])]), "action": event_name.replace("Instances", "").lower()},
        # Volume operations
        ("AttachVolume", "DetachVolume"): lambda: {"action": event_name.lower(), "volume": req.get("volumeId"), "instance": req.get("instanceId")},
        # Gateway operations
        ("AttachInternetGateway", "DetachInternetGateway"): lambda: {"action": event_name.lower(), "gateway": req.get("internetGatewayId"), "vpc": req.get("vpcId")},
        # Subnet operations
        ("CreateSubnet", "DeleteSubnet"): lambda: {"action": event_name.lower(), "cidr": req.get("cidrBlock"), "vpc": req.get("vpcId")},
        # VPC operations
        ("CreateVpc", "DeleteVpc"): lambda: {"action": event_name.lower(), "cidr": req.get("cidrBlock")},
        # Route operations
        ("CreateRouteTable", "DeleteRouteTable"): lambda: {"action": event_name.lower(), "vpc": req.get("vpcId")},
        ("CreateRoute", "DeleteRoute"): lambda: {"action": event_name.lower(), "destination": req.get("destinationCidrBlock"), "gateway": req.get("gatewayId")},
        # RDS operations
        ("RebootDBInstance", "StartDBInstance", "StopDBInstance"): lambda: {"action": event_name.lower().replace("dbinstance", ""), "instance": req.get("dBInstanceIdentifier")},
        # S3 operations
        ("CreateBucket", "DeleteBucket"): lambda: {"action": event_name.lower(), "bucket": req.get("bucketName")},
        # KMS operations
        ("CreateAlias", "DeleteAlias"): lambda: {"action": event_name.lower(), "alias": req.get("aliasName"), "key": req.get("targetKeyId")}
    }
    
    # Check patterns
    for events, func in patterns.items():
        if event_name in events:
            result = func()
            if any(result.values()):  # Only add if has meaningful values
                changes.update({k: v for k, v in result.items() if v})
                break
    
    # Special cases
    if not changes:
        if event_name == "ModifyInstanceAttribute":
            attrs = [f"{k}={req[k]}" for k in ["instanceType", "userData", "disableApiTermination"] if k in req]
            if attrs: changes["attributes"] = ", ".join(attrs)
        elif event_name == "ModifySubnetAttribute" and "mapPublicIpOnLaunch" in req:
            changes["public_ip"] = str(req["mapPublicIpOnLaunch"])
        elif event_name == "ModifyVpcAttribute":
            attrs = [f"{k}={req[k]}" for k in ["enableDnsHostnames", "enableDnsSupport"] if k in req]
            if attrs: changes["attributes"] = ", ".join(attrs)
        elif event_name == "PutBucketTagging" and req.get("tagging", {}).get("tagSet"):
            changes["tags"] = ", ".join([f"{t.get('key','')}={t.get('value','')}" for t in req["tagging"]["tagSet"]])
        elif event_name == "PutBucketEncryption":
            changes.update({"action": "enable_encryption", "encryption": "enabled"})
        elif event_name == "PutBucketVersioning" and req.get("versioningConfiguration"):
            changes["versioning"] = req["versioningConfiguration"].get("status", "").lower()
        elif event_name == "BatchDeleteImage" and req.get("imageIds"):
            changes["deleted_images"] = str(len(req["imageIds"]))
        elif event_name == "UpdateClusterConfig" and req.get("update"):
            changes.update({"action": "update_config", "fields": ", ".join(req["update"].keys())})
    
    # Fallback
    if not changes:
        changes["action"] = event_name.lower()
    
    return json.dumps(changes) if changes else None

def get_all_cloudtrail_events(region, credentials, account_id, account_name):
    cloudtrail_client = create_aws_client("cloudtrail", region, credentials)
    if not cloudtrail_client:
        return {"events": []}

    try:
        start_time = datetime.now() - timedelta(days=1)
        events = []
        total_events = 0
        filtered_events = 0
        
        # Obtener múltiples páginas manualmente
        next_token = None
        pages_processed = 0
        max_pages = 20  # 20 páginas x 50 eventos = 1000 eventos máximo
        
        while pages_processed < max_pages:
            params = {
                'StartTime': start_time,
                'EndTime': datetime.now(),
                'MaxResults': 50
            }
            if next_token:
                params['NextToken'] = next_token
            
            page = cloudtrail_client.lookup_events(**params)
            pages_processed += 1
            
            for event in page.get('Events', []):
                total_events += 1
                event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
                event_name = event_detail.get('eventName', '')
                event_source = event_detail.get('eventSource', '')
                
                if event_name in IMPORTANT_EVENTS and event_source in EVENT_SOURCES:
                    filtered_events += 1
                    resource_name = extract_resource_name(event_detail)
                    if is_valid_resource(resource_name, event_source):
                        events.append({
                            'event_id': event_detail.get('eventID', ''),
                            'event_time': convert_to_utc_time(event_detail.get('eventTime')),
                            'event_name': event_name,
                            'event_source': event_source,
                            'user_name': event_detail.get('userIdentity', {}).get('userName', 'unknown'),
                            'resource_name': resource_name,
                            'resource_type': RESOURCE_TYPES.get(event_source, 'UNKNOWN'),
                            'region': event_detail.get('awsRegion', region),
                            'changes': extract_changes(event_detail)
                        })
            
            # Verificar si hay más páginas
            next_token = page.get('NextToken')
            if not next_token:
                break
        
        # Debug temporal
        if region == "us-east-1" and account_name:
            print(f"DEBUG CloudTrail {region}: {total_events} total, {filtered_events} filtrados, {len(events)} válidos")
        
        return {"events": events}
    except Exception as e:
        print(f"DEBUG CloudTrail ERROR {region}: {str(e)}")
        return {"events": []}

def insert_or_update_cloudtrail_events(events_data):
    if not events_data:
        return {"processed": 0, "inserted": 0, "updated": 0}
    
    from services.utils import get_db_connection
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}
    
    try:
        cursor = conn.cursor()
        inserted = 0
        
        for event in events_data:
            try:
                cursor.execute("""
                    INSERT INTO cloudtrail_events 
                    (event_id, event_time, event_name, event_source, user_name, resource_name, resource_type, region, changes, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (event_id) DO NOTHING
                """, (event['event_id'], event['event_time'], event['event_name'], event['event_source'], 
                     event['user_name'], event['resource_name'], event['resource_type'], event['region'], event['changes']))
                inserted += cursor.rowcount
            except:
                continue
        
        conn.commit()
        
        # No mostrar log aquí, se mostrará en el script principal
        
        return {"processed": len(events_data), "inserted": inserted, "updated": 0}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()