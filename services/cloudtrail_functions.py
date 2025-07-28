import json
from datetime import datetime, timedelta
from services.utils import create_aws_client

def convert_to_utc_time(utc_time):
    if utc_time is None:
        return datetime.now()
    if isinstance(utc_time, str):
        try:
            utc_time = datetime.fromisoformat(utc_time.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            return datetime.now()
    if hasattr(utc_time, 'replace'):
        return utc_time.replace(tzinfo=None)
    return datetime.now()

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
    if not isinstance(event_detail, dict):
        return "unknown"
        
    req = event_detail.get("requestParameters", {})
    resp = event_detail.get("responseElements", {})
    event_source = event_detail.get("eventSource", "")
    
    if not isinstance(req, dict):
        req = {}
    if not isinstance(resp, dict):
        resp = {}
    
    # Check resource sets
    for set_name in ["resourcesSet", "instancesSet"]:
        if set_name in req and isinstance(req[set_name], dict) and req[set_name].get("items"):
            items = req[set_name]["items"]
            if isinstance(items, list) and len(items) > 0 and isinstance(items[0], dict):
                return items[0].get("resourceId" if set_name == "resourcesSet" else "instanceId", "unknown")
    
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

def extract_user_name(event_detail):
    """Extrae el nombre del usuario de diferentes tipos de identidad"""
    if not isinstance(event_detail, dict):
        return 'system'
        
    user_identity = event_detail.get('userIdentity', {})
    if not isinstance(user_identity, dict):
        return 'system'
    
    # Intentar diferentes campos de usuario
    user_name = (
        user_identity.get('userName') or
        user_identity.get('arn', '').split('/')[-1] or
        user_identity.get('principalId', '').split(':')[-1] or
        user_identity.get('type', 'unknown')
    )
    
    # Limpiar nombres de usuario largos
    if isinstance(user_name, str) and len(user_name) > 50:
        user_name = user_name[-50:]  # Últimos 50 caracteres
    
    return user_name if user_name and user_name != 'unknown' else 'system'

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
            if any(result.values()): 
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
    import time
    
    # Validar credenciales antes de crear cliente
    if not credentials or not isinstance(credentials, dict):
        return {"events": []}
    
    cloudtrail_client = create_aws_client("cloudtrail", region, credentials)
    if not cloudtrail_client:
        return {"events": []}

    try:
        start_time = datetime.now() - timedelta(days=7)  # Reducir a 7 días para prueba
        events = []
        total_events = 0
        filtered_events = 0
        
        # Obtener múltiples páginas con rate limiting
        next_token = None
        pages_processed = 0
        max_pages = 5  # Reducir aún más para debugging
        
        while pages_processed < max_pages:
            params = {
                'StartTime': start_time,
                'EndTime': datetime.now(),
                'MaxResults': 20  # Reducir tamaño de página
            }
            if next_token:
                params['NextToken'] = next_token
            
            # Rate limiting - esperar entre llamadas
            if pages_processed > 0:
                time.sleep(0.5)  # Aumentar tiempo de espera
            
            page = None
            try:
                page = cloudtrail_client.lookup_events(**params)
            except Exception as api_error:
                error_str = str(api_error)
                if "ThrottlingException" in error_str or "Rate exceeded" in error_str:
                    time.sleep(3)  # Esperar más tiempo
                    try:
                        page = cloudtrail_client.lookup_events(**params)
                    except Exception as retry_error:
                        print(f"CloudTrail {region}: Throttling persistente, saltando")
                        break
                else:
                    print(f"CloudTrail ERROR {region}: {error_str}")
                    break
            
            pages_processed += 1
            
            # Validaciones exhaustivas
            if page is None:
                print(f"CloudTrail {region}: Respuesta None")
                break
                
            if not isinstance(page, dict):
                print(f"CloudTrail {region}: Respuesta no es dict")
                break
                
            if 'Events' not in page:
                print(f"CloudTrail {region}: No hay clave 'Events'")
                break
                
            events_list = page.get('Events')
            if not isinstance(events_list, list):
                print(f"CloudTrail {region}: 'Events' no es lista")
                break
                
            for event in events_list:
                if not isinstance(event, dict):
                    continue
                    
                total_events += 1
                
                # Verificar que el evento tenga CloudTrailEvent
                cloudtrail_event = event.get('CloudTrailEvent')
                if not cloudtrail_event or not isinstance(cloudtrail_event, str):
                    continue
                    
                try:
                    event_detail = json.loads(cloudtrail_event)
                    if not isinstance(event_detail, dict):
                        continue
                except (json.JSONDecodeError, TypeError):
                    continue
                    
                event_name = event_detail.get('eventName', '')
                event_source = event_detail.get('eventSource', '')
                
                # Solo filtrar por eventos importantes
                if event_name in IMPORTANT_EVENTS and event_source in EVENT_SOURCES:
                    filtered_events += 1
                    resource_name = extract_resource_name(event_detail)
                    
                    events.append({
                        'event_id': event_detail.get('eventID', ''),
                        'event_time': convert_to_utc_time(event_detail.get('eventTime')),
                        'event_name': event_name,
                        'event_source': event_source,
                        'user_name': extract_user_name(event_detail),
                        'resource_name': resource_name if resource_name != 'unknown' else event_name.lower(),
                        'resource_type': RESOURCE_TYPES.get(event_source, 'UNKNOWN'),
                        'region': event_detail.get('awsRegion', region),
                        'changes': extract_changes(event_detail),
                        'account_id': account_id,
                        'account_name': account_name
                    })
            
            # Verificar si hay más páginas
            next_token = page.get('NextToken') if isinstance(page, dict) else None
            if not next_token:
                break
        
        # Mostrar resultados para debugging
        if total_events > 0:
            print(f"CloudTrail {region}: {total_events} total, {filtered_events} importantes")
        
        return {"events": events}
    except Exception as e:
        print(f"CloudTrail ERROR {region}: {str(e)}")
        return {"events": []}

def insert_or_update_cloudtrail_events(events_data):
    if not events_data or not isinstance(events_data, list):
        return {"processed": 0, "inserted": 0, "updated": 0}
    
    from services.utils import get_db_connection
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}
    
    try:
        cursor = conn.cursor()
        inserted = 0
        
        for event in events_data:
            if not isinstance(event, dict):
                continue
                
            try:
                cursor.execute("""
                    INSERT INTO cloudtrail_events 
                    (event_id, event_time, event_name, event_source, user_name, resource_name, resource_type, region, changes, account_id, account_name, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (event_id) DO NOTHING
                """, (event.get('event_id', ''), event.get('event_time'), event.get('event_name', ''), 
                     event.get('event_source', ''), event.get('user_name', ''), event.get('resource_name', ''), 
                     event.get('resource_type', ''), event.get('region', ''), event.get('changes'), 
                     event.get('account_id', ''), event.get('account_name', '')))
                inserted += cursor.rowcount
            except Exception as insert_error:
                print(f"Error insertando evento: {str(insert_error)}")
                continue
        
        conn.commit()
        return {"processed": len(events_data), "inserted": inserted, "updated": 0}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()