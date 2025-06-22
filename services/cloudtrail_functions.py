# cloudtrail_simple.py
import json
from datetime import datetime, timedelta
from services.utils import create_aws_client

# Lista de eventos importantes (conjunta para todos los servicios)
IMPORTANT_EVENTS = {
    "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances",
    "ModifyInstanceAttribute", "CreateTags", "DeleteTags", "RunInstances",
    "AttachVolume", "DetachVolume", "CreateDBInstance", "DeleteDBInstance",
    "ModifyDBInstance", "RebootDBInstance", "StartDBInstance", "StopDBInstance",
    "RestoreDBInstanceFromDBSnapshot", "CreateDBSnapshot", "DeleteDBSnapshot",
    "AddTagsToResource", "RemoveTagsFromResource", "CreateVpc", "DeleteVpc",
    "ModifyVpcAttribute", "CreateSubnet", "DeleteSubnet", "CreateRouteTable",
    "DeleteRouteTable", "CreateInternetGateway", "DeleteInternetGateway",
    "AttachInternetGateway", "DetachInternetGateway", "CreateNatGateway",
    "DeleteNatGateway", "CreateCluster", "DeleteCluster", "ModifyCluster",
    "RebootCluster", "ResizeCluster", "PauseCluster", "ResumeCluster",
    "RestoreFromClusterSnapshot", "CreateClusterSnapshot", "DeleteClusterSnapshot"
}

EVENT_SOURCES = ["ec2.amazonaws.com", "rds.amazonaws.com", "redshift.amazonaws.com"]

def extract_resource_name(event_detail):
    """Extrae resource_name siguiendo el patrón exacto de AWS CloudTrail Console."""
    req = event_detail.get("requestParameters", {})
    resp = event_detail.get("responseElements", {})
    event_name = event_detail.get("eventName", "")
    event_source = event_detail.get("eventSource", "")
    
    # Prioridad 1: Conjuntos de recursos (resourcesSet, instancesSet)
    if "resourcesSet" in req:
        items = req["resourcesSet"].get("items", [])
        if items and "resourceId" in items[0]:
            return items[0]["resourceId"]
    
    if "instancesSet" in req:
        items = req["instancesSet"].get("items", [])
        if items and "instanceId" in items[0]:
            return items[0]["instanceId"]
    
    # Prioridad 2: Campos específicos por servicio y evento
    # EC2 Events
    if event_source == "ec2.amazonaws.com":
        ec2_fields = ["instanceId", "volumeId", "snapshotId", "imageId", "vpcId", 
                     "subnetId", "groupId", "networkInterfaceId", "allocationId", 
                     "natGatewayId", "routeTableId", "internetGatewayId"]
        for field in ec2_fields:
            if field in req and req[field]:
                return req[field]
    
    # RDS Events
    elif event_source == "rds.amazonaws.com":
        rds_fields = ["dBInstanceIdentifier", "dBClusterIdentifier", "dBSnapshotIdentifier", 
                     "dBClusterSnapshotIdentifier", "resourceName"]
        for field in rds_fields:
            if field in req and req[field]:
                return req[field]
    
    # Redshift Events
    elif event_source == "redshift.amazonaws.com":
        redshift_fields = ["clusterIdentifier", "snapshotIdentifier", "resourceName"]
        for field in redshift_fields:
            if field in req and req[field]:
                return req[field]
    
    # Prioridad 3: responseElements para recursos recién creados
    if event_name == "RunInstances" and "instances" in resp:
        instances = resp["instances"]
        if isinstance(instances, list) and instances and "instanceId" in instances[0]:
            return instances[0]["instanceId"]
    
    # Campos comunes en responseElements
    response_fields = ["instanceId", "dBInstanceIdentifier", "clusterIdentifier", 
                      "vpcId", "subnetId", "volumeId", "groupId"]
    for field in response_fields:
        if field in resp and resp[field]:
            return resp[field]
    
    # Prioridad 4: Búsqueda genérica de identificadores
    all_params = {**req, **resp}
    for key, value in all_params.items():
        if isinstance(value, str) and value and (
            key.lower().endswith('id') or 
            'identifier' in key.lower() or 
            key.lower().endswith('name')
        ):
            # Excluir campos que no son resource names
            if key not in ['requestId', 'eventId', 'eventName', 'userName', 'principalId']:
                return value
    
    return "unknown"

def is_valid_resource(resource_name, event_source):
    """Verifica si el resource_name es válido según los criterios."""
    if not resource_name or resource_name == "unknown":
        return False
    
    # Instancias EC2
    if resource_name.startswith("i-"):
        return True
    # VPCs
    if resource_name.startswith("vpc-"):
        return True
    # Subnets
    if resource_name.startswith("subnet-"):
        return True
    # RDS
    if event_source == "rds.amazonaws.com":
        return True
    # Redshift
    if event_source == "redshift.amazonaws.com":
        return True
    
    return False

def extract_changes(event_detail):
    """Extrae información específica de cambios según el tipo de evento."""
    req = event_detail.get("requestParameters", {})
    resp = event_detail.get("responseElements", {})
    event_name = event_detail.get("eventName", "")
    
    changes = {}
    
    # Tags
    if event_name in ["CreateTags", "DeleteTags"]:
        if "tagSet" in req:
            tags = []
            for tag in req["tagSet"].get("items", []):
                key = tag.get("key", "")
                value = tag.get("value", "")
                tags.append(f"{key}={value}")
            if tags:
                changes["tags"] = ", ".join(tags)
    
    # EC2 State changes
    elif event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
        if "instancesSet" in req:
            instances = []
            for item in req["instancesSet"].get("items", []):
                if "instanceId" in item:
                    instances.append(item["instanceId"])
            if instances:
                changes["instances"] = ", ".join(instances)
                changes["action"] = event_name.replace("Instances", "").lower()
    
    # EC2 Creation
    elif event_name == "RunInstances":
        if req.get("instanceType"):
            changes["instance_type"] = req["instanceType"]
        if req.get("imageId"):
            changes["image_id"] = req["imageId"]
        if req.get("subnetId"):
            changes["subnet_id"] = req["subnetId"]
        if req.get("minCount"):
            changes["instance_count"] = req["minCount"]
    
    elif event_name == "ModifyInstanceAttribute":
        changes["attribute"] = req.get("attribute")
        if "value" in req:
            changes["new_value"] = str(req["value"])
    
    # RDS
    elif event_name == "CreateDBInstance":
        changes["db_instance_class"] = req.get("dBInstanceClass")
        changes["engine"] = req.get("engine")
        changes["engine_version"] = req.get("engineVersion")
        changes["allocated_storage"] = req.get("allocatedStorage")
    
    elif event_name in ["StartDBInstance", "StopDBInstance", "RebootDBInstance"]:
        changes["action"] = event_name.replace("DBInstance", "").lower()
    
    elif event_name == "ModifyDBInstance":
        modify_fields = ["dBInstanceClass", "allocatedStorage", "engineVersion"]
        for field in modify_fields:
            if field in req:
                changes[field.lower()] = req[field]
    
    # VPC/Subnet
    elif event_name == "CreateVpc":
        changes["cidr_block"] = req.get("cidrBlock")
    
    elif event_name == "CreateSubnet":
        changes["cidr_block"] = req.get("cidrBlock")
        changes["vpc_id"] = req.get("vpcId")
    
    # Redshift
    elif event_name == "CreateCluster":
        changes["node_type"] = req.get("nodeType")
        changes["number_of_nodes"] = req.get("numberOfNodes")
    
    elif event_name in ["PauseCluster", "ResumeCluster"]:
        changes["action"] = event_name.replace("Cluster", "").lower()
    
    # Fallback: capturar campos importantes genéricos
    if not changes:
        important_fields = ["instanceType", "imageId", "cidrBlock", "engine", "nodeType"]
        for field in important_fields:
            if field in req and req[field]:
                changes[field.lower()] = req[field]
    
    return json.dumps(changes) if changes else None

def extract_basic_info(event_detail):
    """Extrae información clave del evento."""
    event_name = event_detail.get("eventName", "unknown")
    user = event_detail.get("userIdentity", {})
    user_name = user.get("userName") or user.get("principalId", "unknown")
    resource_name = extract_resource_name(event_detail)
    changes = extract_changes(event_detail)
    
    return {
        "event_name": event_name,
        "user_name": user_name,
        "resource_name": resource_name,
        "changes": changes
    }

def get_all_cloudtrail_events(region, credentials, account_id, account_name):
    """Obtiene eventos importantes de CloudTrail del último día."""
    client = create_aws_client("cloudtrail", region, credentials)
    if not client:
        return {"error": "No se pudo crear el cliente de CloudTrail", "events": []}

    start_time = datetime.utcnow() - timedelta(days=1)
    end_time = datetime.utcnow()
    all_events = []

    for source in EVENT_SOURCES:
        next_token = None
        while True:
            params = {
                "LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": source}],
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": 50
            }
            if next_token:
                params["NextToken"] = next_token

            response = client.lookup_events(**params)
            events = response.get("Events", [])
            next_token = response.get("NextToken")

            for event in events:
                try:
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                    if detail.get("eventName") not in IMPORTANT_EVENTS:
                        continue
                    
                    basic_info = extract_basic_info(detail)
                    
                    # Filtrar solo recursos válidos
                    if not is_valid_resource(basic_info["resource_name"], detail.get("eventSource", source)):
                        continue
                    
                    all_events.append({
                        "event_id": event.get("EventId"),
                        "event_time": event.get("EventTime"),
                        **basic_info,
                        "region": region,
                        "event_source": detail.get("eventSource", source),
                        "account_id": account_id,
                        "account_name": account_name
                    })
                except Exception as e:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Evento - {e}")

            if not next_token:
                break

    return {"events": all_events}

def insert_or_update_cloudtrail_events(events_data):
    """Inserta eventos de CloudTrail en la base de datos."""
    if not events_data:
        return {"processed": 0, "inserted": 0}

    from services.utils import get_db_connection
    
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0}

    inserted = 0
    processed = len(events_data)

    try:
        cursor = conn.cursor()
        
        for event in events_data:
            resource_type = {
                "ec2.amazonaws.com": "EC2",
                "rds.amazonaws.com": "RDS", 
                "redshift.amazonaws.com": "Redshift"
            }.get(event["event_source"], "Unknown")

            cursor.execute("""
                INSERT INTO cloudtrail_events (
                    event_id, event_time, event_name, user_name, resource_name,
                    resource_type, region, event_source, account_id, account_name, changes, last_updated
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
                )
                ON CONFLICT (event_id) DO NOTHING
            """, (
                event["event_id"], event["event_time"], event["event_name"],
                event["user_name"], event["resource_name"], resource_type,
                event["region"], event["event_source"], event["account_id"], 
                event["account_name"], event.get("changes")
            ))
            
            if cursor.rowcount > 0:
                inserted += 1

        conn.commit()
        return {
            "processed": processed,
            "inserted": inserted
        }

    except Exception as e:
        conn.rollback()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: DB cloudtrail_events - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0}
    finally:
        conn.close()
