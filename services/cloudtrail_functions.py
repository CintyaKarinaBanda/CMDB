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

def extract_basic_info(event_detail):
    """Extrae información clave del evento."""
    event_name = event_detail.get("eventName", "unknown")
    user = event_detail.get("userIdentity", {})
    user_name = user.get("userName") or user.get("principalId", "unknown")
    
    # Extrae un ID de recurso genérico (mejorable si se quiere precisión por tipo)
    resource_id = "unknown"
    req = event_detail.get("requestParameters", {})
    for key in ["instanceId", "dBInstanceIdentifier", "vpcId", "subnetId", "clusterIdentifier"]:
        if key in req:
            resource_id = req[key]
            break
    
    return {
        "event_name": event_name,
        "user_name": user_name,
        "resource_id": resource_id
    }

def get_important_cloudtrail_events(region, credentials):
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
                    all_events.append({
                        "event_id": event.get("EventId"),
                        "event_time": event.get("EventTime"),
                        **basic_info,
                        "region": region,
                        "event_source": detail.get("eventSource", source)
                    })
                except Exception as e:
                    print(f"[ERROR] Procesando evento: {e}")

            if not next_token:
                break

    return {"events": all_events}
