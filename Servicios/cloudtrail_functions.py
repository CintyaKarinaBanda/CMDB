# Servicios/cloudtrail_functions.py
import json
from datetime import datetime, timedelta
from Servicios.utils import create_aws_client, get_db_connection

IMPORTANT_EC2_EVENTS = {
    "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances", 
    "ModifyInstanceAttribute", "CreateTags", "DeleteTags", "RunInstances", 
    "AttachVolume", "DetachVolume", "ModifyVolume", "AssociateAddress", 
    "DisassociateAddress"
}

def extract_instance_id(event):
    """Extrae el ID de instancia u otro recurso relevante del evento."""
    event_name = event.get("eventName", "")
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    if event_name == "CreateTags":
        resources = req.get("resourcesSet", {}).get("items", [])
        for resource in resources:
            resource_id = resource.get("resourceId")
            if resource_id and resource_id.startswith(("i-", "vol-", "snap-", "eni-", "ami-")):
                return resource_id
    
    if event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
        instances = req.get("instancesSet", {}).get("items", []) or res.get("instancesSet", {}).get("items", [])
        if instances and len(instances) > 0:
            return instances[0].get("instanceId", "unknown")
    
    if event_name == "ModifyInstanceAttribute":
        return req.get("instanceId", "unknown")
    
    if event_name in ["AttachVolume", "DetachVolume", "ModifyVolume"]:
        instance_id = req.get("instanceId") or res.get("instanceId")
        if instance_id and instance_id.startswith("i-"):
            return instance_id
        return req.get("volumeId") or res.get("volumeId") or "unknown"
    
    for obj in [req, res]:
        for key in ["instanceId", "resourceId", "volumeId"]:
            if key in obj and obj[key] and isinstance(obj[key], str):
                if obj[key].startswith(("i-", "vol-", "snap-", "eni-", "ami-")):
                    return obj[key]
    
    resources = event.get("resources", [])
    for resource in resources:
        resource_name = resource.get("ARN") or resource.get("resourceName")
        if resource_name and isinstance(resource_name, str):
            parts = resource_name.split("/")
            if len(parts) > 1 and parts[-1].startswith(("i-", "vol-", "snap-", "eni-", "ami-")):
                return parts[-1]
    
    return "unknown"

def extract_changes(event):
    """Extrae información detallada de cambios de un evento CloudTrail."""
    event_name = event.get("eventName", "")
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    changes = {
        "eventType": event_name,
        "details": {}
    }
    
    if event_name == "RunInstances":
        instances = res.get("instancesSet", {}).get("items", [])
        if instances:
            instance = instances[0]
            changes["details"].update({
                "instanceType": instance.get("instanceType"),
                "imageId": instance.get("imageId"),
                "subnetId": instance.get("subnetId"),
                "vpcId": instance.get("vpcId"),
                "privateIpAddress": instance.get("privateIpAddress"),
                "keyName": instance.get("keyName")
            })
            
            if "tagSet" in instance:
                tags = {}
                for tag_item in instance.get("tagSet", {}).get("items", []):
                    if "key" in tag_item and "value" in tag_item:
                        tags[tag_item["key"]] = tag_item["value"]
                if tags:
                    changes["details"]["tags"] = tags
    
    elif event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
        instances = res.get("instancesSet", {}).get("items", [])
        if instances:
            state_changes = []
            for instance in instances:
                state_changes.append({
                    "instanceId": instance.get("instanceId"),
                    "previousState": instance.get("previousState", {}).get("name"),
                    "currentState": instance.get("currentState", {}).get("name")
                })
            changes["details"]["stateChanges"] = state_changes
    
    elif event_name == "ModifyInstanceAttribute":
        for key, value in req.items():
            if key not in ["instanceId", "attribute", "value"]:
                changes["details"][key] = value
    
    elif event_name in ["CreateTags", "DeleteTags"]:
        tag_items = req.get("tagSet", {}).get("items", [])
        if tag_items:
            tags = {}
            for tag_item in tag_items:
                if "key" in tag_item and "value" in tag_item:
                    tags[tag_item["key"]] = tag_item["value"]
            changes["details"]["tags"] = tags
            
            resources = []
            for resource_item in req.get("resourcesSet", {}).get("items", []):
                resources.append(resource_item.get("resourceId"))
            if resources:
                changes["details"]["resources"] = resources
    
    elif event_name in ["AttachVolume", "DetachVolume"]:
        changes["details"].update({
            "volumeId": req.get("volumeId"),
            "instanceId": req.get("instanceId"),
            "device": req.get("device")
        })
    
    if not changes["details"]:
        for key in ["instanceType", "volumeId", "instanceState"]:
            value = req.get(key) or res.get(key)
            if value:
                changes["details"][key] = value
    
    return changes

def get_ec2_cloudtrail_events(region, credentials):
    """Obtiene eventos de CloudTrail relacionados con EC2."""
    print(f"[CloudTrail] Consultando región {region}")
    
    start_time = datetime.utcnow() - timedelta(days=3)  
    max_events = 500 
    
    try:
        client = create_aws_client("cloudtrail", region, credentials)
        if not client:
            return {"error": "Error al crear cliente CloudTrail", "events": []}

        all_events = []
        next_token = None
        
        for call_num in range(1, 6):
            try:
                response = client.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "ec2.amazonaws.com"}],
                    StartTime=start_time,
                    EndTime=datetime.utcnow(),
                    MaxResults=100,
                    **({"NextToken": next_token} if next_token else {})
                )
                
                events_batch = response.get("Events", [])
                all_events.extend(events_batch)
                print(f"[CloudTrail] Llamada #{call_num}: {len(events_batch)} eventos")
                
                if len(all_events) >= max_events or not response.get("NextToken"):
                    break
                    
                next_token = response.get("NextToken")
                
            except Exception as e:
                print(f"[CloudTrail] Error en llamada #{call_num}: {str(e)}")
                break
        
        print(f"[CloudTrail] Total eventos obtenidos: {len(all_events)}")
        
        parsed_events = []
        processed_event_ids = set()
        
        for raw_event in all_events:
            try:
                event_id = raw_event.get("EventId")
                
                if event_id in processed_event_ids:
                    continue
                
                detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                event_name = detail.get("eventName")
                
                if event_name not in IMPORTANT_EC2_EVENTS:
                    continue
                
                user_identity = detail.get("userIdentity", {})
                user_name_options = [
                    raw_event.get("Username"),
                    user_identity.get("userName"),
                    user_identity.get("principalId"),
                    user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName"),
                    user_identity.get("arn", "").split("/")[-1] if user_identity.get("arn") else None,
                    user_identity.get("type")
                ]
                
                user_name = next((name for name in user_name_options if name), "unknown")
                
                resource_name = extract_instance_id(detail)
                
                if not resource_name.startswith("i-"):
                    continue
                
                changes = extract_changes(detail)
                
                parsed_event = {
                    "eventId": event_id,
                    "eventTime": raw_event.get("EventTime"),
                    "eventName": event_name,
                    "userName": user_name,
                    "resourceName": resource_name,
                    "region": raw_event.get("AwsRegion"),
                    "changes": changes
                }
                
                parsed_events.append(parsed_event)
                processed_event_ids.add(event_id)
                
            except Exception as e:
                print(f"[CloudTrail] Error al procesar evento: {str(e)}")
        
        return {"events": parsed_events}
        
    except Exception as e:
        print(f"[CloudTrail] Error general: {str(e)}")
        return {"error": str(e), "events": []}

def insert_or_update_cloudtrail_events(events):
    """Inserta o actualiza eventos de CloudTrail en la base de datos."""
    if not events:
        return {"inserted": 0, "updated": 0}
    
    conn = get_db_connection()
    if not conn:
        return {"error": "No se pudo conectar a la base de datos"}
    
    cursor = conn.cursor()
    inserted, updated = 0, 0
    
    try:
        for event in events:
            cursor.execute(
                "SELECT id FROM cloudtrail_events WHERE event_id = %s",
                (event["eventId"],)
            )
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute(
                    """
                    UPDATE cloudtrail_events 
                    SET event_time = %s, event_name = %s, user_name = %s, 
                        resource_name = %s, region = %s, changes = %s,
                        updated_at = NOW()
                    WHERE event_id = %s
                    """,
                    (
                        event["eventTime"],
                        event["eventName"],
                        event["userName"],
                        event["resourceName"],
                        event["region"],
                        json.dumps(event["changes"]),
                        event["eventId"]
                    )
                )
                updated += 1
            else:
                cursor.execute(
                    """
                    INSERT INTO cloudtrail_events 
                    (event_id, event_time, event_name, user_name, resource_name, region, changes, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                    """,
                    (
                        event["eventId"],
                        event["eventTime"],
                        event["eventName"],
                        event["userName"],
                        event["resourceName"],
                        event["region"],
                        json.dumps(event["changes"])
                    )
                )
                inserted += 1
        
        conn.commit()
        return {"inserted": inserted, "updated": updated}
        
    except Exception as e:
        conn.rollback()
        print(f"Error al insertar/actualizar eventos: {str(e)}")
        return {"error": str(e), "inserted": inserted, "updated": updated}
        
    finally:
        cursor.close()
        conn.close()