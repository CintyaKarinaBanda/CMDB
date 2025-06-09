# Servicios/cloudtrail_functions.py
import json
from datetime import datetime, timedelta
from Servicios.utils import create_aws_client, get_db_connection

IMPORTANT_EC2_EVENTS = {
    "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances",
    "ModifyInstanceAttribute", "CreateTags", "DeleteTags", "RunInstances",
    "AttachVolume", "DetachVolume", "ModifyVolume", "AssociateAddress",
    "DisassociateAddress", "AssignPrivateIpAddresses", "UnassignPrivateIpAddresses",
    "ModifyInstanceCreditSpecification", "ModifyInstancePlacement",
    "ModifyInstanceMetadataOptions", "ModifyInstanceCapacityReservationAttributes"
}

RESOURCE_PREFIXES = ("i-", "vol-", "snap-", "eni-", "ami-")

def is_resource_id(value):
    return isinstance(value, str) and value.startswith(RESOURCE_PREFIXES)

def extract_instance_id(event):
    """Extrae el ID de recurso de un evento CloudTrail."""
    event_name = event.get("eventName", "")
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    # Casos específicos
    if event_name == "CreateTags":
        for resource in req.get("resourcesSet", {}).get("items", []):
            if is_resource_id(resource.get("resourceId")):
                return resource["resourceId"]
    
    if event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
        for instance in (req.get("instancesSet", {}) or res.get("instancesSet", {}).get("items", [])):
            if is_resource_id(instance.get("instanceId")):
                return instance["instanceId"]
    
    if event_name == "ModifyInstanceAttribute" and is_resource_id(req.get("instanceId")):
        return req["instanceId"]
    
    if event_name in ["AttachVolume", "DetachVolume", "ModifyVolume"]:
        if is_resource_id(req.get("instanceId") or res.get("instanceId")):
            return req.get("instanceId") or res.get("instanceId")
        if is_resource_id(req.get("volumeId") or res.get("volumeId")):
            return req.get("volumeId") or res.get("volumeId")
    
    # Búsqueda exhaustiva
    def find_ids(obj):
        if isinstance(obj, dict):
            for key in ["instanceId", "resourceId", "volumeId", "snapshotId", "networkInterfaceId"]:
                if is_resource_id(obj.get(key)):
                    return obj[key]
            for value in obj.values():
                if (found := find_ids(value)):
                    return found
        elif isinstance(obj, list):
            for item in obj:
                if (found := find_ids(item)):
                    return found
        elif is_resource_id(obj):
            return obj
        return None
    
    if (found := find_ids(req) or find_ids(res)):
        return found
    
    # Último recurso: buscar en resources
    for resource in event.get("resources", []):
        if (arn := resource.get("ARN")) and "/" in arn:
            last_part = arn.split("/")[-1]
            if is_resource_id(last_part):
                return last_part
    
    return "unknown"

def extract_changes(event):
    """Extrae información detallada de cambios de un evento CloudTrail."""
    event_name = event.get("eventName", "")
    req, res = event.get("requestParameters", {}), event.get("responseElements", {})
    changes = {"eventType": event_name, "details": {}}
    
    # Procesamiento específico por tipo de evento
    if event_name == "RunInstances" and (instances := res.get("instancesSet", {}).get("items")):
        instance = instances[0]
        changes["details"].update({
            "instanceType": instance.get("instanceType"),
            "imageId": instance.get("imageId"),
            "subnetId": instance.get("subnetId"),
            "vpcId": instance.get("vpcId"),
            "privateIpAddress": instance.get("privateIpAddress"),
            "keyName": instance.get("keyName")
        })
        if (tags := instance.get("tagSet", {}).get("items")):
            changes["details"]["tags"] = {t["key"]: t["value"] for t in tags if "key" in t and "value" in t}
    
    elif event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"] and (instances := res.get("instancesSet", {}).get("items")):
        changes["details"]["stateChanges"] = [{
            "instanceId": i.get("instanceId"),
            "previousState": i.get("previousState", {}).get("name"),
            "currentState": i.get("currentState", {}).get("name")
        } for i in instances]
    
    elif event_name == "ModifyInstanceAttribute":
        changes["details"].update({k: v for k, v in req.items() if k not in ["instanceId", "attribute", "value"]})
    
    elif event_name in ["CreateTags", "DeleteTags"] and (tags := req.get("tagSet", {}).get("items")):
        changes["details"]["tags"] = {t["key"]: t["value"] for t in tags if "key" in t and "value" in t}
        if (resources := req.get("resourcesSet", {}).get("items")):
            changes["details"]["resources"] = [r.get("resourceId") for r in resources]
    
    elif event_name in ["AttachVolume", "DetachVolume"]:
        changes["details"].update({
            "volumeId": req.get("volumeId"),
            "instanceId": req.get("instanceId"),
            "device": req.get("device")
        })
    
    # Si no hay detalles, añadir información genérica
    if not changes["details"]:
        candidates = {
            "tagSet": (req.get("tagSet", {}) or res.get("tagSet", {})).get("items"),
            "volumeId": req.get("volumeId") or res.get("volumeId"),
            "instanceType": req.get("instanceType") or res.get("instanceType"),
            "instanceState": req.get("instanceState") or res.get("instanceState"),
            "stateChange": {"previous": res.get("previousState"), "current": res.get("currentState")}
        }
        changes["details"].update({k: v for k, v in candidates.items() if v})
    
    # Si aún no hay detalles, devolver el evento completo
    if not changes["details"]:
        combined = {}
        if req: combined["requestParameters"] = req
        if res: combined["responseElements"] = res
        changes["details"] = combined or {"raw": "No se pudieron extraer detalles específicos"}
    
    return changes

def get_ec2_cloudtrail_events(region, credentials):
    """Obtiene eventos de CloudTrail relacionados con instancias EC2 del último día."""
    try:
        if not (client := create_aws_client("cloudtrail", region, credentials)):
            return {"error": "Error al crear cliente CloudTrail", "events": []}

        all_events, next_token = [], None
        start_time = datetime.utcnow() - timedelta(days=1)
        
        for _ in range(5):  # Máximo 5 llamadas API
            try:
                response = client.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "ec2.amazonaws.com"}],
                    StartTime=start_time, EndTime=datetime.utcnow(), MaxResults=100,
                    **({"NextToken": next_token} if next_token else {})
                )
                
                all_events.extend(response.get("Events", []))
                if not (next_token := response.get("NextToken")) or len(all_events) >= 500:
                    break
            except Exception as e:
                print(f"Error CloudTrail API: {str(e)}")
                break
        
        # Procesar eventos
        parsed_events, processed_ids = [], set()
        for raw_event in all_events:
            if not (event_id := raw_event.get("EventId")) or event_id in processed_ids:
                continue
            
            try:
                detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                if (event_name := detail.get("eventName")) not in IMPORTANT_EC2_EVENTS:
                    continue
                
                # Extraer usuario
                user_identity = detail.get("userIdentity", {})
                session_issuer = user_identity.get("sessionContext", {}).get("sessionIssuer", {})
                user_name = next(
                    (name for name in [
                        raw_event.get("Username"),
                        user_identity.get("userName"),
                        user_identity.get("principalId"),
                        session_issuer.get("userName"),
                        user_identity.get("arn", "").split("/")[-1] if user_identity.get("arn") else None,
                        user_identity.get("type")
                    ] if name), "unknown")
                
                # Extraer y validar recurso
                if not (resource_name := extract_instance_id(detail)).startswith("i-"):
                    continue
                
                # Extraer cambios
                changes = extract_changes(detail)
                if event_name == "CreateTags" and isinstance(changes, dict) and (resources := detail.get("requestParameters", {}).get("resourcesSet", {}).get("items")):
                    changes["details"]["resources"] = [r.get("resourceId") for r in resources if r.get("resourceId", "").startswith("i-")]
                
                parsed_events.append({
                    "event_id": event_id,
                    "event_time": raw_event.get("EventTime"),
                    "event_name": event_name,
                    "event_source": detail.get("eventSource", "unknown"),
                    "user_name": user_name,
                    "resource_name": resource_name,
                    "changes": changes,
                    "region": region
                })
                processed_ids.add(event_id)
            except Exception:
                continue
        
        print(f"CloudTrail: {len(parsed_events)} eventos de instancias EC2 encontrados en {region}")
        return {"events": parsed_events}
    except Exception as e:
        print(f"[CloudTrail] Error general: {str(e)}")
        return {"error": str(e), "events": []}

def insert_or_update_cloudtrail_events(events, resource_category = 'EC2'):
    """Inserta eventos de CloudTrail en la base de datos evitando duplicados."""
    if not (conn := get_db_connection()):
        return {"error": "Error al conectar a la base de datos", "inserted": 0}

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_event FROM cloudtrail_events")
            existing_ids = {row[0] for row in cursor.fetchall()}
            
            to_insert = [
                resource_category,
                (e["event_id"], e["event_name"], e["event_time"], e["user_name"],
                e["event_source"], e["resource_name"], json.dumps(e["changes"]))
                for e in events
                if e["event_id"] not in existing_ids and e["resource_name"].startswith("i-")
            ]
            
            if to_insert:
                cursor.executemany("""
                    INSERT INTO ec2_cloudtrail_events
                    (resource_category, id_event, event_name, event_time, user_name, event_source, resource_name, changes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, to_insert)
                inserted = cursor.rowcount
                conn.commit()
                print(f"CloudTrail DB: {inserted} nuevos eventos insertados")
                return {"inserted": inserted}
            return {"inserted": 0}
    except Exception as e:
        conn.rollback()
        print(f"Error DB: {str(e)}")
        return {"error": str(e)}
    finally:
        conn.close()