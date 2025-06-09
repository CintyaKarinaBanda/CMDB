# Servicios/cloudtrail_functions.py
import json
from datetime import datetime, timedelta
from Servicios.utils import create_aws_client, get_db_connection

# Eventos importantes de EC2 que queremos rastrear
IMPORTANT_EC2_EVENTS = {
    "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances", 
    "ModifyInstanceAttribute", "CreateTags", "DeleteTags", "RunInstances", 
    "AttachVolume", "DetachVolume", "ModifyVolume", "AssociateAddress", 
    "DisassociateAddress", "AssignPrivateIpAddresses", "UnassignPrivateIpAddresses",
    "ModifyInstanceCreditSpecification", "ModifyInstancePlacement", 
    "ModifyInstanceMetadataOptions", "ModifyInstanceCapacityReservationAttributes"
}

def extract_instance_id(event):
    event_name = event.get("eventName", "")
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    if event_name == "CreateTags":
        resources_set = req.get("resourcesSet", {}).get("items", [])
        if resources_set:
            for resource in resources_set:
                resource_id = resource.get("resourceId")
                if resource_id:
                    if (resource_id.startswith("i-") or 
                        resource_id.startswith("vol-") or 
                        resource_id.startswith("snap-") or 
                        resource_id.startswith("eni-") or
                        resource_id.startswith("ami-")):
                        return resource_id
    
    instance_events = ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]
    if event_name in instance_events:
        instances = req.get("instancesSet", {}).get("items", []) or res.get("instancesSet", {}).get("items", [])
        if instances and len(instances) > 0:
            for instance in instances:
                instance_id = instance.get("instanceId")
                if instance_id and instance_id.startswith("i-"):
                    return instance_id
    
    if event_name == "ModifyInstanceAttribute":
        instance_id = req.get("instanceId")
        if instance_id and instance_id.startswith("i-"):
            return instance_id
    
    volume_events = ["AttachVolume", "DetachVolume", "ModifyVolume"]
    if event_name in volume_events:
        instance_id = req.get("instanceId") or res.get("instanceId")
        if instance_id and instance_id.startswith("i-"):
            return instance_id
        
        volume_id = req.get("volumeId") or res.get("volumeId")
        if volume_id and volume_id.startswith("vol-"):
            return volume_id
    
    def find_resource_ids(obj, path=""):
        if not obj:
            return []
            
        found_ids = []
        
        # Si es un diccionario, buscar en sus claves y valores
        if isinstance(obj, dict):
            # Buscar directamente en claves específicas
            for key in ["instanceId", "resourceId", "volumeId", "snapshotId", "networkInterfaceId"]:
                if key in obj and obj[key] and isinstance(obj[key], str):
                    value = obj[key]
                    if (value.startswith("i-") or value.startswith("vol-") or 
                        value.startswith("snap-") or value.startswith("eni-") or
                        value.startswith("ami-")):
                        found_ids.append((value, f"{path}.{key}"))
            
            # Buscar recursivamente en todos los valores
            for key, value in obj.items():
                found_ids.extend(find_resource_ids(value, f"{path}.{key}"))
                
        # Si es una lista, buscar en cada elemento
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                found_ids.extend(find_resource_ids(item, f"{path}[{i}]"))
                
        # Si es un string, verificar si es un ID de recurso
        elif isinstance(obj, str):
            if (obj.startswith("i-") or obj.startswith("vol-") or 
                obj.startswith("snap-") or obj.startswith("eni-") or
                obj.startswith("ami-")):
                found_ids.append((obj, path))
            
        return found_ids
    
    # Buscar en lugares específicos primero (búsqueda directa)
    direct_paths = [
        req.get("instanceId"),
        req.get("resourceId"),
        req.get("volumeId"),
        req.get("snapshotId"),
        req.get("networkInterfaceId"),
        res.get("instanceId"),
        res.get("volumeId"),
        res.get("snapshotId"),
        res.get("networkInterfaceId")
    ]
    
    # Verificar resultados de búsqueda directa
    for path in direct_paths:
        if path and isinstance(path, str):
            if (path.startswith("i-") or path.startswith("vol-") or 
                path.startswith("snap-") or path.startswith("eni-") or
                path.startswith("ami-")):
                return path
    
    # Si no se encuentra en las rutas directas, hacer una búsqueda exhaustiva
    all_ids = find_resource_ids(req, "requestParameters") + find_resource_ids(res, "responseElements")
    
    # Si se encontraron IDs, devolver el primero
    if all_ids:
        return all_ids[0][0]
    
    # Buscar en el evento completo como último recurso
    all_ids = find_resource_ids(event, "root")
    if all_ids:
        return all_ids[0][0]
    
    # Si aún no se encuentra, intentar extraer de resources
    resources = event.get("resources", [])
    for resource in resources:
        resource_name = resource.get("ARN") or resource.get("resourceName")
        
        if resource_name and isinstance(resource_name, str):
            # Extraer ID del recurso del ARN o nombre
            parts = resource_name.split("/")
            if len(parts) > 1:
                last_part = parts[-1]
                if (last_part.startswith("i-") or last_part.startswith("vol-") or 
                    last_part.startswith("snap-") or last_part.startswith("eni-") or
                    last_part.startswith("ami-")):
                    return last_part
    
    return "unknown"

def extract_changes(event):
    """Extrae información detallada de cambios de un evento CloudTrail."""
    # Extraer información del evento
    event_name = event.get("eventName", "")
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    # Crear un diccionario para almacenar los cambios
    changes = {
        "eventType": event_name,
        "details": {}
    }
    
    # Función para extraer cambios según el tipo de evento
    def extract_by_event_type():
        # RunInstances (creación de instancia)
        if event_name == "RunInstances":
            # Extraer detalles de la instancia creada
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
                
                # Extraer tags si existen
                if "tagSet" in instance:
                    tags = {}
                    for tag_item in instance.get("tagSet", {}).get("items", []):
                        if "key" in tag_item and "value" in tag_item:
                            tags[tag_item["key"]] = tag_item["value"]
                    if tags:
                        changes["details"]["tags"] = tags
            
            return
            
        # StartInstances, StopInstances, RebootInstances, TerminateInstances
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
            return
            
        # ModifyInstanceAttribute
        elif event_name == "ModifyInstanceAttribute":
            # Identificar qué atributo se modificó
            for key, value in req.items():
                if key not in ["instanceId", "attribute", "value"]:
                    changes["details"][key] = value
            return
            
        # CreateTags, DeleteTags
        elif event_name in ["CreateTags", "DeleteTags"]:
            tag_items = req.get("tagSet", {}).get("items", [])
            if tag_items:
                tags = {}
                for tag_item in tag_items:
                    if "key" in tag_item and "value" in tag_item:
                        tags[tag_item["key"]] = tag_item["value"]
                changes["details"]["tags"] = tags
                
                # Extraer recursos afectados
                resources = []
                for resource_item in req.get("resourcesSet", {}).get("items", []):
                    resources.append(resource_item.get("resourceId"))
                if resources:
                    changes["details"]["resources"] = resources
            return
            
        # AttachVolume, DetachVolume
        elif event_name in ["AttachVolume", "DetachVolume"]:
            changes["details"].update({
                "volumeId": req.get("volumeId"),
                "instanceId": req.get("instanceId"),
                "device": req.get("device")
            })
            return
    
    # Extraer cambios específicos según el tipo de evento
    extract_by_event_type()
    
    # Si no se encontraron detalles específicos, buscar en lugares comunes
    if not changes["details"]:
        # Lista de posibles ubicaciones de datos de cambios
        candidates = {
            "tagSet": req.get("tagSet", {}).get("items") or res.get("tagSet", {}).get("items"),
            "volumeId": req.get("volumeId") or res.get("volumeId"),
            "instanceType": req.get("instanceType") or res.get("instanceType"),
            "instanceState": req.get("instanceState") or res.get("instanceState"),
            "stateChange": {
                "previous": res.get("previousState"),
                "current": res.get("currentState")
            }
        }
        
        for key, value in candidates.items():
            if value:
                changes["details"][key] = value
    
    if not changes["details"]:
        combined = {}
        if req:
            combined["requestParameters"] = req
        if res:
            combined["responseElements"] = res
        
        if combined:
            changes["details"] = combined
        else:
            changes["details"] = {"raw": "No se pudieron extraer detalles específicos"}
    
    return changes

def get_ec2_cloudtrail_events(region, credentials):
    """Obtiene eventos de CloudTrail relacionados con EC2 con búsqueda exhaustiva."""
    print(f"[CloudTrail] Consultando región {region}")
    
    start_time = datetime.utcnow() - timedelta(days=3)  
    max_events = 500 
    max_api_calls = 5  
    
    try:
        client = create_aws_client("cloudtrail", region, credentials)
        if not client:
            return {"error": "Error al crear cliente CloudTrail", "events": []}

        all_events = []
        next_token = None
        
        for call_num in range(1, max_api_calls + 1):
            try:
                lookup_attrs = [
                    {
                        "AttributeKey": "EventSource",
                        "AttributeValue": "ec2.amazonaws.com"
                    }
                ]
                
                response = client.lookup_events(
                    LookupAttributes=lookup_attrs,
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
        
        # Procesar eventos
        parsed_events = []
        skipped_events = 0
        unknown_resources = 0
        non_instance_resources = 0
        
        processed_event_ids = set()
        
        for raw_event in all_events:
            try:
                event_id = raw_event.get("EventId")
                
                if event_id in processed_event_ids:
                    skipped_events += 1
                    continue
                
                detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                event_name = detail.get("eventName")
                
                if event_name not in IMPORTANT_EC2_EVENTS:
                    skipped_events += 1
                    continue
                
                user_identity = detail.get("userIdentity", {})
                session_context = user_identity.get("sessionContext", {})
                session_issuer = session_context.get("sessionIssuer", {})
                
                user_name_options = [
                    raw_event.get("Username"),
                    user_identity.get("userName"),
                    user_identity.get("principalId"),
                    session_issuer.get("userName"),
                    user_identity.get("arn", "").split("/")[-1] if user_identity.get("arn") else None,
                    user_identity.get("type")
                ]
                
                user_name = next((name for name in user_name_options if name), "unknown")
                
                resource_name = extract_instance_id(detail)
                
                if event_name == "CreateTags" and resource_name == "unknown":
                    req = detail.get("requestParameters", {})
                    resources_set = req.get("resourcesSet", {}).get("items", [])
                    if resources_set and len(resources_set) > 0:
                        resource_id = resources_set[0].get("resourceId")
                        if resource_id:
                            resource_name = resource_id
                
                if not resource_name.startswith("i-"):
                    non_instance_resources += 1
                    continue
                
                if resource_name == "unknown":
                    unknown_resources += 1
                
                changes = extract_changes(detail)
                
                if event_name == "CreateTags" and isinstance(changes, dict):
                    req = detail.get("requestParameters", {})
                    resources_set = req.get("resourcesSet", {}).get("items", [])
                    if resources_set:
                        resources = []
                        for resource in resources_set:
                            resource_id = resource.get("resourceId")
                            if resource_id and resource_id.startswith("i-"):
                                resources.append(resource_id)
                        
                        if resources and "details" in changes:
                            changes["details"]["resources"] = resources
                
                parsed_event = {
                    "event_id": event_id,
                    "event_time": raw_event.get("EventTime"),
                    "event_name": event_name,
                    "event_source": detail.get("eventSource", "unknown"),
                    "user_name": user_name,
                    "resource_name": resource_name,
                    "changes": changes,
                    "region": region
                }
                
                parsed_events.append(parsed_event)
                
                processed_event_ids.add(event_id)
                
            except Exception as e:
                print(f"[CloudTrail] Error al procesar evento: {str(e)}")
                continue
        
        print(f"[CloudTrail] Eventos procesados: {len(parsed_events)}")
        print(f"[CloudTrail] Eventos omitidos: {skipped_events}")
        print(f"[CloudTrail] Recursos no instancia: {non_instance_resources}")
        print(f"[CloudTrail] Recursos desconocidos: {unknown_resources}")
        
        return {"events": parsed_events}
        
    except Exception as e:
        print(f"[CloudTrail] Error general: {str(e)}")
        return {"error": str(e), "events": []}

def insert_or_update_cloudtrail_events(events, resource_category='EC2'):
    conn = get_db_connection()
    if not conn:
        return {"error": "Error al conectar a la base de datos", "inserted": 0, "processed": 0}

    start_time = datetime.utcnow() - timedelta(days=7)
    inserted, processed, skipped = 0, 0, 0

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id_event FROM cloudtrail_events"
            )
            existing_event_ids = {row[0] for row in cursor.fetchall()}

        with conn.cursor() as cursor:
            for event in events:
                processed += 1
                event_id = event["event_id"]
                
                if event_id in existing_event_ids:
                    skipped += 1
                    continue
                
                resource_name = event["resource_name"]
                if not resource_name.startswith("i-"):
                    skipped += 1
                    continue

                cursor.execute("""
                    INSERT INTO cloudtrail_events (
                        resource_category, event_id, event_name, event_time, user_name,
                        event_source, resource_name, changes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    resource_category, event_id, event["event_name"], event["event_time"],
                    event["user_name"], event["event_source"], resource_name,
                    json.dumps(event["changes"])
                ))
                inserted += 1
                existing_event_ids.add(event_id)  
                
        conn.commit()
        print(f"[CloudTrail DB] Procesados: {processed}, Insertados: {inserted}, Omitidos: {skipped}")
        return {"inserted": inserted, "processed": processed, "skipped": skipped}

    except Exception as e:
        conn.rollback()
        print(f"[CloudTrail DB] Error: {str(e)}")
        return {"error": str(e), "inserted": inserted, "processed": processed, "skipped": skipped}

    finally:
        conn.close()