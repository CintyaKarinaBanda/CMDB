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
    """Extrae el ID de instancia de un evento CloudTrail de manera exhaustiva."""
    # Función para buscar IDs de instancia en cualquier estructura de datos
    def find_instance_ids(obj, path=""):
        if not obj:
            return []
            
        found_ids = []
        
        # Si es un diccionario, buscar en sus claves y valores
        if isinstance(obj, dict):
            # Buscar directamente en claves específicas
            for key in ["instanceId", "resourceId", "resourceName", "instancesSet"]:
                if key in obj and obj[key] and isinstance(obj[key], str) and obj[key].startswith("i-"):
                    found_ids.append((obj[key], f"{path}.{key}"))
            
            # Buscar recursivamente en todos los valores
            for key, value in obj.items():
                found_ids.extend(find_instance_ids(value, f"{path}.{key}"))
                
        # Si es una lista, buscar en cada elemento
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                found_ids.extend(find_instance_ids(item, f"{path}[{i}]"))
                
        # Si es un string, verificar si es un ID de instancia
        elif isinstance(obj, str) and obj.startswith("i-"):
            found_ids.append((obj, path))
            
        return found_ids
    
    # Buscar en lugares específicos primero (búsqueda directa)
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    direct_paths = [
        req.get("instanceId"),
        req.get("resourceId"),
        req.get("instancesSet", {}).get("items", [{}])[0].get("instanceId") if req.get("instancesSet") else None,
        req.get("resourcesSet", {}).get("items", [{}])[0].get("resourceId") if req.get("resourcesSet") else None,
        res.get("instanceId"),
        res.get("instancesSet", {}).get("items", [{}])[0].get("instanceId") if res.get("instancesSet") else None,
        res.get("instances", [{}])[0].get("instanceId") if res.get("instances") else None
    ]
    
    # Verificar resultados de búsqueda directa
    for path in direct_paths:
        if path and isinstance(path, str) and path.startswith("i-"):
            return path
    
    # Si no se encuentra en las rutas directas, hacer una búsqueda exhaustiva
    all_ids = find_instance_ids(req, "requestParameters") + find_instance_ids(res, "responseElements")
    
    # Si se encontraron IDs, devolver el primero
    if all_ids:
        print(f"[CloudTrail] ID de instancia encontrado en ruta no estándar: {all_ids[0][1]}")
        return all_ids[0][0]
    
    # Buscar en el evento completo como último recurso
    all_ids = find_instance_ids(event, "root")
    if all_ids:
        print(f"[CloudTrail] ID de instancia encontrado en evento completo: {all_ids[0][1]}")
        return all_ids[0][0]
    
    # Si aún no se encuentra, intentar extraer de ARNs o recursos relacionados
    resources = event.get("resources", [])
    for resource in resources:
        resource_type = resource.get("type")
        resource_name = resource.get("ARN") or resource.get("resourceName")
        
        if resource_type == "AWS::EC2::Instance" and resource_name:
            # Extraer ID de instancia del ARN o nombre
            if isinstance(resource_name, str):
                parts = resource_name.split("/")
                if len(parts) > 1 and parts[-1].startswith("i-"):
                    return parts[-1]
    
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
        
        # Añadir solo los valores no vacíos
        for key, value in candidates.items():
            if value:
                changes["details"][key] = value
    
    # Si aún no hay detalles, devolver el evento completo como último recurso
    if not changes["details"]:
        # Combinar requestParameters y responseElements
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
    
    # Configuración
    start_time = datetime.utcnow() - timedelta(days=3)  # Aumentado a 3 días para capturar más eventos
    max_events = 500  # Aumentado el límite de eventos
    max_api_calls = 5  # Aumentado el límite de llamadas API
    
    try:
        client = create_aws_client("cloudtrail", region, credentials)
        if not client:
            return {"error": "Error al crear cliente CloudTrail", "events": []}

        # Obtener eventos
        all_events = []
        next_token = None
        
        for call_num in range(1, max_api_calls + 1):
            try:
                # Usar filtros más específicos para obtener eventos relevantes
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
        
        for raw_event in all_events:
            try:
                # Extraer detalles del evento
                detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                event_name = detail.get("eventName")
                
                # Verificar si es un evento importante
                if event_name not in IMPORTANT_EC2_EVENTS:
                    skipped_events += 1
                    continue
                
                # Extraer información de identidad
                user_identity = detail.get("userIdentity", {})
                session_context = user_identity.get("sessionContext", {})
                session_issuer = session_context.get("sessionIssuer", {})
                
                # Determinar nombre de usuario con más opciones
                user_name_options = [
                    raw_event.get("Username"),
                    user_identity.get("userName"),
                    user_identity.get("principalId"),
                    session_issuer.get("userName"),
                    user_identity.get("arn", "").split("/")[-1] if user_identity.get("arn") else None,
                    user_identity.get("type")
                ]
                
                user_name = next((name for name in user_name_options if name), "unknown")
                
                # Extraer ID de recurso
                resource_name = extract_instance_id(detail)
                if resource_name == "unknown":
                    unknown_resources += 1
                
                # Extraer cambios detallados
                changes = extract_changes(detail)
                
                # Crear evento procesado
                parsed_event = {
                    "event_id": raw_event.get("EventId"),
                    "event_time": raw_event.get("EventTime"),
                    "event_name": event_name,
                    "event_source": detail.get("eventSource", "unknown"),
                    "user_name": user_name,
                    "resource_name": resource_name,
                    "changes": changes,
                    "region": region,
                    "raw_event": detail  # Incluir el evento completo para referencia
                }
                
                parsed_events.append(parsed_event)
                
            except Exception as e:
                print(f"[CloudTrail] Error al procesar evento: {str(e)}")
                continue
        
        print(f"[CloudTrail] Eventos procesados: {len(parsed_events)}")
        print(f"[CloudTrail] Eventos omitidos: {skipped_events}")
        print(f"[CloudTrail] Recursos desconocidos: {unknown_resources}")
        
        return {"events": parsed_events}
        
    except Exception as e:
        print(f"[CloudTrail] Error general: {str(e)}")
        return {"error": str(e), "events": []}

def insert_or_update_cloudtrail_events(events, region, credentials):
    """Inserta o actualiza eventos de CloudTrail en la base de datos."""
    conn = get_db_connection()
    if not conn:
        return {"error": "Error al conectar a la base de datos", "inserted": 0, "processed": 0}

    start_time = datetime.utcnow() - timedelta(days=7)
    inserted, processed = 0, 0

    try:
        # Obtener eventos existentes
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id_event, event_time FROM ec2_cloudtrail_events WHERE event_time >= %s", 
                (start_time,)
            )
            existing_keys = {f"{row[0]}_{row[1].isoformat()}" for row in cursor.fetchall()}

        # Insertar nuevos eventos
        with conn.cursor() as cursor:
            for event in events:
                processed += 1
                key = f"{event['event_id']}_{event['event_time'].isoformat()}"
                
                if key in existing_keys:
                    continue

                cursor.execute("""
                    INSERT INTO ec2_cloudtrail_events (
                        id_event, event_name, event_time, user_name,
                        event_source, resource_name, changes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    event["event_id"], event["event_name"], event["event_time"],
                    event["user_name"], event["event_source"], event["resource_name"],
                    json.dumps(event["changes"])
                ))
                inserted += 1

        conn.commit()
        return {"inserted": inserted, "processed": processed}

    except Exception as e:
        conn.rollback()
        return {"error": str(e), "inserted": inserted, "processed": processed}

    finally:
        conn.close()