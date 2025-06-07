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
    """Extrae el ID de instancia de un evento CloudTrail."""
    paths = [
        event.get("requestParameters", {}).get("instanceId"),
        event.get("requestParameters", {}).get("resourcesSet", {}).get("items", [{}])[0].get("resourceId"),
        event.get("requestParameters", {}).get("instancesSet", {}).get("items", [{}])[0].get("instanceId"),
        event.get("responseElements", {}).get("instanceId"),
        event.get("responseElements", {}).get("instancesSet", {}).get("items", [{}])[0].get("instanceId"),
        event.get("responseElements", {}).get("instances", [{}])[0].get("instanceId")
    ]
    
    for path in paths:
        if path and isinstance(path, str) and path.startswith("i-"):
            return path
    
    return "unknown"

def extract_changes(event):
    """Extrae información de cambios de un evento CloudTrail."""
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    # Lista de posibles ubicaciones de datos de cambios
    candidates = [
        req.get("tagSet", {}).get("items"),
        res.get("tagSet", {}).get("items"),
        req.get("volumeId"), res.get("volumeId"),
        req.get("instanceType"), res.get("instanceType"),
        req.get("instanceState"), res.get("instanceState"),
        res.get("currentState"), res.get("previousState")
    ]
    
    # Buscar en instancias
    for container in [req, res]:
        instances = container.get("instances", [{}])
        if instances and len(instances) > 0:
            candidates.extend([
                instances[0].get("tagSet", {}).get("items"),
                instances[0].get("blockDeviceMapping"),
                instances[0].get("imageId"),
                instances[0].get("instanceType")
            ])
    
    # Buscar en instancesSet
    for container in [req, res]:
        items = container.get("instancesSet", {}).get("items", [{}])
        if items and len(items) > 0:
            candidates.extend([
                items[0].get("currentState"),
                items[0].get("previousState"),
                items[0].get("instanceId")
            ])
    
    # Retornar el primer valor no vacío
    for candidate in candidates:
        if candidate:
            return candidate
    
    return "unknown"

def get_ec2_cloudtrail_events(region, credentials):
    """Obtiene eventos de CloudTrail relacionados con EC2."""
    print(f"[CloudTrail] Consultando región {region}")
    
    # Configuración
    start_time = datetime.utcnow() - timedelta(days=1)  # Solo 1 día para reducir carga
    max_events = 200  # Límite de eventos
    max_api_calls = 3  # Límite de llamadas API
    
    try:
        client = create_aws_client("cloudtrail", region, credentials)
        if not client:
            return {"error": "Error al crear cliente CloudTrail", "events": []}

        # Obtener eventos
        all_events = []
        next_token = None
        
        for call_num in range(1, max_api_calls + 1):
            try:
                response = client.lookup_events(
                    LookupAttributes=[{
                        "AttributeKey": "EventSource",
                        "AttributeValue": "ec2.amazonaws.com"
                    }],
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
        
        # Procesar eventos
        parsed_events = []
        for raw_event in all_events:
            try:
                detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                event_name = detail.get("eventName")
                
                if event_name not in IMPORTANT_EC2_EVENTS:
                    continue
                    
                user_identity = detail.get("userIdentity", {})
                session_issuer = user_identity.get("sessionContext", {}).get("sessionIssuer", {})
                
                # Determinar nombre de usuario
                user_name = (raw_event.get("Username") or 
                            user_identity.get("userName") or 
                            user_identity.get("principalId") or 
                            session_issuer.get("userName") or 
                            "unknown")
                
                parsed_events.append({
                    "event_id": raw_event.get("EventId"),
                    "event_time": raw_event.get("EventTime"),
                    "event_name": event_name,
                    "event_source": detail.get("eventSource", "unknown"),
                    "user_name": user_name,
                    "resource_name": extract_instance_id(detail),
                    "changes": extract_changes(detail)
                })
            except Exception:
                continue
                
        print(f"[CloudTrail] {len(parsed_events)} eventos importantes procesados")
        return {"events": parsed_events}
        
    except Exception as e:
        print(f"[CloudTrail] Error: {str(e)}")
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