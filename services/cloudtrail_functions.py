# Servicios/cloudtrail_functions.py
import json
from datetime import datetime, timedelta
from services.utils import create_aws_client, get_db_connection

# Eventos importantes que queremos rastrear por servicio
IMPORTANT_EVENTS = {
    "EC2": {
        "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances", 
        "ModifyInstanceAttribute", "CreateTags", "DeleteTags", "RunInstances", 
        "AttachVolume", "DetachVolume"
    },
    "RDS": {
        "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance", "RebootDBInstance",
        "StartDBInstance", "StopDBInstance", "RestoreDBInstanceFromDBSnapshot",
        "CreateDBSnapshot", "DeleteDBSnapshot", "AddTagsToResource", "RemoveTagsFromResource"
    },
    "VPC": {
        "CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "CreateSubnet", "DeleteSubnet", 
        "ModifySubnetAttribute", "CreateRouteTable", "DeleteRouteTable", "CreateRoute", 
        "DeleteRoute", "CreateInternetGateway", "DeleteInternetGateway", "AttachInternetGateway", 
        "DetachInternetGateway", "CreateNatGateway", "DeleteNatGateway"
    },
    "SUBNET": {
        "CreateSubnet", "DeleteSubnet", "ModifySubnetAttribute", "CreateNetworkAcl", 
        "DeleteNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAclEntry", 
        "ReplaceNetworkAclAssociation", "CreateRoute", "DeleteRoute", "CreateRouteTable", 
        "DeleteRouteTable", "AssociateRouteTable", "DisassociateRouteTable"
    },
    "REDSHIFT": {
        "CreateCluster", "DeleteCluster", "ModifyCluster", "RebootCluster",
        "ResizeCluster", "PauseCluster", "ResumeCluster", "RestoreFromClusterSnapshot",
        "CreateClusterSnapshot", "DeleteClusterSnapshot", "CreateTags", "DeleteTags"
    }
}

# Mapeo de fuentes de eventos a tipos de recursos
EVENT_SOURCES = {
    "ec2.amazonaws.com": ["EC2", "VPC", "SUBNET"],
    "rds.amazonaws.com": ["RDS"],
    "redshift.amazonaws.com": ["REDSHIFT"]
}

def extract_resource_id(event, resource_type):
    """Extrae el ID del recurso del evento según el tipo."""
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    # Mapeo de campos comunes por tipo de recurso
    id_fields = {
        "EC2": ["instanceId", "resourceId"],
        "RDS": ["dBInstanceIdentifier", "dBSnapshotIdentifier"],
        "VPC": ["vpcId", "internetGatewayId", "natGatewayId"],
        "SUBNET": ["subnetId", "networkAclId", "routeTableId", "associationId"],
        "REDSHIFT": ["clusterIdentifier", "snapshotIdentifier"]
    }
    
    # Buscar en campos específicos según el tipo de recurso
    for field in id_fields.get(resource_type, []):
        if field in req:
            return req[field]
        
        # Buscar en respuesta para algunos campos
        if field in res:
            return res[field]
    
    # Casos especiales
    if resource_type == "EC2" and event.get("eventName") in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
        instances = req.get("instancesSet", {}).get("items", [])
        if instances and len(instances) > 0:
            return instances[0].get("instanceId", "unknown")
    
    # Buscar en estructuras anidadas
    nested_paths = {
        "VPC": [("vpc", "vpcId"), ("internetGateway", "internetGatewayId"), ("natGateway", "natGatewayId")],
        "SUBNET": [("subnet", "subnetId"), ("networkAcl", "networkAclId"), ("routeTable", "routeTableId")],
        "REDSHIFT": [("cluster", "clusterIdentifier"), ("snapshot", "snapshotIdentifier")]
    }
    
    for container, field in nested_paths.get(resource_type, []):
        if container in res and field in res[container]:
            return res[container][field]
    
    return "unknown"

def extract_changes(event, resource_type):
    """Extrae cambios relevantes del evento de forma simplificada."""
    event_name = event.get("eventName", "")
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    changes = {"eventType": event_name, "details": {}}
    
    # Extraer detalles básicos según el tipo de evento
    if resource_type == "EC2":
        if "instanceId" in req:
            changes["details"]["instanceId"] = req["instanceId"]
        if event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
            instances = res.get("instancesSet", {}).get("items", [])
            if instances:
                changes["details"]["state"] = instances[0].get("currentState", {}).get("name")
    
    elif resource_type == "RDS":
        if "dBInstanceIdentifier" in req:
            changes["details"]["dBInstanceIdentifier"] = req["dBInstanceIdentifier"]
        if event_name == "CreateDBInstance":
            for key in ["engine", "dbInstanceClass", "allocatedStorage", "multiAZ"]:
                if key in req:
                    changes["details"][key] = req[key]
    
    elif resource_type == "VPC":
        if "vpcId" in req:
            changes["details"]["vpcId"] = req["vpcId"]
        if event_name == "CreateVpc" and "cidrBlock" in req:
            changes["details"]["cidrBlock"] = req["cidrBlock"]
    
    elif resource_type == "SUBNET":
        if "subnetId" in req:
            changes["details"]["subnetId"] = req["subnetId"]
        if event_name == "CreateSubnet":
            for key in ["vpcId", "cidrBlock", "availabilityZone"]:
                if key in req:
                    changes["details"][key] = req[key]
    
    elif resource_type == "REDSHIFT":
        if "clusterIdentifier" in req:
            changes["details"]["clusterIdentifier"] = req["clusterIdentifier"]
        if event_name == "CreateCluster":
            for key in ["nodeType", "numberOfNodes", "databaseName"]:
                if key in req:
                    changes["details"][key] = req[key]
    
    # Extraer tags si existen
    if "tags" in req:
        changes["details"]["tags"] = req["tags"]
    
    return changes

def get_all_cloudtrail_events(region, credentials):
    """
    Obtiene todos los eventos importantes de CloudTrail en una sola llamada.
    Implementa paginación para obtener todos los eventos del día anterior.
    """
    try:
        client = create_aws_client("cloudtrail", region, credentials)
        if not client:
            return {"error": "Error al crear cliente CloudTrail", "events": []}

        # Configurar el rango de tiempo para obtener eventos del día anterior
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=1)
        
        all_parsed_events = []
        
        # Crear un conjunto con todos los eventos importantes
        all_important_events = set()
        for events in IMPORTANT_EVENTS.values():
            all_important_events.update(events)
        
        # Procesar cada fuente de eventos
        for event_source, resource_types in EVENT_SOURCES.items():
            next_token = None
            
            while True:
                # Preparar parámetros para la llamada a CloudTrail
                lookup_params = {
                    "LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": event_source}],
                    "StartTime": start_time,
                    "EndTime": end_time,
                    "MaxResults": 50
                }
                
                if next_token:
                    lookup_params["NextToken"] = next_token
                
                # Realizar la llamada a CloudTrail
                response = client.lookup_events(**lookup_params)
                events = response.get("Events", [])
                next_token = response.get("NextToken")
                
                # Procesar cada evento
                for raw_event in events:
                    try:
                        detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                        event_name = detail.get("eventName")
                        
                        # Verificar si es un evento importante
                        if event_name not in all_important_events:
                            continue
                        
                        # Determinar el tipo de recurso para este evento
                        resource_type = None
                        for rt in resource_types:
                            if event_name in IMPORTANT_EVENTS[rt]:
                                resource_type = rt
                                break
                        
                        if not resource_type:
                            continue
                        
                        # Obtener usuario
                        user_identity = detail.get("userIdentity", {})
                        user_name = user_identity.get("userName") or user_identity.get("principalId") or "unknown"
                        
                        # Obtener recurso afectado y cambios
                        resource_name = extract_resource_id(detail, resource_type)
                        changes = extract_changes(detail, resource_type)
                        
                        parsed_event = {
                            "event_id": raw_event.get("EventId"),
                            "event_time": raw_event.get("EventTime"),
                            "event_name": event_name,
                            "event_source": detail.get("eventSource", "unknown"),
                            "user_name": user_name,
                            "resource_name": resource_name,
                            "resource_type": resource_type,
                            "changes": changes,
                            "region": region
                        }
                        
                        all_parsed_events.append(parsed_event)
                        
                    except Exception as e:
                        print(f"[ERROR] Procesando evento: {str(e)}")
                
                # Salir del bucle si no hay más páginas
                if not next_token:
                    break
        
        return {"events": all_parsed_events}
        
    except Exception as e:
        print(f"[ERROR] CloudTrail: {str(e)}")
        return {"error": str(e), "events": []}

def insert_or_update_cloudtrail_events(events):
    """Inserta eventos de CloudTrail en la base de datos usando inserción por lotes."""
    if not events:
        return {"inserted": 0, "updated": 0}
    
    conn = get_db_connection()
    if not conn:
        return {"error": "No se pudo conectar a la base de datos"}
    
    cursor = conn.cursor()
    inserted = 0
    
    try:
        # Verificar si la tabla existe
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'cloudtrail_events'
            )
        """)
        table_exists = cursor.fetchone()[0]
        
        # Crear tabla si no existe
        if not table_exists:
            cursor.execute("""
                CREATE TABLE cloudtrail_events (
                    id SERIAL PRIMARY KEY,
                    event_id VARCHAR(255) UNIQUE,
                    event_time TIMESTAMP,
                    event_name VARCHAR(255),
                    event_source VARCHAR(255),
                    user_name VARCHAR(255),
                    resource_name VARCHAR(255),
                    resource_type VARCHAR(50),
                    region VARCHAR(50),
                    changes JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            conn.commit()
        
        # Insertar eventos en lotes para mejorar rendimiento
        batch_size = 100
        for i in range(0, len(events), batch_size):
            batch = events[i:i+batch_size]
            
            # Preparar valores para inserción por lotes
            values_list = []
            args_list = []
            
            for event in batch:
                try:
                    # Validar datos antes de insertar
                    event_id = event.get("event_id")
                    if not event_id:
                        continue
                        
                    values_list.append("(%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())")
                    args_list.extend([
                        event_id,
                        event.get("event_time"),
                        event.get("event_name"),
                        event.get("event_source", "unknown"),
                        event.get("user_name", "unknown"),
                        event.get("resource_name", "unknown"),
                        event.get("resource_type", "EC2"),
                        event.get("region", "unknown"),
                        json.dumps(event.get("changes", {}))
                    ])
                except Exception as e:
                    print(f"[ERROR] Preparando evento: {str(e)}")
            
            if values_list:
                try:
                    # Ejecutar inserción por lotes
                    sql = f"""
                    INSERT INTO cloudtrail_events 
                    (event_id, event_time, event_name, event_source, user_name, resource_name, 
                     resource_type, region, changes, created_at)
                    VALUES {", ".join(values_list)}
                    ON CONFLICT (event_id) DO NOTHING
                    """
                    cursor.execute(sql, args_list)
                    inserted += len(values_list)
                except Exception as e:
                    print(f"[ERROR] Inserción por lotes: {str(e)}")
                    # Si falla el lote, intentar insertar uno por uno
                    for j, event in enumerate(batch):
                        try:
                            cursor.execute(
                                """
                                INSERT INTO cloudtrail_events 
                                (event_id, event_time, event_name, event_source, user_name, resource_name, 
                                resource_type, region, changes, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                                ON CONFLICT (event_id) DO NOTHING
                                """,
                                (
                                    event.get("event_id"),
                                    event.get("event_time"),
                                    event.get("event_name"),
                                    event.get("event_source", "unknown"),
                                    event.get("user_name", "unknown"),
                                    event.get("resource_name", "unknown"),
                                    event.get("resource_type", "EC2"),
                                    event.get("region", "unknown"),
                                    json.dumps(event.get("changes", {}))
                                )
                            )
                            inserted += 1
                        except Exception as e:
                            print(f"[ERROR] DB: evento_id={event.get('event_id')} - {str(e)}")
            
            # Commit después de cada lote para evitar transacciones largas
            conn.commit()
        
        return {"inserted": inserted, "updated": 0}
        
    except Exception as e:
        conn.rollback()
        print(f"[ERROR] DB: {str(e)}")
        return {"error": str(e), "inserted": 0, "updated": 0}
        
    finally:
        cursor.close()
        conn.close()