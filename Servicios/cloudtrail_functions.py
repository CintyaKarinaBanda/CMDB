import json
from datetime import datetime, timedelta
from Servicios.utils import create_aws_client, get_db_connection, log, execute_db_query

# Eventos importantes que queremos rastrear
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
    }
}

# Mapeo de servicios a fuentes de eventos
EVENT_SOURCES = {
    "EC2": "ec2.amazonaws.com",
    "RDS": "rds.amazonaws.com",
    "VPC": "ec2.amazonaws.com"  # VPC usa el mismo source que EC2
}

def extract_resource_id(event, resource_type):
    """Extrae el ID del recurso del evento según el tipo."""
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    event_name = event.get("eventName", "")
    
    # Para recursos EC2
    if resource_type == "EC2":
        # Eventos de instancias
        if event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
            instances = req.get("instancesSet", {}).get("items", [])
            if instances and len(instances) > 0:
                return instances[0].get("instanceId", "unknown")
        
        if event_name == "ModifyInstanceAttribute":
            return req.get("instanceId", "unknown")
        
        # Campos comunes
        for key in ["instanceId", "resourceId"]:
            if key in req and req[key]:
                return req[key]
    
    # Para recursos RDS
    elif resource_type == "RDS":
        # Campos específicos de RDS
        if "dBInstanceIdentifier" in req:
            return req["dBInstanceIdentifier"]
        
        if "dBInstanceIdentifier" in res:
            return res["dBInstanceIdentifier"]
        
        # Eventos de snapshot
        if "dBSnapshotIdentifier" in req:
            return req["dBSnapshotIdentifier"]
        
        # Eventos de tags
        if event_name in ["AddTagsToResource", "RemoveTagsFromResource"]:
            resource_arn = req.get("resourceName")
            if resource_arn and "rds:db:" in resource_arn:
                parts = resource_arn.split(":")
                if len(parts) > 6:
                    return parts[6]
    
    # Para recursos VPC
    elif resource_type == "VPC":
        # Campos específicos de VPC
        if "vpcId" in req:
            return req["vpcId"]
        
        if "vpc" in res and "vpcId" in res["vpc"]:
            return res["vpc"]["vpcId"]
        
        # Eventos de subnet
        if "subnetId" in req:
            return req["subnetId"]
        
        if "subnet" in res and "subnetId" in res["subnet"]:
            return res["subnet"]["subnetId"]
        
        # Eventos de internet gateway
        if "internetGatewayId" in req:
            return req["internetGatewayId"]
        
        if "internetGateway" in res and "internetGatewayId" in res["internetGateway"]:
            return res["internetGateway"]["internetGatewayId"]
        
        # Eventos de NAT gateway
        if "natGatewayId" in req:
            return req["natGatewayId"]
        
        if "natGateway" in res and "natGatewayId" in res["natGateway"]:
            return res["natGateway"]["natGatewayId"]
    
    return "unknown"

def extract_changes(event, resource_type):
    """Extrae cambios relevantes del evento."""
    event_name = event.get("eventName", "")
    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})
    
    changes = {"eventType": event_name, "details": {}}
    
    # Para recursos EC2
    if resource_type == "EC2":
        if event_name in ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"]:
            instances = res.get("instancesSet", {}).get("items", [])
            if instances:
                changes["details"]["state"] = instances[0].get("currentState", {}).get("name")
        
        elif event_name == "ModifyInstanceAttribute":
            for key, value in req.items():
                if key not in ["instanceId", "attribute", "value"]:
                    changes["details"][key] = value
    
    # Para recursos RDS
    elif resource_type == "RDS":
        if event_name == "CreateDBInstance":
            changes["details"].update({
                "engine": req.get("engine"),
                "dbInstanceClass": req.get("dbInstanceClass"),
                "allocatedStorage": req.get("allocatedStorage"),
                "multiAZ": req.get("multiAZ")
            })
        
        elif event_name == "ModifyDBInstance":
            for key in ["dbInstanceClass", "allocatedStorage", "multiAZ", "engineVersion"]:
                if key in req:
                    changes["details"][key] = req[key]
        
        elif event_name in ["StartDBInstance", "StopDBInstance", "RebootDBInstance"]:
            changes["details"]["action"] = event_name.replace("DBInstance", "")
        
        elif event_name in ["AddTagsToResource", "RemoveTagsFromResource"]:
            if "tags" in req:
                changes["details"]["tags"] = req["tags"]
    
    # Para recursos VPC
    elif resource_type == "VPC":
        if event_name == "CreateVpc":
            changes["details"].update({
                "cidrBlock": req.get("cidrBlock"),
                "instanceTenancy": req.get("instanceTenancy", "default")
            })
            if "vpc" in res:
                changes["details"]["vpcId"] = res["vpc"].get("vpcId")
        
        elif event_name == "ModifyVpcAttribute":
            for key, value in req.items():
                if key not in ["vpcId", "attribute"]:
                    changes["details"][key] = value
        
        elif event_name == "CreateSubnet":
            changes["details"].update({
                "vpcId": req.get("vpcId"),
                "cidrBlock": req.get("cidrBlock"),
                "availabilityZone": req.get("availabilityZone")
            })
            if "subnet" in res:
                changes["details"]["subnetId"] = res["subnet"].get("subnetId")
        
        elif event_name in ["CreateInternetGateway", "AttachInternetGateway", "DetachInternetGateway", 
                           "CreateNatGateway"]:
            # Extraer detalles específicos según el tipo de evento
            for key, value in req.items():
                if key not in ["attribute"]:
                    changes["details"][key] = value
            
            # Añadir IDs de recursos creados si están disponibles
            for resource_key in ["internetGateway", "natGateway"]:
                if resource_key in res and f"{resource_key}Id" in res[resource_key]:
                    changes["details"][f"{resource_key}Id"] = res[resource_key].get(f"{resource_key}Id")
    
    return changes

def get_cloudtrail_events(region, credentials, resource_type):
    """Obtiene eventos de CloudTrail para un tipo de recurso específico."""
    try:
        client = create_aws_client("cloudtrail", region, credentials)
        if not client:
            return {"error": f"Error al crear cliente CloudTrail para {resource_type}", "events": []}

        # Obtener configuración específica para el tipo de recurso
        event_source = EVENT_SOURCES.get(resource_type)
        important_events = IMPORTANT_EVENTS.get(resource_type, set())
        
        if not event_source or not important_events:
            return {"error": f"Tipo de recurso no soportado: {resource_type}", "events": []}

        # Consultar eventos de los últimos 3 días
        start_time = datetime.utcnow() - timedelta(days=3)
        response = client.lookup_events(
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": event_source}],
            StartTime=start_time,
            EndTime=datetime.utcnow(),
            MaxResults=100
        )
        
        events = response.get("Events", [])
        
        # Procesar eventos
        parsed_events = []
        for raw_event in events:
            try:
                detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                event_name = detail.get("eventName")
                
                # Filtrar solo eventos importantes
                if event_name not in important_events:
                    continue
                
                # Extraer información relevante
                user_identity = detail.get("userIdentity", {})
                user_name = user_identity.get("userName") or user_identity.get("principalId") or "unknown"
                resource_name = extract_resource_id(detail, resource_type)
                changes = extract_changes(detail, resource_type)
                
                parsed_events.append({
                    "event_id": raw_event.get("EventId"),
                    "event_time": raw_event.get("EventTime"),
                    "event_name": event_name,
                    "event_source": detail.get("eventSource", "unknown"),
                    "user_name": user_name,
                    "resource_name": resource_name,
                    "resource_type": resource_type,
                    "changes": changes,
                    "region": region
                })
                
            except Exception as e:
                log(f"ERROR: Procesar evento {resource_type} en {region}: {str(e)}")
        
        if parsed_events:
            log(f"INFO: CloudTrail {resource_type} en {region}: {len(parsed_events)} eventos encontrados")
        return {"events": parsed_events}
        
    except Exception as e:
        log(f"ERROR: CloudTrail {resource_type} en {region}: {str(e)}")
        return {"error": str(e), "events": []}

# Funciones específicas para cada tipo de recurso
def get_ec2_cloudtrail_events(region, credentials):
    return get_cloudtrail_events(region, credentials, "EC2")

def get_rds_cloudtrail_events(region, credentials):
    return get_cloudtrail_events(region, credentials, "RDS")

def get_vpc_cloudtrail_events(region, credentials):
    return get_cloudtrail_events(region, credentials, "VPC")

def insert_or_update_cloudtrail_events(events):
    """Inserta eventos de CloudTrail en la base de datos."""
    if not events:
        return {"inserted": 0, "updated": 0}
    
    # Verificar si la tabla existe, crearla si no
    table_exists = execute_db_query("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'cloudtrail_events'
        )
    """, fetch=True)
    
    if not table_exists or not table_exists[0][0]:
        result = execute_db_query("""
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
        if "error" in result:
            return {"error": result["error"], "inserted": 0, "updated": 0}
        log("INFO: Tabla cloudtrail_events creada")
    
    # Preparar datos para inserción
    prepared_data = [(
        event["event_id"],
        event["event_time"],
        event["event_name"],
        event["event_source"],
        event["user_name"],
        event["resource_name"],
        event.get("resource_type", "EC2"),  # Por defecto EC2 para compatibilidad
        event["region"],
        json.dumps(event["changes"])
    ) for event in events]
    
    # Insertar eventos
    result = execute_db_query("""
        INSERT INTO cloudtrail_events 
        (event_id, event_time, event_name, event_source, user_name, resource_name, 
         resource_type, region, changes, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (event_id) DO NOTHING
        RETURNING event_id
    """, prepared_data, many=True, fetch=True)
    
    if "error" in result:
        return {"error": result["error"], "inserted": 0, "updated": 0}
    
    inserted = len(result)
    return {"inserted": inserted, "updated": 0}