import boto3
import pg8000
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from config import DB_USER, DB_PASSWORD, DB_HOST, DB_NAME

def log(message):
    """Función simple de logging."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")

def create_aws_client(service, region, credentials):
    """Crea un cliente de AWS para el servicio especificado."""
    if not credentials or "error" in credentials:
        return None
    try:
        return boto3.client(
            service,
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
    except Exception as e:
        print(f"[ERROR] Cliente {service} en {region}: {str(e)}")
        return None

def get_db_connection():
    """Establece conexión con la base de datos."""
    try:
        return pg8000.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=5432,
            database=DB_NAME
        )
    except Exception as e:
        print(f"[ERROR] Conexión a base de datos: {str(e)}")
        return None

def execute_db_query(query, params=None, fetch=False, many=False):
    """Ejecuta una consulta en la base de datos y maneja errores."""
    conn = get_db_connection()
    if not conn:
        return {"error": "Database connection failed"}
    
    try:
        cursor = conn.cursor()
        
        if many and params:
            cursor.executemany(query, params)
        elif params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
            
        if fetch:
            results = cursor.fetchall()
            conn.commit()
            return results
        
        affected = cursor.rowcount
        conn.commit()
        return {"affected": affected, "success": True}
    
    except Exception as e:
        conn.rollback()
        print(f"[ERROR] Consulta BD: {str(e)}")
        return {"error": str(e)}
    
    finally:
        conn.close()

def get_resource_changed_by(resource_id, resource_type, update_date, field_name=None):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización."""
    try:
        # Mapeo de campos a eventos relacionados por tipo de recurso
        field_event_maps = {
            'EC2': {
                'instancename': ['CreateTags', 'DeleteTags'],
                'instancetype': ['ModifyInstanceAttribute'],
                'state': ['StartInstances', 'StopInstances', 'RebootInstances', 'TerminateInstances'],
                'iamrole': ['AssociateIamInstanceProfile', 'DisassociateIamInstanceProfile', 'TerminateInstances'],
                'securitygroups': ['ModifyInstanceAttribute', 'AuthorizeSecurityGroupIngress', 'StartInstances', 'StopInstances', 'TerminateInstances'],
                'publicip': ['AssociateAddress', 'DisassociateAddress', 'StartInstances', 'StopInstances', 'TerminateInstances'],
                'privateip': ['ModifyInstanceAttribute', 'StartInstances', 'StopInstances', 'TerminateInstances'],
                'vpc': ['ModifyInstanceAttribute', 'StartInstances', 'StopInstances', 'TerminateInstances'],
                'subnet': ['ModifyInstanceAttribute', 'StartInstances', 'StopInstances', 'TerminateInstances'],
                'storagevolumes': ['AttachVolume', 'DetachVolume']
            },
            'VPC': {
                'vpc_name': ['CreateTags', 'DeleteTags'],
                'state': ['CreateVpc', 'DeleteVpc'],
                'subnets': ['CreateSubnet', 'DeleteSubnet'],
                'security_groups': ['CreateSecurityGroup', 'DeleteSecurityGroup'],
                'network_acls': ['CreateNetworkAcl', 'DeleteNetworkAcl'],
                'internet_gateways': ['CreateInternetGateway', 'AttachInternetGateway', 'DetachInternetGateway'],
                'vpn_connections': ['CreateVpnConnection', 'DeleteVpnConnection'],
                'vpc_endpoints': ['CreateVpcEndpoint', 'DeleteVpcEndpoint'],
                'vpc_peerings': ['CreateVpcPeeringConnection', 'DeleteVpcPeeringConnection'],
                'route_rules': ['CreateRouteTable', 'DeleteRouteTable']
            }
        }
        
        # Buscar primero por evento directo
        results = execute_db_query("""
            SELECT user_name FROM cloudtrail_events
            WHERE resource_type = %s AND resource_name = %s 
            AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
            ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
        """, (resource_type, resource_id, update_date, update_date), fetch=True)
        
        if results and results[0]:
            return results[0][0]
        
        # Si no encuentra evento directo y hay field_name, buscar por eventos relacionados
        if field_name and resource_type in field_event_maps:
            field_events = field_event_maps[resource_type].get(field_name.lower(), [])
            if field_events:
                event_list = "', '".join(field_events)
                results = execute_db_query(f"""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND event_name IN ('{event_list}')
                    AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                    ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
                """, (resource_id, update_date, update_date), fetch=True)
                
                if results and results[0]:
                    return results[0][0]
        
        return "unknown"
    except Exception as e:
        print(f"[ERROR] Buscar changed_by para {resource_type} {resource_id}: {str(e)}")
        return "unknown"

def log_change(service_type, resource_id, field_name, old_value, new_value, changed_by, account_id=None, region=None):
    """Registra un cambio en la tabla unificada de historial."""
    try:
        # Ignorar cambios en Lambdas del sistema AWS
        if service_type == 'Lambda':
            system_lambdas = {
                'aws-controltower-NotificationForwarder',
                'aws-controltower-ConfigComplianceCheck',
                'aws-controltower-BaselineCloudTrail',
                'nops-register-aws-account',
                'generate-external-id',
                'CidInitialSetup-DoNotRun',
                'CidCustomResourceDashboard',
                'CidCustomResourceFunctionInit-DoNotRun',
                'CidCustomResourceProcessPath-DoNotRun',
                'cid-CID-Analytics',
                'cid-CID-Analytics-DataExports',
                'AWS-Cost-Reporting-Lambda'
            }
            # Extraer nombre de función del resource_id si es ARN
            function_name = resource_id.split(':')[-1] if ':' in resource_id else resource_id
            if function_name in system_lambdas:
                return False
        
        # Filtrar cambios irrelevantes
        if not _is_significant_change(field_name, old_value, new_value):
            return False
        
        # Si changed_by es "unknown", intentar buscar con el field_name
        if changed_by == "unknown":
            changed_by = get_resource_changed_by(resource_id, service_type, datetime.now(), field_name)
            
        execute_db_query("""
            INSERT INTO changes_history 
            (service_type, resource_id, field_name, old_value, new_value, changed_by, account_id, region)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (service_type, resource_id, field_name, str(old_value), str(new_value), changed_by, account_id, region))
        return True
    except Exception as e:
        print(f"[ERROR] Log change: {str(e)}")
        return False

def _is_significant_change(field_name, old_value, new_value):
    """Determina si un cambio es significativo y debe registrarse."""
    old_str = str(old_value).strip() if old_value is not None else ""
    new_str = str(new_value).strip() if new_value is not None else ""
    
    # Ignorar cambios vacíos o idénticos
    if old_str == new_str:
        return False
    
    # Ignorar cambios entre [] y {} (listas vacías vs diccionarios vacíos)
    if (old_str in ['[]', '{}'] and new_str in ['[]', '{}']) or (old_str == '' and new_str in ['[]', '{}']) or (new_str == '' and old_str in ['[]', '{}']):
        return False
    
    # Ignorar cambios entre formatos de booleanos (false vs False, true vs True)
    if (old_str.lower() in ['false', 'true'] and new_str.lower() in ['false', 'true']) and old_str.lower() == new_str.lower():
        return False
    
    # Ignorar campos de metadatos internos
    ignore_fields = {
        'last_updated', 'created_at', 'modified_at', 'updated_at',
        'map-migrated', 'migration-id', 'aws-migration-project-id',
        'requestid', 'eventid', 'principalid', 'sessioncontext',
        'creation_date', 'account', 'accountname', 'accountid', 'region'
    }
    
    # Ignorar cambios en tags automáticos de CloudFormation
    if field_name.lower() == 'tags' and old_str.startswith('{') and new_str.startswith('{'):
        try:
            import json
            import ast
            # Parsear ambos diccionarios
            try:
                old_tags = json.loads(old_str)
            except:
                old_tags = ast.literal_eval(old_str)
            
            try:
                new_tags = json.loads(new_str)
            except:
                new_tags = ast.literal_eval(new_str)
            
            # Filtrar tags de CloudFormation automáticos
            cf_keys = {'aws:cloudformation:logical-id', 'aws:cloudformation:stack-id', 'aws:cloudformation:stack-name'}
            old_filtered = {k: v for k, v in old_tags.items() if k not in cf_keys}
            new_filtered = {k: v for k, v in new_tags.items() if k not in cf_keys}
            
            # Si solo cambiaron los tags de CloudFormation, ignorar
            if old_filtered == new_filtered:
                return False
        except:
            pass
    
    if field_name.lower() in ignore_fields:
        return False
    
    # Ignorar cambios de formato JSON idénticos
    if old_str.startswith('{') and new_str.startswith('{'):
        try:
            import json
            import ast
            # Intentar parsear como JSON primero
            try:
                old_json = json.loads(old_str)
            except:
                # Si falla, intentar como dict de Python
                old_json = ast.literal_eval(old_str)
            
            try:
                new_json = json.loads(new_str)
            except:
                # Si falla, intentar como dict de Python
                new_json = ast.literal_eval(new_str)
            
            if old_json == new_json:
                return False
        except:
            pass
    
    # Ignorar cambios de orden en arrays JSON
    if old_str.startswith('[') and new_str.startswith('['):
        try:
            import json
            old_data = json.loads(old_str)
            new_data = json.loads(new_str)
            if isinstance(old_data, list) and isinstance(new_data, list):
                if set(str(x) for x in old_data) == set(str(x) for x in new_data):
                    return False
        except:
            pass
    
    # Ignorar cambios de orden en listas Python (para VPC, Subnets, etc.)
    if field_name.lower() in ['subnets', 'security_groups', 'network_acls', 'internet_gateways', 
                              'vpc_endpoints', 'vpc_peerings', 'route_rules', 'availability_zones',
                              'securitygroups', 'storagevolumes', 'vpceendpoints', 'routetables', 'tags']:
        try:
            # Convertir ambos valores a listas normalizadas
            def normalize_to_list(value):
                if isinstance(value, list):
                    return value
                elif isinstance(value, set):
                    return list(value)
                elif isinstance(value, str):
                    value = value.strip()
                    if value.startswith('[') and value.endswith(']'):
                        try:
                            import json
                            return json.loads(value)
                        except:
                            return value.split(',') if value else []
                    elif value.startswith('{') and value.endswith('}'):
                        # Manejar sets de Python y strings JSON
                        try:
                            import ast
                            parsed = ast.literal_eval(value)
                            if isinstance(parsed, set):
                                # Convertir set a lista
                                return list(parsed)
                            elif isinstance(parsed, dict):
                                # Es un diccionario JSON
                                return [parsed]
                            else:
                                return [parsed] if parsed else []
                        except:
                            # Si falla el parsing, intentar como JSON
                            try:
                                import json
                                parsed_json = json.loads(value)
                                return [parsed_json] if isinstance(parsed_json, dict) else parsed_json
                            except:
                                # Último recurso: split por comas
                                inner = value[1:-1].strip()  # Remover { }
                                return [item.strip() for item in inner.split(',') if item.strip()]
                    else:
                        return value.split(',') if value else []
                else:
                    return [str(value)] if value else []
            
            old_list = normalize_to_list(old_value)
            new_list = normalize_to_list(new_value)
            
            # Normalizar elementos de la lista
            def normalize_element(elem):
                if isinstance(elem, dict):
                    # Para diccionarios, convertir a JSON normalizado
                    import json
                    return json.dumps(elem, sort_keys=True)
                elif isinstance(elem, str) and elem.strip().startswith('{'):
                    # Para strings JSON, parsear y normalizar
                    try:
                        import json
                        parsed = json.loads(elem)
                        return json.dumps(parsed, sort_keys=True)
                    except:
                        return elem.strip()
                else:
                    return str(elem).strip()
            
            old_normalized = sorted([normalize_element(x) for x in old_list if str(x).strip()])
            new_normalized = sorted([normalize_element(x) for x in new_list if str(x).strip()])
            
            if old_normalized == new_normalized:
                return False
        except:
            pass
    
    # Ignorar cambios de formato decimal
    if field_name.lower() in ['execution_duration', 'compliance_percentage']:
        try:
            if float(old_str) == float(new_str):
                return False
        except:
            pass
    
    # Ignorar cambios de formato de timestamp/fecha equivalentes
    field_lower = field_name.lower()
    date_keywords = ['time', 'date', 'created', 'modified', 'updated', 'started', 'ended', 'finished', 'completed', 'executed', 'run', 'launch', 'domain']
    
    if any(keyword in field_lower for keyword in date_keywords):
        try:
            from dateutil import parser
            import pytz
            
            old_dt = parser.parse(old_str)
            new_dt = parser.parse(new_str)
            
            # Convertir ambos a UTC para comparación
            utc = pytz.UTC
            
            # Si no tiene timezone, asumir UTC
            if old_dt.tzinfo is None:
                old_dt = old_dt.replace(tzinfo=utc)
            else:
                old_dt = old_dt.astimezone(utc)
                
            if new_dt.tzinfo is None:
                new_dt = new_dt.replace(tzinfo=utc)
            else:
                new_dt = new_dt.astimezone(utc)
            
            # Comparar ignorando microsegundos
            old_utc = old_dt.replace(microsecond=0)
            new_utc = new_dt.replace(microsecond=0)
            
            if abs((old_utc - new_utc).total_seconds()) < 1:
                return False
        except:
            pass
    
    return True