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

def get_resource_changed_by(resource_id, resource_type, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización."""
    try:
        results = execute_db_query("""
            SELECT user_name FROM cloudtrail_events
            WHERE resource_type = %s AND resource_name = %s 
            AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
            ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
        """, (resource_type, resource_id, update_date, update_date), fetch=True)
        
        return results[0][0] if results and results[0] else "unknown"
    except Exception as e:
        print(f"[ERROR] Buscar changed_by para {resource_type} {resource_id}: {str(e)}")
        return "unknown"

def log_change(service_type, resource_id, field_name, old_value, new_value, changed_by, account_id=None, region=None):
    """Registra un cambio en la tabla unificada de historial."""
    try:
        # Filtrar cambios irrelevantes
        if not _is_significant_change(field_name, old_value, new_value):
            return False
            
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
    
    # Ignorar campos de metadatos internos
    ignore_fields = {
        'last_updated', 'created_at', 'modified_at', 'updated_at',
        'map-migrated', 'migration-id', 'aws-migration-project-id',
        'requestid', 'eventid', 'principalid', 'sessioncontext'
    }
    
    if field_name.lower() in ignore_fields:
        return False
    
    # Ignorar cambios de timestamps mínimos (menos de 1 minuto)
    if 'time' in field_name.lower() or 'date' in field_name.lower():
        try:
            from datetime import datetime
            old_time = datetime.fromisoformat(old_str.replace('Z', '+00:00')) if old_str else None
            new_time = datetime.fromisoformat(new_str.replace('Z', '+00:00')) if new_str else None
            if old_time and new_time and abs((new_time - old_time).total_seconds()) < 60:
                return False
        except:
            pass
    
    # Ignorar cambios de IDs de migración AWS
    if (old_str.startswith('mig') and new_str.startswith('mig') and 
        len(old_str) > 10 and len(new_str) > 10):
        return False
    
    # Ignorar cambios de formato JSON idénticos
    if old_str.startswith('{') and new_str.startswith('{'):
        try:
            import json
            old_json = json.loads(old_str)
            new_json = json.loads(new_str)
            if old_json == new_json:
                return False
        except:
            pass
    
    return True