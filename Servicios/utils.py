import boto3
import pg8000
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import DB_USER, DB_PASSWORD, DB_HOST, DB_NAME

def log(msg):
    """Registra un mensaje con fecha y hora."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")

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
        log(f"ERROR: Cliente {service} en {region}: {str(e)}")
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
        log(f"ERROR: Conexión a base de datos: {str(e)}")
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
        log(f"ERROR: Consulta BD: {str(e)}")
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
        log(f"ERROR: Buscar changed_by para {resource_type} {resource_id}: {str(e)}")
        return "unknown"