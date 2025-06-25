#!/usr/bin/env python3
import psycopg2
from services.utils import get_db_connection

def check_s3_capacity():
    """Verifica los valores de capacity en la base de datos"""
    conn = get_db_connection()
    if not conn:
        print("Error: No se pudo conectar a la base de datos")
        return
    
    try:
        cursor = conn.cursor()
        
        # Verificar estructura de la tabla
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 's3' AND column_name = 'capacity'
        """)
        
        column_info = cursor.fetchone()
        if column_info:
            print(f"Columna capacity: {column_info[0]} - Tipo: {column_info[1]}")
        else:
            print("ERROR: Columna 'capacity' no encontrada")
            return
        
        # Verificar datos actuales
        cursor.execute("SELECT bucket_name, capacity FROM s3 ORDER BY bucket_name")
        rows = cursor.fetchall()
        
        print(f"\nRegistros en la tabla s3: {len(rows)}")
        print("Bucket Name | Capacity")
        print("-" * 40)
        
        for row in rows:
            print(f"{row[0]} | {row[1]}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_s3_capacity()