from datetime import datetime
from ..utils import get_db_connection

def get_resource_changed_by(resource_id, field_name, resource_type, field_event_map):
    """Función común para obtener changed_by"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            possible_events = field_event_map.get(field_name, [])
            
            if possible_events:
                placeholders = ','.join(['%s'] * len(possible_events))
                query = f"""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = %s
                    AND event_name IN ({placeholders})
                    ORDER BY event_time DESC LIMIT 1
                """
                cursor.execute(query, (resource_id, resource_type, *possible_events))
            else:
                cursor.execute("""
                    SELECT user_name FROM cloudtrail_events
                    WHERE resource_name = %s AND resource_type = %s
                    ORDER BY event_time DESC LIMIT 1
                """, (resource_id, resource_type))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: changed_by {resource_id}/{field_name} - {str(e)}")
        return "unknown"
    finally:
        conn.close()

def generic_insert_or_update(data, table_name, history_table, id_field, insert_query, campos_map, resource_type, field_event_map):
    """Función genérica para insertar/actualizar con historial"""
    if not data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_change_history = f"""
        INSERT INTO {history_table} ({id_field}, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index(id_field.lower())]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for item in data:
            # Obtener ID del recurso (asume que está en la tercera posición)
            resource_id = list(item.values())[2]
            processed += 1

            # Preparar valores para inserción (excluir last_updated)
            insert_values = [v for k, v in item.items() if k.lower() != 'last_updated']

            if resource_id not in existing_data:
                cursor.execute(insert_query, insert_values)
                inserted += 1
            else:
                db_row = existing_data[resource_id]
                updates = []
                values = []

                for col, new_val in campos_map.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_resource_changed_by(resource_id, col, resource_type, field_event_map)
                        
                        cursor.execute(
                            query_change_history,
                            (resource_id, col, str(old_val), str(new_val), changed_by)
                        )

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE {table_name} SET {', '.join(updates)} WHERE {id_field.lower()} = %s"
                    values.append(resource_id)
                    cursor.execute(update_query, tuple(values))
                    updated += 1

        conn.commit()
        return {
            "processed": processed,
            "inserted": inserted,
            "updated": updated
        }

    except Exception as e:
        conn.rollback()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: DB {table_name} - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()

def log_service_info(service_name, region, count):
    """Log estándar para servicios"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: {service_name} {region}: {count} encontrados")

def log_service_error(service_name, region, account_id, error):
    """Log estándar para errores de servicios"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {service_name} {region}/{account_id} - {str(error)}")