from datetime import datetime
from ..utils import get_db_connection

class DatabaseOperations:
    """Operaciones comunes de base de datos para todos los servicios"""
    
    @staticmethod
    def get_changed_by(resource_id, field_name, resource_type, field_event_map):
        """Busca el usuario que cambió un campo específico"""
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
    
    @staticmethod
    def insert_or_update_data(data, config):
        """
        Función genérica para insertar/actualizar datos con historial
        config debe contener: table_name, history_table, id_field, insert_query, 
                             resource_type, field_event_map
        """
        if not data:
            return {"processed": 0, "inserted": 0, "updated": 0}

        conn = get_db_connection()
        if not conn:
            return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

        query_change_history = f"""
            INSERT INTO {config['history_table']} ({config['id_field']}, field_name, old_value, new_value, changed_by)
            VALUES (%s, %s, %s, %s, %s)
        """

        inserted = updated = processed = 0

        try:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {config['table_name']}")
            columns = [desc[0].lower() for desc in cursor.description]
            existing_data = {row[columns.index(config['id_field'].lower())]: dict(zip(columns, row)) 
                           for row in cursor.fetchall()}

            for item in data:
                resource_id = item[config['resource_id_key']]
                processed += 1

                if resource_id not in existing_data:
                    cursor.execute(config['insert_query'], config['get_insert_values'](item))
                    inserted += 1
                else:
                    db_row = existing_data[resource_id]
                    updates = []
                    values = []

                    for col, new_val in config['get_field_mapping'](item).items():
                        old_val = db_row.get(col)
                        if str(old_val) != str(new_val):
                            updates.append(f"{col} = %s")
                            values.append(new_val)
                            changed_by = DatabaseOperations.get_changed_by(
                                resource_id, col, config['resource_type'], config['field_event_map']
                            )
                            
                            cursor.execute(query_change_history,
                                         (resource_id, col, str(old_val), str(new_val), changed_by))

                    updates.append("last_updated = CURRENT_TIMESTAMP")

                    if updates:
                        update_query = f"UPDATE {config['table_name']} SET {', '.join(updates)} WHERE {config['id_field'].lower()} = %s"
                        values.append(resource_id)
                        cursor.execute(update_query, tuple(values))
                        updated += 1

            conn.commit()
            return {"processed": processed, "inserted": inserted, "updated": updated}

        except Exception as e:
            conn.rollback()
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: DB {config['table_name']} - {str(e)}")
            return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
        finally:
            conn.close()