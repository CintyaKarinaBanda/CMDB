from botocore.exceptions import ClientError
from datetime import datetime
import time
from services.utils import create_aws_client, get_db_connection, log_change

def get_local_time():
    return 'NOW()'

FIELD_EVENT_MAP = {
    "keyname": ["CreateKey", "UpdateKeyDescription"],
    "estado": ["EnableKey", "DisableKey"],
    "keytype": ["CreateKey"],
    "tags": ["TagResource", "UntagResource"]
}

def normalize_list_comparison(old_val, new_val):
    """Normaliza listas para comparación, ignorando orden"""
    if isinstance(new_val, list) and isinstance(old_val, (list, str)):
        old_list = old_val if isinstance(old_val, list) else str(old_val).split(',') if old_val else []
        return sorted([str(x).strip() for x in old_list]) == sorted([str(x).strip() for x in new_val])
    return str(old_val) == str(new_val)

def get_key_changed_by(key_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'KMS' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (key_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_kms_data(key, kms_client, account_name, account_id, region):
    key_id = key["KeyId"]
    
    # Get key details
    try:
        key_detail = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        key_state = key_detail.get("KeyState", "N/A")
        key_spec = key_detail.get("KeySpec", "SYMMETRIC_DEFAULT")
        key_type = "Simétrica" if key_spec == "SYMMETRIC_DEFAULT" else "Asimétrica"
    except:
        key_state = key_type = key_spec = "N/A"
    
    # Get aliases
    try:
        aliases_response = kms_client.list_aliases(KeyId=key_id)
        aliases = [alias["AliasName"] for alias in aliases_response.get("Aliases", [])]
        key_name = ", ".join(aliases) if aliases else "N/A"
    except:
        key_name = "N/A"
    
    # Get tags
    try:
        tags_response = kms_client.list_resource_tags(KeyId=key_id)
        tags = tags_response.get("Tags", [])
    except:
        tags = []
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "KeyID": key_id,
        "KeyName": key_name,
        "Estado": key_state,
        "KeyType": key_type,
        "KeySpec": key_spec,
        "Tags": tags
    }

def get_kms_keys(region, credentials, account_id, account_name):
    kms_client = create_aws_client("kms", region, credentials)
    if not kms_client:
        return []
    try:
        keys_info = []
        for page in kms_client.get_paginator('list_keys').paginate():
            for key in page.get("Keys", []):
                try:
                    # Get key details to filter
                    key_detail = kms_client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    # Only include customer managed keys (like console shows)
                    if key_detail.get("KeyManager") == "CUSTOMER":
                        keys_info.append(extract_kms_data(key, kms_client, account_name, account_id, region))
                except:
                    continue
        return keys_info
    except:
        return []

def insert_or_update_kms_data(kms_data):
    if not kms_data:
        return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}
    
    inserted = updated = processed = 0
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM kms")
        columns = [desc[0].lower() for desc in cursor.description]
        existing = {(row[columns.index("keyid")], row[columns.index("accountid")]): dict(zip(columns, row)) for row in cursor.fetchall()}
        
        for kms in kms_data:
            processed += 1
            key_id = kms["KeyID"]
            values = (kms["AccountName"], kms["AccountID"], kms["KeyID"], kms["KeyName"], kms["Estado"], kms["KeyType"], kms["KeySpec"], kms["Tags"])
            
            if (key_id, kms["AccountID"]) not in existing:
                cursor.execute("INSERT INTO kms (AccountName, AccountID, KeyID, KeyName, Estado, KeyType, KeySpec, Tags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                inserted += 1
            else:
                db_row = existing[(key_id, kms["AccountID"])]
                updates = []
                vals = []
                campos = {"accountname": kms["AccountName"], "accountid": kms["AccountID"], "keyid": kms["KeyID"], "keyname": kms["KeyName"], "estado": kms["Estado"], "keytype": kms["KeyType"], "keyspec": kms["KeySpec"], "tags": kms["Tags"]}
                
                # Verificar si cambió el account_id o key_id (campos de identificación)
                if (str(db_row.get('accountid')) != str(kms["AccountID"]) or 
                    str(db_row.get('keyid')) != str(kms["KeyID"])):
                    # Si cambió la identificación, insertar como nuevo registro
                    cursor.execute("INSERT INTO kms (AccountName, AccountID, KeyID, KeyName, Estado, KeyType, KeySpec, Tags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())", values)
                    inserted += 1
                    continue
                
                for col, new_val in campos.items():
                    # Saltar campos de identificación para actualizaciones
                    if col in ['accountid', 'keyid']:
                        continue
                    
                    old_val = db_row.get(col)
                    if not normalize_list_comparison(old_val, new_val):
                        updates.append(f"{col} = %s")
                        vals.append(new_val)
                        changed_by = get_key_changed_by(key_id, datetime.now())
                        log_change('KMS', key_id, col, old_val, new_val, changed_by, kms["AccountID"], "us-east-1")
                
                if updates:
                    cursor.execute(f"UPDATE kms SET {', '.join(updates)}, last_updated = NOW() WHERE keyid = %s", vals + [key_id])
                    updated += 1
        
        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()