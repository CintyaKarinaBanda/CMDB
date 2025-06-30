from botocore.exceptions import ClientError
from datetime import datetime
import pytz
from services.utils import create_aws_client, get_db_connection

MEXICO_TZ = pytz.timezone('America/Mexico_City')

def get_mexico_time():
    return datetime.now(MEXICO_TZ).strftime('%Y-%m-%d %H:%M:%S')

FIELD_EVENT_MAP = {
    "keyname": ["CreateKey", "UpdateKeyDescription"],
    "estado": ["EnableKey", "DisableKey"],
    "keytype": ["CreateKey"],
    "tags": ["TagResource", "UntagResource"]
}

def get_key_changed_by(key_id, field_name):
    conn = get_db_connection()
    if not conn:
        return "unknown"
    try:
        with conn.cursor() as cursor:
            events = FIELD_EVENT_MAP.get(field_name, [])
            if events:
                placeholders = ','.join(['%s'] * len(events))
                cursor.execute(f"SELECT user_name FROM cloudtrail_events WHERE resource_name = %s AND resource_type = 'KMS' AND event_name IN ({placeholders}) ORDER BY event_time DESC LIMIT 1", (key_id, *events))
            else:
                cursor.execute("SELECT user_name FROM cloudtrail_events WHERE resource_name = %s AND resource_type = 'KMS' ORDER BY event_time DESC LIMIT 1", (key_id,))
            return cursor.fetchone()[0] if cursor.fetchone() else "unknown"
    except:
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
        existing = {row[columns.index("keyid")]: dict(zip(columns, row)) for row in cursor.fetchall()}
        
        for kms in kms_data:
            processed += 1
            key_id = kms["KeyID"]
            values = (kms["AccountName"], kms["AccountID"], kms["KeyID"], kms["KeyName"], kms["Estado"], kms["KeyType"], kms["KeySpec"], kms["Tags"])
            
            if key_id not in existing:
                cursor.execute("INSERT INTO kms (AccountName, AccountID, KeyID, KeyName, Estado, KeyType, KeySpec, Tags, last_updated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", values + (get_mexico_time(),))
                inserted += 1
            else:
                db_row = existing[key_id]
                updates = []
                vals = []
                campos = {"accountname": kms["AccountName"], "accountid": kms["AccountID"], "keyid": kms["KeyID"], "keyname": kms["KeyName"], "estado": kms["Estado"], "keytype": kms["KeyType"], "keyspec": kms["KeySpec"], "tags": kms["Tags"]}
                
                for col, new_val in campos.items():
                    if str(db_row.get(col)) != str(new_val):
                        updates.append(f"{col} = %s")
                        vals.append(new_val)
                        cursor.execute("INSERT INTO kms_changes_history (key_id, field_name, old_value, new_value, changed_by) VALUES (%s, %s, %s, %s, %s)", (key_id, col, str(db_row.get(col)), str(new_val), get_key_changed_by(key_id, col)))
                
                if updates:
                    cursor.execute(f"UPDATE kms SET {', '.join(updates)}, last_updated = %s WHERE keyid = %s", vals + [get_mexico_time(), key_id])
                    updated += 1
        
        conn.commit()
        return {"processed": processed, "inserted": inserted, "updated": updated}
    except Exception as e:
        conn.rollback()
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()