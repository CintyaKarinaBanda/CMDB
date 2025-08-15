from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_sns_changed_by(topic_arn, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'SNS' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (topic_arn, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_sns_data(topic, account_name, account_id, region):
    try:
        topic_arn = topic.get('TopicArn', 'N/A')
        topic_name = topic_arn.split(':')[-1] if topic_arn != 'N/A' else 'N/A'
        
        return {
            "AccountName": account_name,
            "AccountID": account_id,
            "TopicName": topic_name,
            "Domain": "N/A",
            "TopicArn": topic_arn,
            "DisplayName": topic_name,
            "Type": "Standard"
        }
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: SNS extract {region}/{account_id}: {str(e)}")
        return None

def get_sns_topics(region, credentials, account_id, account_name):
    client = create_aws_client("sns", region, credentials)
    if not client: return []

    try:
        response = client.list_topics()
        topics = response.get('Topics', [])
        
        return [
            info for topic in topics
            if (info := extract_sns_data(topic, account_name, account_id, region))
        ]
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: SNS {region}/{account_id}: {str(e)}")
        return []

def insert_or_update_sns_data(sns_data):
    if not sns_data: return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn: return {"error": "DB connection failed"}

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sns")
        cols = [d[0].lower() for d in cur.description]
        existing = {(r[cols.index("topic_arn")], r[cols.index("account_id")]): dict(zip(cols, r)) for r in cur.fetchall()}

        ins, upd = 0, 0
        for topic in sns_data:
            ta = topic["TopicArn"]
            key = (ta, topic["AccountID"])
            
            if key not in existing:
                cur.execute("""
                    INSERT INTO sns (account_name, account_id, topic_name, domain, topic_arn, display_name, type, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    topic["AccountName"], topic["AccountID"], topic["TopicName"], topic["Domain"],
                    ta, topic["DisplayName"], topic["Type"]
                ))
                ins += 1
            else:
                old_data = existing[key]
                # Comparar y registrar cambios
                fields_map = {
                    "topic_name": topic["TopicName"],
                    "domain": topic["Domain"],
                    "display_name": topic["DisplayName"],
                    "type": topic["Type"]
                }
                
                for field, new_val in fields_map.items():
                    old_val = old_data.get(field)
                    if str(old_val) != str(new_val):
                        changed_by = get_sns_changed_by(ta, datetime.now())
                        log_change('SNS', ta, field, old_val, new_val, changed_by, 
                                 topic["AccountID"], "us-east-1")
                
                cur.execute("""
                    UPDATE sns SET topic_name=%s, domain=%s, display_name=%s, type=%s, last_updated=NOW()
                    WHERE topic_arn=%s AND account_id=%s
                """, (
                    topic["TopicName"], topic["Domain"], topic["DisplayName"], topic["Type"], ta, topic["AccountID"]
                ))
                upd += 1

        conn.commit()
        return {"processed": len(sns_data), "inserted": ins, "updated": upd}
    except Exception as e:
        conn.rollback()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: SNS DB: {str(e)}")
        return {"error": str(e)}
    finally:
        conn.close()