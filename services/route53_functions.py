from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_route53_changed_by(record_id, field_name):
    conn = get_db_connection()
    if not conn: return "unknown"
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_name FROM cloudtrail_events 
            WHERE resource_name = %s AND resource_type = 'route53' 
            ORDER BY event_time DESC LIMIT 1
        """, (record_id,))
        result = cursor.fetchone()
        return result[0] if result else "unknown"
    except:
        return "unknown"
    finally:
        conn.close()

def extract_route53_data(record, hosted_zone_name, hosted_zone_id, account_name, account_id, region):
    try:
        record_name = record.get('Name', 'N/A')
        record_type = record.get('Type', 'N/A')
        record_id = f"{hosted_zone_id}_{record_name}_{record_type}"
        
        # Extraer valores de ResourceRecords
        values = []
        if 'ResourceRecords' in record:
            values = [rr.get('Value', '') for rr in record['ResourceRecords']]
        elif 'AliasTarget' in record:
            values = [record['AliasTarget'].get('DNSName', '')]
        
        return {
            "AccountName": account_name,
            "AccountID": account_id,
            "DomainName": record_name,
            "RecordType": record_type,
            "RecordValue": ', '.join(values) if values else 'N/A',
            "TTL": str(record.get('TTL', 'N/A')),
            "HostedZone": hosted_zone_name,
            "RecordId": record_id
        }
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Route53 extract {region}/{account_id}: {str(e)}")
        return None

def get_route53_records(region, credentials, account_id, account_name):
    client = create_aws_client("route53", region, credentials)
    if not client: return []

    try:
        # Obtener hosted zones
        zones_response = client.list_hosted_zones()
        hosted_zones = zones_response.get('HostedZones', [])
        
        route53_data = []
        for zone in hosted_zones:
            zone_id = zone.get('Id', '').replace('/hostedzone/', '')
            zone_name = zone.get('Name', 'N/A')
            
            try:
                # Obtener records de cada hosted zone
                records_response = client.list_resource_record_sets(HostedZoneId=zone_id)
                records = records_response.get('ResourceRecordSets', [])
                
                for record in records:
                    if (info := extract_route53_data(record, zone_name, zone_id, account_name, account_id, region)):
                        route53_data.append(info)
            except Exception as e:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Route53 zone {zone_id}: {str(e)}")
                continue
        
        return route53_data
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Route53 {region}/{account_id}: {str(e)}")
        return []

def insert_or_update_route53_data(route53_data):
    if not route53_data: return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn: return {"error": "DB connection failed"}

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM route53")
        cols = [d[0].lower() for d in cur.description]
        existing = {(r[cols.index("record_id")], r[cols.index("account_id")]): dict(zip(cols, r)) for r in cur.fetchall()}

        ins, upd = 0, 0
        for record in route53_data:
            rec_id = record["RecordId"]
            key = (rec_id, record["AccountID"])
            
            if key not in existing:
                cur.execute("""
                    INSERT INTO route53 (account_name, account_id, domain_name, record_type, 
                    record_value, ttl, hosted_zone, record_id, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (record_id) DO NOTHING
                """, (
                    record["AccountName"], record["AccountID"], record["DomainName"], 
                    record["RecordType"], record["RecordValue"], record["TTL"],
                    record["HostedZone"], rec_id
                ))
                ins += 1
            else:
                old_data = existing[key]
                changed_by = get_route53_changed_by(rec_id, "record")
                
                # Comparar y registrar cambios
                fields_map = {
                    "domain_name": record["DomainName"],
                    "record_type": record["RecordType"],
                    "record_value": record["RecordValue"],
                    "ttl": record["TTL"],
                    "hosted_zone": record["HostedZone"]
                }
                
                for field, new_val in fields_map.items():
                    old_val = old_data.get(field)
                    if str(old_val) != str(new_val):
                        log_change('route53', rec_id, field, old_val, new_val, changed_by, 
                                 record["AccountID"], region)
                
                cur.execute("""
                    UPDATE route53 SET domain_name=%s, record_type=%s, record_value=%s, 
                    ttl=%s, hosted_zone=%s, last_updated=NOW()
                    WHERE record_id=%s AND account_id=%s
                """, (
                    record["DomainName"], record["RecordType"], record["RecordValue"],
                    record["TTL"], record["HostedZone"], rec_id, record["AccountID"]
                ))
                upd += 1

        conn.commit()
        return {"processed": len(route53_data), "inserted": ins, "updated": upd}
    except Exception as e:
        conn.rollback()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Route53 DB: {str(e)}")
        return {"error": str(e)}
    finally:
        conn.close()