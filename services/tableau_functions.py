from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_tableau_changed_by(workbook_id, field_name):
    conn = get_db_connection()
    if not conn: return "unknown"
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_name FROM cloudtrail_events 
            WHERE resource_name = %s AND resource_type = 'tableau' 
            ORDER BY event_time DESC LIMIT 1
        """, (workbook_id,))
        result = cursor.fetchone()
        return result[0] if result else "unknown"
    except:
        return "unknown"
    finally:
        conn.close()

def extract_tableau_data(workbook, account_name, account_id, region):
    try:
        workbook_id = workbook.get('Id', 'N/A')
        workbook_name = workbook.get('Name', 'N/A')
        
        return {
            "AccountName": account_name,
            "AccountID": account_id,
            "WorkbookName": workbook_name,
            "ContentType": workbook.get('ContentType', 'Workbook'),
            "DataSource": workbook.get('DataSource', 'N/A'),
            "RefreshFrequency": workbook.get('RefreshSchedule', 'Manual'),
            "Integrations": workbook.get('ConnectedDataSources', 'None'),
            "WorkbookId": workbook_id
        }
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Tableau extract {region}/{account_id}: {str(e)}")
        return None

def get_tableau_workbooks(region, credentials, account_id, account_name):
    client = create_aws_client("quicksight", region, credentials)
    if not client: return []

    try:
        response = client.list_dashboards(AwsAccountId=account_id)
        dashboards = response.get('DashboardSummaryList', [])
        
        tableau_data = []
        for dashboard in dashboards:
            workbook_data = {
                'Id': dashboard.get('DashboardId', 'N/A'),
                'Name': dashboard.get('Name', 'N/A'),
                'ContentType': 'Dashboard',
                'DataSource': 'QuickSight',
                'RefreshSchedule': 'On-demand',
                'ConnectedDataSources': str(len(dashboard.get('PublishedVersionNumber', 0)))
            }
            
            if (info := extract_tableau_data(workbook_data, account_name, account_id, region)):
                tableau_data.append(info)
        
        return tableau_data
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Tableau {region}/{account_id}: {str(e)}")
        return []

def insert_or_update_tableau_data(tableau_data):
    if not tableau_data: return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn: return {"error": "DB connection failed"}

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM tableau")
        cols = [d[0].lower() for d in cur.description]
        existing = {(r[cols.index("workbook_id")], r[cols.index("account_id")]): dict(zip(cols, r)) for r in cur.fetchall()}

        ins, upd = 0, 0
        for workbook in tableau_data:
            wb_id = workbook["WorkbookId"]
            key = (wb_id, workbook["AccountID"])
            
            if key not in existing:
                cur.execute("""
                    INSERT INTO tableau (account_name, account_id, workbook_name, content_type, data_source, 
                    refresh_frequency, integrations, workbook_id, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    workbook["AccountName"], workbook["AccountID"], workbook["WorkbookName"], 
                    workbook["ContentType"], workbook["DataSource"], workbook["RefreshFrequency"],
                    workbook["Integrations"], wb_id
                ))
                ins += 1
            else:
                old_data = existing[key]
                changed_by = get_tableau_changed_by(wb_id, "workbook")
                
                # Comparar y registrar cambios
                fields_map = {
                    "workbook_name": workbook["WorkbookName"],
                    "content_type": workbook["ContentType"],
                    "data_source": workbook["DataSource"],
                    "refresh_frequency": workbook["RefreshFrequency"],
                    "integrations": workbook["Integrations"]
                }
                
                for field, new_val in fields_map.items():
                    old_val = old_data.get(field)
                    if str(old_val) != str(new_val):
                        log_change('tableau', wb_id, field, old_val, new_val, changed_by, 
                                 workbook["AccountID"], region)
                
                cur.execute("""
                    UPDATE tableau SET workbook_name=%s, content_type=%s, data_source=%s, 
                    refresh_frequency=%s, integrations=%s, last_updated=NOW()
                    WHERE workbook_id=%s AND account_id=%s
                """, (
                    workbook["WorkbookName"], workbook["ContentType"], workbook["DataSource"],
                    workbook["RefreshFrequency"], workbook["Integrations"], wb_id, workbook["AccountID"]
                ))
                upd += 1

        conn.commit()
        return {"processed": len(tableau_data), "inserted": ins, "updated": upd}
    except Exception as e:
        conn.rollback()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Tableau DB: {str(e)}")
        return {"error": str(e)}
    finally:
        conn.close()