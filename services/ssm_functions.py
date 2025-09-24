from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_association_changed_by(association_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'SSM' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (association_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_association_data(association, ssm_client, account_name, account_id, region):
    """Extrae datos relevantes de una asociación de SSM"""
    association_id = association["AssociationId"]
    
    # Obtener detalles de compliance
    try:
        compliance_response = ssm_client.list_compliance_items(
            Filters=[
                {'Key': 'ComplianceType', 'Values': ['Association']},
                {'Key': 'Id', 'Values': [association_id]}
            ]
        )
        
        compliant_count = 0
        non_compliant_count = 0
        
        for item in compliance_response.get('ComplianceItems', []):
            if item.get('Status') == 'COMPLIANT':
                compliant_count += 1
            else:
                non_compliant_count += 1
        
        total_resources = compliant_count + non_compliant_count
        compliance_percentage = (compliant_count / total_resources * 100) if total_resources > 0 else 0
        
    except ClientError:
        compliant_count = 0
        non_compliant_count = 0
        compliance_percentage = 0
    
    # Obtener información de recursos no conformes por tiempo (simulado)
    non_compliant_15_days = int(non_compliant_count * 0.3)
    non_compliant_15_90_days = int(non_compliant_count * 0.4)
    non_compliant_90_days = non_compliant_count - non_compliant_15_days - non_compliant_15_90_days
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "AssociationId": association_id[:255],
        "AssociationName": association.get("Name", "N/A")[:255],
        "Domain": association.get("DocumentName", "N/A")[:255],
        "CompliantResources": compliant_count,
        "NonCompliantResources": non_compliant_count,
        "CompliancePercentage": round(compliance_percentage, 2),
        "NonCompliant15Days": non_compliant_15_days,
        "NonCompliant15to90Days": non_compliant_15_90_days,
        "NonCompliant90Days": non_compliant_90_days,
        "Region": region[:50]
    }

def get_ssm_associations(region, credentials, account_id, account_name):
    """Obtiene asociaciones de SSM de una región."""
    ssm_client = create_aws_client("ssm", region, credentials)
    if not ssm_client:
        return []

    try:
        paginator = ssm_client.get_paginator('list_associations')
        associations_info = []

        for page in paginator.paginate():
            for association in page.get("Associations", []):
                info = extract_association_data(association, ssm_client, account_name, account_id, region)
                associations_info.append(info)
        

        return associations_info
    except ClientError as e:
        pass
        return []

def insert_or_update_ssm_data(ssm_data):
    """Inserta o actualiza datos de SSM en la base de datos con seguimiento de cambios."""
    if not ssm_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO ssm (
            account_name, account_id, association_id, association_name, domain,
            compliant_resources, non_compliant_resources, compliance_percentage,
            non_compliant_15_days, non_compliant_15_90_days, non_compliant_90_days,
            region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM ssm")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("association_id")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for association in ssm_data:
            association_id = association["AssociationId"]
            processed += 1

            insert_values = (
                association["AccountName"], association["AccountID"], association["AssociationId"],
                association["AssociationName"], association["Domain"], association["CompliantResources"],
                association["NonCompliantResources"], association["CompliancePercentage"],
                association["NonCompliant15Days"], association["NonCompliant15to90Days"],
                association["NonCompliant90Days"], association["Region"]
            )

            if association_id not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[association_id]
                updates = []
                values = []

                campos = {
                    "account_name": association["AccountName"],
                    "account_id": association["AccountID"],
                    "association_id": association["AssociationId"],
                    "association_name": association["AssociationName"],
                    "domain": association["Domain"],
                    "compliant_resources": association["CompliantResources"],
                    "non_compliant_resources": association["NonCompliantResources"],
                    "compliance_percentage": association["CompliancePercentage"],
                    "non_compliant_15_days": association["NonCompliant15Days"],
                    "non_compliant_15_90_days": association["NonCompliant15to90Days"],
                    "non_compliant_90_days": association["NonCompliant90Days"],
                    "region": association["Region"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_association_changed_by(
                            association_id=association_id,
                            update_date=datetime.now()
                        )
                        
                        log_change('SSM', association_id, col, old_val, new_val, changed_by, association["AccountID"], association["Region"])

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE ssm SET {', '.join(updates)} WHERE association_id = %s"
                    values.append(association_id)
                    cursor.execute(update_query, tuple(values))
                    updated += 1
                else:
                    cursor.execute("UPDATE ssm SET last_updated = CURRENT_TIMESTAMP WHERE association_id = %s", [association_id])

        conn.commit()
        return {
            "processed": processed,
            "inserted": inserted,
            "updated": updated
        }

    except Exception as e:
        conn.rollback()
        pass
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()