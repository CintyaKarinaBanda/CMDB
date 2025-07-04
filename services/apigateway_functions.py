from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_api_changed_by(api_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'API-GATEWAY' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (api_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_api_data(api, apigateway_client, account_name, account_id, region):
    """Extrae datos relevantes de una API Gateway"""
    tags = {}
    try:
        tags_response = apigateway_client.get_tags(resourceArn=f"arn:aws:apigateway:{region}::/restapis/{api['id']}")
        tags = tags_response.get('tags', {})
    except ClientError:
        pass
    
    endpoint_types = api.get("endpointConfiguration", {}).get("types", ["REGIONAL"])
    endpoint_type = endpoint_types[0] if endpoint_types else "REGIONAL"
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "ApiId": api["id"][:255],
        "Name": (api.get("name", "N/A") or "N/A")[:500],
        "Description": (api.get("description", "N/A") or "N/A"),
        "Protocol": "REST"[:100],
        "EndpointType": endpoint_type[:255],
        "CreatedDate": api.get("createdDate"),
        "Region": region[:50]
    }

def extract_apiv2_data(api, apigatewayv2_client, account_name, account_id, region):
    """Extrae datos relevantes de una API Gateway v2 (HTTP/WebSocket)"""
    tags = api.get("Tags", {})
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "ApiId": api["ApiId"][:255],
        "Name": (api.get("Name", "N/A") or "N/A")[:500],
        "Description": (api.get("Description", "N/A") or "N/A"),
        "Protocol": (api.get("ProtocolType", "HTTP") or "HTTP")[:100],
        "EndpointType": (api.get("ApiEndpoint", "REGIONAL") or "REGIONAL")[:255],
        "CreatedDate": api.get("CreatedDate"),
        "Region": region[:50]
    }

def get_apigateway_apis(region, credentials, account_id, account_name):
    """Obtiene APIs de API Gateway de una región."""
    # Cliente para REST APIs (v1)
    apigateway_client = create_aws_client("apigateway", region, credentials)
    # Cliente para HTTP/WebSocket APIs (v2)
    apigatewayv2_client = create_aws_client("apigatewayv2", region, credentials)
    
    apis_info = []
    
    # Obtener REST APIs (v1)
    if apigateway_client:
        try:
            paginator = apigateway_client.get_paginator('get_rest_apis')
            for page in paginator.paginate():
                for api in page.get("items", []):
                    info = extract_api_data(api, apigateway_client, account_name, account_id, region)
                    apis_info.append(info)
        except ClientError as e:
            pass
    
    # Obtener HTTP/WebSocket APIs (v2)
    if apigatewayv2_client:
        try:
            paginator = apigatewayv2_client.get_paginator('get_apis')
            for page in paginator.paginate():
                for api in page.get("Items", []):
                    info = extract_apiv2_data(api, apigatewayv2_client, account_name, account_id, region)
                    apis_info.append(info)
        except ClientError as e:
            pass
    

    return apis_info

def insert_or_update_apigateway_data(apigateway_data):
    """Inserta o actualiza datos de API Gateway en la base de datos con seguimiento de cambios."""
    if not apigateway_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO apigateway (
            account_name, account_id, api_id, name, description,
            protocol, endpoint_type, created_date, region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """



    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM apigateway")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("api_id")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for api in apigateway_data:
            api_id = api["ApiId"]
            processed += 1

            insert_values = (
                api["AccountName"], api["AccountID"], api["ApiId"],
                api["Name"], api["Description"], api["Protocol"],
                api["EndpointType"], api["CreatedDate"], api["Region"]
            )

            if api_id not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[api_id]
                updates = []
                values = []

                campos = {
                    "account_name": api["AccountName"],
                    "account_id": api["AccountID"],
                    "api_id": api["ApiId"],
                    "name": api["Name"],
                    "description": api["Description"],
                    "protocol": api["Protocol"],
                    "endpoint_type": api["EndpointType"],
                    "created_date": api["CreatedDate"],
                    "region": api["Region"]
                }

                # Verificar si cambió el account_id o api_id (campos de identificación)
                if (str(db_row.get('account_id')) != str(api["AccountID"]) or 
                    str(db_row.get('api_id')) != str(api["ApiId"])):
                    # Si cambió la identificación, insertar como nuevo registro
                    cursor.execute(query_insert, insert_values)
                    inserted += 1
                    continue
                
                for col, new_val in campos.items():
                    # Saltar campos de identificación para actualizaciones
                    if col in ['account_id', 'api_id']:
                        continue
                    
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_api_changed_by(api_id, datetime.now())
                        log_change('API-GATEWAY', api_id, col, old_val, new_val, changed_by, api["AccountID"], api["Region"])

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE apigateway SET {', '.join(updates)} WHERE api_id = %s"
                    values.append(api_id)
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
        pass
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()