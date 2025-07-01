from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection

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
        print(f"[ERROR] changed_by: {api_id} - {str(e)}")
        return "unknown"
    finally:
        conn.close()

def extract_api_data(api, apigateway_client, account_name, account_id, region):
    """Extrae datos relevantes de una API Gateway"""
    tags = {}
    try:
        # Obtener tags de la API
        tags_response = apigateway_client.get_tags(resourceArn=f"arn:aws:apigateway:{region}::/restapis/{api['id']}")
        tags = tags_response.get('tags', {})
    except ClientError:
        pass  # Ignorar si no se pueden obtener tags
    
    get_tag = lambda key: tags.get(key, "N/A")
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "ApiId": api["id"],
        "Name": api.get("name", "N/A"),
        "Description": api.get("description", "N/A"),
        "Protocol": "REST",  # REST API por defecto
        "EndpointType": api.get("endpointConfiguration", {}).get("types", ["REGIONAL"])[0],
        "CreatedDate": api.get("createdDate"),
        "Region": region
    }

def extract_apiv2_data(api, apigatewayv2_client, account_name, account_id, region):
    """Extrae datos relevantes de una API Gateway v2 (HTTP/WebSocket)"""
    tags = api.get("Tags", {})
    get_tag = lambda key: tags.get(key, "N/A")
    
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "ApiId": api["ApiId"],
        "Name": api.get("Name", "N/A"),
        "Description": api.get("Description", "N/A"),
        "Protocol": api.get("ProtocolType", "HTTP"),
        "EndpointType": api.get("ApiEndpoint", "REGIONAL"),
        "CreatedDate": api.get("CreatedDate"),
        "Region": region
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
            print(f"[ERROR] API Gateway REST: {region}/{account_id} - {str(e)}")
    
    # Obtener HTTP/WebSocket APIs (v2)
    if apigatewayv2_client:
        try:
            paginator = apigatewayv2_client.get_paginator('get_apis')
            for page in paginator.paginate():
                for api in page.get("Items", []):
                    info = extract_apiv2_data(api, apigatewayv2_client, account_name, account_id, region)
                    apis_info.append(info)
        except ClientError as e:
            print(f"[ERROR] API Gateway v2: {region}/{account_id} - {str(e)}")
    
    if apis_info:
        print(f"INFO: API Gateway en {region}: {len(apis_info)} APIs encontradas")
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

    query_change_history = """
        INSERT INTO apigateway_changes_history (api_id, field_name, old_value, new_value, changed_by)
        VALUES (%s, %s, %s, %s, %s)
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

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_api_changed_by(
                            api_id=api_id,
                            update_date=datetime.now()
                        )
                        
                        cursor.execute(
                            query_change_history,
                            (api_id, col, str(old_val), str(new_val), changed_by)
                        )

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
        print(f"[ERROR] DB: apigateway_data - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()