from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_server_changed_by(server_id, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'TRANSFER-FAMILY' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (server_id, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        pass
        return "unknown"
    finally:
        conn.close()

def extract_server_data(server, transfer_client, account_name, account_id, region):
    """Extrae datos relevantes de un servidor de Transfer Family"""
    server_id = server["ServerId"]
    
    # Obtener detalles adicionales del servidor
    try:
        server_details = transfer_client.describe_server(ServerId=server_id)
        server_info = server_details["Server"]
        
        # Información del endpoint
        endpoint_details = server_info.get("EndpointDetails", {})
        endpoint_type = server_info.get("EndpointType", "PUBLIC")
        
        # Construir información del endpoint
        if endpoint_type == "VPC":
            vpc_id = endpoint_details.get("VpcId", "N/A")
            subnet_ids = endpoint_details.get("SubnetIds", [])
            endpoint_info = f"VPC: {vpc_id}, Subnets: {len(subnet_ids)}"
        elif endpoint_type == "VPC_ENDPOINT":
            vpc_endpoint_id = endpoint_details.get("VpcEndpointId", "N/A")
            endpoint_info = f"VPC Endpoint: {vpc_endpoint_id}"
        else:
            endpoint_info = "Public"
        
        # Información del dominio
        domain = server_info.get("Domain", "S3")
        
        # Estado del servidor
        state = server_info.get("State", "UNKNOWN")
        
    except ClientError:
        endpoint_info = "N/A"
        domain = "S3"
        state = "UNKNOWN"
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "ServerId": server_id[:255],
        "Domain": domain[:255],
        "Endpoint": endpoint_info[:500],
        "State": state[:50],
        "Region": region[:50]
    }

def get_transfer_servers(region, credentials, account_id, account_name):
    """Obtiene servidores de Transfer Family de una región."""
    transfer_client = create_aws_client("transfer", region, credentials)
    if not transfer_client:
        return []

    try:
        paginator = transfer_client.get_paginator('list_servers')
        servers_info = []

        for page in paginator.paginate():
            for server in page.get("Servers", []):
                info = extract_server_data(server, transfer_client, account_name, account_id, region)
                servers_info.append(info)
        
        return servers_info
    except ClientError as e:
        pass
        return []

def insert_or_update_transfer_data(transfer_data):
    """Inserta o actualiza datos de Transfer Family en la base de datos con seguimiento de cambios."""
    if not transfer_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO transfer_family (
            account_name, account_id, server_id, domain, endpoint, state, region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """

    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM transfer_family")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {(row[columns.index("server_id")], row[columns.index("account_id")]): dict(zip(columns, row)) for row in cursor.fetchall()}

        for server in transfer_data:
            server_id = server["ServerId"]
            processed += 1

            insert_values = (
                server["AccountName"], server["AccountID"], server["ServerId"],
                server["Domain"], server["Endpoint"], server["State"], server["Region"]
            )

            if (server_id, server["AccountID"]) not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[(server_id, server["AccountID"])]
                updates = []
                values = []

                campos = {
                    "account_name": server["AccountName"],
                    "account_id": server["AccountID"],
                    "server_id": server["ServerId"],
                    "domain": server["Domain"],
                    "endpoint": server["Endpoint"],
                    "state": server["State"],
                    "region": server["Region"]
                }

                # Verificar si cambió el account_id o server_id (campos de identificación)
                if (str(db_row.get('account_id')) != str(server["AccountID"]) or 
                    str(db_row.get('server_id')) != str(server["ServerId"])):
                    # Si cambió la identificación, insertar como nuevo registro
                    cursor.execute(query_insert, insert_values)
                    inserted += 1
                    continue

                for col, new_val in campos.items():
                    # Saltar campos de identificación para actualizaciones
                    if col in ['account_id', 'server_id']:
                        continue
                    
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_server_changed_by(server_id, datetime.now())
                        log_change('TRANSFER-FAMILY', server_id, col, old_val, new_val, changed_by, server["AccountID"], server["Region"])

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE transfer_family SET {', '.join(updates)} WHERE server_id = %s AND account_id = %s"
                    values.extend([server_id, server["AccountID"]])
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