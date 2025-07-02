from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change

def get_job_changed_by(job_name, update_date):
    """Busca el usuario que realizó el cambio más cercano a la fecha de actualización"""
    conn = get_db_connection()
    if not conn:
        return "unknown"
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_name FROM cloudtrail_events
                WHERE resource_type = 'GLUE' AND resource_name = %s 
                AND ABS(EXTRACT(EPOCH FROM (event_time - %s))) < 86400
                ORDER BY ABS(EXTRACT(EPOCH FROM (event_time - %s))) ASC LIMIT 1
            """, (job_name, update_date, update_date))
            
            if result := cursor.fetchone():
                return result[0]
            return "unknown"
    except Exception as e:
        print(f"[ERROR] changed_by: {job_name} - {str(e)}")
        return "unknown"
    finally:
        conn.close()

def extract_job_data(job, glue_client, account_name, account_id, region):
    """Extrae datos relevantes de un job de Glue"""
    tags = {}
    try:
        # Obtener tags del job
        tags_response = glue_client.get_tags(ResourceArn=f"arn:aws:glue:{region}:{account_id}:job/{job['Name']}")
        tags = tags_response.get('Tags', {})
    except ClientError:
        pass  # Ignorar si no se pueden obtener tags
    
    get_tag = lambda key: tags.get(key, "N/A")
    
    # Determinar el tipo de job basado en el comando
    command_name = job.get('Command', {}).get('Name', '')
    if command_name == 'glueetl':
        job_type = "ETL"
    elif command_name == 'pythonshell':
        job_type = "Python Shell"
    elif command_name == 'gluestreaming':
        job_type = "Streaming"
    else:
        job_type = "ETL"  # Por defecto
    
    # Determinar el creador basado en el origen del job
    created_by = "N/A"
    if 'CodeGenConfigurationNodes' in job:
        created_by = "Visual"  # Creado con Glue Studio Visual
    elif job.get('Command', {}).get('ScriptLocation', '').endswith('.ipynb'):
        created_by = "Notebook"  # Creado con Notebook
    elif job.get('Command', {}).get('ScriptLocation'):
        created_by = "Script"  # Creado con Script
    else:
        # Intentar determinar por otros indicadores
        if job.get('DefaultArguments', {}).get('--enable-glue-datacatalog') == 'true':
            created_by = "Script"
        else:
            created_by = "Visual"  # Asumir Visual por defecto
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "JobName": job["Name"][:255],
        "Type": job_type[:100],
        "Domain": job.get("CreatedOn"),  # Fecha de creación como dominio
        "CreatedBy": created_by[:255],
        "GlueVersion": job.get("GlueVersion", "N/A")[:50],
        "Region": region[:50]
    }

def get_glue_jobs(region, credentials, account_id, account_name):
    """Obtiene jobs de Glue de una región."""
    glue_client = create_aws_client("glue", region, credentials)
    if not glue_client:
        return []

    try:
        paginator = glue_client.get_paginator('get_jobs')
        jobs_info = []

        for page in paginator.paginate():
            for job in page.get("Jobs", []):
                info = extract_job_data(job, glue_client, account_name, account_id, region)
                jobs_info.append(info)
        
        if jobs_info:
            print(f"INFO: Glue en {region}: {len(jobs_info)} jobs encontrados")
        return jobs_info
    except ClientError as e:
        print(f"[ERROR] Glue: {region}/{account_id} - {str(e)}")
        return []

def insert_or_update_glue_data(glue_data):
    """Inserta o actualiza datos de Glue en la base de datos con seguimiento de cambios."""
    if not glue_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO glue (
            account_name, account_id, job_name, type, domain,
            created_by, glue_version, region, last_updated
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
        )
    """



    inserted = 0
    updated = 0
    processed = 0

    try:
        cursor = conn.cursor()

        # Obtener datos existentes
        cursor.execute("SELECT * FROM glue")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {row[columns.index("job_name")]: dict(zip(columns, row)) for row in cursor.fetchall()}

        for job in glue_data:
            job_name = job["JobName"]
            processed += 1

            insert_values = (
                job["AccountName"], job["AccountID"], job["JobName"],
                job["Type"], job["Domain"], job["CreatedBy"],
                job["GlueVersion"], job["Region"]
            )

            if job_name not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[job_name]
                updates = []
                values = []

                campos = {
                    "account_name": job["AccountName"],
                    "account_id": job["AccountID"],
                    "job_name": job["JobName"],
                    "type": job["Type"],
                    "domain": job["Domain"],
                    "created_by": job["CreatedBy"],
                    "glue_version": job["GlueVersion"],
                    "region": job["Region"]
                }

                for col, new_val in campos.items():
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_job_changed_by(
                            job_name=job_name,
                            update_date=datetime.now()
                        )
                        
                        log_change('GLUE', job_name, col, old_val, new_val, changed_by, job["AccountID"], job["Region"])

                updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE glue SET {', '.join(updates)} WHERE job_name = %s"
                    values.append(job_name)
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
        print(f"[ERROR] DB: glue_data - {str(e)}")
        return {"error": str(e), "processed": 0, "inserted": 0, "updated": 0}
    finally:
        conn.close()