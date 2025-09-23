from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change, get_resource_changed_by

def extract_pipeline_data(pipeline, codepipeline_client, account_name, account_id, region):
    """Extrae datos relevantes de un pipeline de CodePipeline"""
    pipeline_name = pipeline["name"]
    
    # Obtener estado de la última ejecución
    try:
        executions_response = codepipeline_client.list_pipeline_executions(
            pipelineName=pipeline_name,
            maxResults=5
        )
        executions = executions_response.get("pipelineExecutionSummaries", [])
        
        if executions:
            latest_execution = executions[0]
            last_execution_status = latest_execution.get("status", "Unknown")
            
            # Manejar fecha de última ejecución
            start_time = latest_execution.get("startTime")
            if start_time:
                if hasattr(start_time, 'replace'):
                    # Remover timezone y formatear como string
                    last_execution_started = start_time.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S.%f')
                else:
                    try:
                        from dateutil.parser import parse
                        parsed_date = parse(str(start_time))
                        last_execution_started = parsed_date.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S.%f')
                    except:
                        last_execution_started = str(start_time)
            else:
                last_execution_started = None
            
            # Obtener revisiones de origen
            source_revisions = latest_execution.get("sourceRevisions", [])
            latest_source_revisions = []
            for revision in source_revisions[:3]:  # Máximo 3 revisiones
                action_name = revision.get("actionName", "N/A")
                revision_id = revision.get("revisionId", "N/A")[:10]  # Primeros 10 caracteres
                latest_source_revisions.append(f"{action_name}:{revision_id}")
            
            source_revisions_str = ", ".join(latest_source_revisions) if latest_source_revisions else "N/A"
            recent_executions_count = len(executions)
        else:
            last_execution_status = "Never executed"
            last_execution_started = None
            source_revisions_str = "N/A"
            recent_executions_count = 0
            
    except ClientError:
        last_execution_status = "Unknown"
        last_execution_started = None
        source_revisions_str = "N/A"
        recent_executions_count = 0
    
    return {
        "AccountName": account_name[:255],
        "AccountID": account_id[:20],
        "PipelineName": pipeline_name[:255],
        "LastExecutionStatus": last_execution_status[:100],
        "LatestSourceRevisions": source_revisions_str[:500],
        "LastExecutionStarted": last_execution_started,
        "RecentExecutions": recent_executions_count,
        "Region": region[:50]
    }

def get_codepipeline_pipelines(region, credentials, account_id, account_name):
    """Obtiene pipelines de CodePipeline de una región."""
    codepipeline_client = create_aws_client("codepipeline", region, credentials)
    if not codepipeline_client:
        return []

    try:
        paginator = codepipeline_client.get_paginator('list_pipelines')
        pipelines_info = []

        for page in paginator.paginate():
            for pipeline in page.get("pipelines", []):
                info = extract_pipeline_data(pipeline, codepipeline_client, account_name, account_id, region)
                pipelines_info.append(info)
        
        return pipelines_info
    except ClientError as e:
        pass
        return []

def insert_or_update_codepipeline_data(codepipeline_data):
    """Inserta o actualiza datos de CodePipeline en la base de datos con seguimiento de cambios."""
    if not codepipeline_data:
        return {"processed": 0, "inserted": 0, "updated": 0}

    conn = get_db_connection()
    if not conn:
        return {"error": "DB connection failed", "processed": 0, "inserted": 0, "updated": 0}

    query_insert = """
        INSERT INTO codepipeline (
            account_name, account_id, pipeline_name, last_execution_status,
            latest_source_revisions, last_execution_started, recent_executions,
            region, last_updated
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
        cursor.execute("SELECT * FROM codepipeline")
        columns = [desc[0].lower() for desc in cursor.description]
        existing_data = {(row[columns.index("pipeline_name")], row[columns.index("account_id")]): dict(zip(columns, row)) for row in cursor.fetchall()}

        for pipeline in codepipeline_data:
            pipeline_name = pipeline["PipelineName"]
            processed += 1

            insert_values = (
                pipeline["AccountName"], pipeline["AccountID"], pipeline["PipelineName"],
                pipeline["LastExecutionStatus"], pipeline["LatestSourceRevisions"],
                pipeline["LastExecutionStarted"], pipeline["RecentExecutions"], pipeline["Region"]
            )

            if (pipeline_name, pipeline["AccountID"]) not in existing_data:
                cursor.execute(query_insert, insert_values)
                inserted += 1
            else:
                db_row = existing_data[(pipeline_name, pipeline["AccountID"])]
                updates = []
                values = []

                campos = {
                    "account_name": pipeline["AccountName"],
                    "account_id": pipeline["AccountID"],
                    "pipeline_name": pipeline["PipelineName"],
                    "last_execution_status": pipeline["LastExecutionStatus"],
                    "latest_source_revisions": pipeline["LatestSourceRevisions"],
                    "last_execution_started": pipeline["LastExecutionStarted"],
                    "recent_executions": pipeline["RecentExecutions"],
                    "region": pipeline["Region"]
                }

                # Verificar si cambió el account_id o pipeline_name (campos de identificación)
                if (str(db_row.get('account_id')) != str(pipeline["AccountID"]) or 
                    str(db_row.get('pipeline_name')) != str(pipeline["PipelineName"])):
                    # Si cambió la identificación, insertar como nuevo registro
                    cursor.execute(query_insert, insert_values)
                    inserted += 1
                    continue

                for col, new_val in campos.items():
                    # Saltar campos de identificación para actualizaciones
                    if col in ['account_id', 'pipeline_name']:
                        continue
                    
                    old_val = db_row.get(col)
                    if str(old_val) != str(new_val):
                        updates.append(f"{col} = %s")
                        values.append(new_val)
                        changed_by = get_resource_changed_by(pipeline_name, 'CODEPIPELINE', datetime.now(), col)
                        log_change('CODEPIPELINE', pipeline_name, col, old_val, new_val, changed_by, pipeline["AccountID"], pipeline["Region"])

                if updates:
                    updates.append("last_updated = CURRENT_TIMESTAMP")

                if updates:
                    update_query = f"UPDATE codepipeline SET {', '.join(updates)} WHERE pipeline_name = %s AND account_id = %s"
                    values.extend([pipeline_name, pipeline["AccountID"]])
                    cursor.execute(update_query, tuple(values))
                    updated += 1
                else:
                    cursor.execute("UPDATE [TABLE] SET last_updated = [TIMESTAMP] WHERE [KEY] = %s", [[ID]])

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