from botocore.exceptions import ClientError
from datetime import datetime
from services.utils import create_aws_client, get_db_connection, log_change, get_resource_changed_by

def extract_codebuild_data(project, account_name, account_id, region):
    try:
        source = project.get('source', {})
        source_type = source.get('type', 'N/A')
        repository = source.get('location', 'N/A')
        
        # Obtener último build
        last_build = project.get('lastModified')
        if last_build:
            if hasattr(last_build, 'replace'):
                # Remover timezone y formatear como string
                last_modified = last_build.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S.%f')
            else:
                # Si es string, parsearlo y normalizar formato
                try:
                    from dateutil.parser import parse
                    parsed_date = parse(str(last_build))
                    last_modified = parsed_date.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S.%f')
                except:
                    last_modified = str(last_build)
        else:
            last_modified = None
        
        return {
            "AccountName": account_name,
            "AccountID": account_id,
            "ProjectName": project.get('name', 'N/A'),
            "SourceProvider": source_type,
            "Repository": repository,
            "LastBuildStatus": "N/A",  # Requiere llamada adicional
            "Description": project.get('description', 'N/A'),
            "LastModified": last_modified
        }
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: CodeBuild extract {region}/{account_id}: {str(e)}")
        return None

def get_codebuild_projects(region, credentials, account_id, account_name):
    client = create_aws_client("codebuild", region, credentials)
    if not client: return []

    try:
        response = client.list_projects()
        project_names = response.get('projects', [])
        
        if not project_names:
            return []
            
        # Obtener detalles de proyectos
        details_response = client.batch_get_projects(names=project_names)
        projects = details_response.get('projects', [])
        
        return [
            info for project in projects
            if (info := extract_codebuild_data(project, account_name, account_id, region))
        ]
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: CodeBuild {region}/{account_id}: {str(e)}")
        return []

def insert_or_update_codebuild_data(codebuild_data):
    if not codebuild_data: return {"processed": 0, "inserted": 0, "updated": 0}
    conn = get_db_connection()
    if not conn: return {"error": "DB connection failed"}

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM codebuild")
        cols = [d[0].lower() for d in cur.description]
        existing = {(r[cols.index("project_name")], r[cols.index("account_id")]): dict(zip(cols, r)) for r in cur.fetchall()}

        ins, upd = 0, 0
        for project in codebuild_data:
            pn = project["ProjectName"]
            key = (pn, project["AccountID"])
            
            if key not in existing:
                cur.execute("""
                    INSERT INTO codebuild (account_name, account_id, project_name, source_provider,
                    repository, last_build_status, description, last_modified, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    project["AccountName"], project["AccountID"], pn, project["SourceProvider"],
                    project["Repository"], project["LastBuildStatus"], project["Description"],
                    project["LastModified"]
                ))
                ins += 1
            else:
                old_data = existing[key]
                
                # Comparar y registrar cambios
                fields_map = {
                    "source_provider": project["SourceProvider"],
                    "repository": project["Repository"],
                    "last_build_status": project["LastBuildStatus"],
                    "description": project["Description"],
                    "last_modified": project["LastModified"]
                }
                
                for field, new_val in fields_map.items():
                    old_val = old_data.get(field)
                    if str(old_val) != str(new_val):
                        changed_by = get_resource_changed_by(pn, 'CODEBUILD', datetime.now(), field)
                        log_change('CODEBUILD', pn, field, old_val, new_val, changed_by, 
                                 project["AccountID"], "us-east-1")
                
                updates_made = False
                for field, new_val in fields_map.items():
                    old_val = old_data.get(field)
                    if str(old_val) != str(new_val):
                        updates_made = True
                        changed_by = get_resource_changed_by(pn, 'CODEBUILD', datetime.now(), field)
                        log_change('CODEBUILD', pn, field, old_val, new_val, changed_by, 
                                 project["AccountID"], "us-east-1")
                
                if updates_made:
                    cur.execute("""
                        UPDATE codebuild SET source_provider=%s, repository=%s, last_build_status=%s,
                        description=%s, last_modified=%s, last_updated=NOW()
                        WHERE project_name=%s AND account_id=%s
                    """, (
                        project["SourceProvider"], project["Repository"], project["LastBuildStatus"],
                        project["Description"], project["LastModified"], pn, project["AccountID"]
                    ))
                    upd += 1
                else:
                    cur.execute("UPDATE codebuild SET last_updated=NOW() WHERE project_name=%s AND account_id=%s", [pn, project["AccountID"]])

        conn.commit()
        return {"processed": len(codebuild_data), "inserted": ins, "updated": upd}
    except Exception as e:
        conn.rollback()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: CodeBuild DB: {str(e)}")
        return {"error": str(e)}
    finally:
        conn.close()