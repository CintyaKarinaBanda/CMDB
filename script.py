#!/usr/bin/env python3
import boto3, argparse
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

from listadoDeRoles import ROLES
from config import Regions
# DEBUG: Importaciones de servicios con manejo de errores
print("📦 DEBUG: Importando servicios...")
try:
    from services import (
        get_ec2_instances, insert_or_update_ec2_data,
        get_rds_instances, insert_or_update_rds_data,
        get_redshift_clusters, insert_or_update_redshift_data,
        get_vpc_details, insert_or_update_vpc_data,
        get_subnets_details, insert_or_update_subnet_data,
        get_all_cloudtrail_events, insert_or_update_cloudtrail_events,
        get_s3_buckets, insert_or_update_s3_data,
        get_eks_clusters, insert_or_update_eks_data,
        get_ecr_repositories, insert_or_update_ecr_data,
        get_kms_keys, insert_or_update_kms_data,
        get_lambda_functions, insert_or_update_lambda_data,
        get_apigateway_apis, insert_or_update_apigateway_data,
        get_glue_jobs, insert_or_update_glue_data,
        get_cloudformation_stacks, insert_or_update_cloudformation_data,
        get_cloudtrail_trails, insert_or_update_cloudtrail_trails_data,
        get_ssm_associations, insert_or_update_ssm_data,
        get_tax_queries, insert_or_update_tax_data,
        get_stepfunctions_state_machines, insert_or_update_stepfunctions_data,
        get_athena_queries, insert_or_update_athena_data,
        get_transfer_servers, insert_or_update_transfer_data,
        get_codepipeline_pipelines, insert_or_update_codepipeline_data,
        get_emr_clusters, insert_or_update_emr_data,
        get_codebuild_projects, insert_or_update_codebuild_data,
        get_sns_topics, insert_or_update_sns_data,
        get_route53_records, insert_or_update_route53_data
    )
    print("✅ DEBUG: Servicios importados correctamente")
except ImportError as e:
    print(f"❌ DEBUG: Error importando servicios: {e}")
    print(f"❌ DEBUG: Verifica que el directorio 'services' y sus archivos existan")
    exit(1)
except Exception as e:
    print(f"❌ DEBUG: Error inesperado importando servicios: {e}")
    exit(1)

def assume_role(role_arn):
    """Asume un rol IAM y devuelve credenciales temporales."""
    print(f"🔑 DEBUG: Intentando asumir rol: {role_arn}")
    try:
        # DEBUG: Verificar credenciales actuales
        sts_client = boto3.client("sts")
        try:
            current_identity = sts_client.get_caller_identity()
            print(f"🔍 DEBUG: Identidad actual: {current_identity.get('Arn', 'N/A')}")
        except Exception as e:
            print(f"⚠️ DEBUG: No se pudo obtener identidad actual: {e}")
        
        creds = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"EC2Session-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            DurationSeconds=900
        )["Credentials"]
        print(f"✅ DEBUG: Rol asumido exitosamente: {role_arn}")
        return {k: creds[k] for k in ["AccessKeyId", "SecretAccessKey", "SessionToken"]}
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        print(f"❌ DEBUG: Error asumiendo rol {role_arn}:")
        print(f"  - Código: {error_code}")
        print(f"  - Mensaje: {error_msg}")
        return {"error": f"{error_code}: {error_msg}"}
    except Exception as e:
        print(f"❌ DEBUG: Error inesperado asumiendo rol {role_arn}: {str(e)}")
        return {"error": str(e)}

def get_service_funcs(region, creds, account_id, account_name):
    """Retorna el diccionario de funciones de servicios"""
    return {
        "ec2": lambda: get_ec2_instances(region, creds, account_id, account_name),
        "rds": lambda: get_rds_instances(region, creds, account_id, account_name),
        "redshift": lambda: get_redshift_clusters(region, creds, account_id, account_name),
        "vpc": lambda: get_vpc_details(region, creds, account_id, account_name),
        "subnets": lambda: get_subnets_details(region, creds, account_id, account_name),
        "cloudtrail": lambda: get_all_cloudtrail_events(region, creds, account_id, account_name).get("events", []),
        "s3": lambda: get_s3_buckets(region, creds, account_id, account_name),
        "eks": lambda: get_eks_clusters(region, creds, account_id, account_name),
        "ecr": lambda: get_ecr_repositories(region, creds, account_id, account_name),
        "kms": lambda: get_kms_keys(region, creds, account_id, account_name),
        "lambda": lambda: get_lambda_functions(region, creds, account_id, account_name),
        "apigateway": lambda: get_apigateway_apis(region, creds, account_id, account_name),
        "glue": lambda: get_glue_jobs(region, creds, account_id, account_name),
        "cloudformation": lambda: get_cloudformation_stacks(region, creds, account_id, account_name),
        "cloudtrail_trails": lambda: get_cloudtrail_trails(region, creds, account_id, account_name),
        "ssm": lambda: get_ssm_associations(region, creds, account_id, account_name),
        "tax": lambda: get_tax_queries(region, creds, account_id, account_name),
        "stepfunctions": lambda: get_stepfunctions_state_machines(region, creds, account_id, account_name),
        "athena": lambda: get_athena_queries(region, creds, account_id, account_name),
        "transfer": lambda: get_transfer_servers(region, creds, account_id, account_name),
        "codepipeline": lambda: get_codepipeline_pipelines(region, creds, account_id, account_name),
        "emr": lambda: get_emr_clusters(region, creds, account_id, account_name),
        "codebuild": lambda: get_codebuild_projects(region, creds, account_id, account_name),
        "sns": lambda: get_sns_topics(region, creds, account_id, account_name),
        "route53": lambda: get_route53_records(region, creds, account_id, account_name)
    }

def process_account_region(account_id, role_name, account_name, region, services):
    print(f"🔍 DEBUG: Procesando cuenta {account_id} ({account_name}) en región {region}")
    creds = assume_role(f"arn:aws:iam::{account_id}:role/{role_name}")
    if "error" in creds:
        print(f"❌ DEBUG: Error en credenciales para {account_id}-{region}: {creds['error']}")
        return {"account_id": account_id, "region": region, "error": creds["error"]}



    # Obtener funciones de servicios para esta cuenta/región
    service_funcs = get_service_funcs(region, creds, account_id, account_name)
    
    result = {"account_id": account_id, "region": region, "credentials": creds}
    for service in services:
        try:
            print(f"📊 DEBUG: Recolectando {service} para {account_id}-{region}")
            start_time = datetime.now()
            data = service_funcs.get(service, lambda: [])()
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            result[f"{service}_data"] = data
            print(f"✅ DEBUG: {service} - {len(data) if isinstance(data, list) else 'N/A'} elementos recolectados en {duration:.1f}s")
        except Exception as e:
            print(f"❌ DEBUG: Error recolectando {service} en {account_id}-{region}:")
            print(f"  - Tipo: {type(e).__name__}")
            print(f"  - Mensaje: {str(e)}")
            if hasattr(e, 'response'):
                error_code = e.response.get('Error', {}).get('Code', 'N/A')
                print(f"  - Código AWS: {error_code}")
            result[f"{service}_data"] = []
    return result

def main(services):
    """Función principal que coordina la recolección de datos."""
    start = datetime.now()
    local_time = datetime.fromtimestamp(time.time())
    print(f"=== Iniciando proceso: {local_time.strftime('%Y-%m-%d %H:%M:%S')} ===")
    print(f"Servicios: {', '.join(services)}")
    
    # DEBUG: Verificar configuraciones
    print(f"🔧 DEBUG: Regiones configuradas: {Regions}")
    print(f"🔧 DEBUG: Total de roles: {len(ROLES)}")
    print(f"🔧 DEBUG: Primeros 3 roles: {ROLES[:3]}")
    print(f"🔧 DEBUG: Base de datos: {DB_HOST}:{DB_NAME}")
    
    # DEBUG: Verificar servicios disponibles
    available_services = ["ec2", "rds", "redshift", "vpc", "subnets", "cloudtrail", "s3", "eks", "ecr", "kms", "lambda", "apigateway", "glue", "cloudformation", "cloudtrail_trails", "ssm", "tax", "stepfunctions", "athena", "transfer", "codepipeline", "emr", "codebuild", "sns", "route53"]
    print(f"🔧 DEBUG: Servicios disponibles: {available_services}")
    
    # DEBUG: Verificar que los servicios solicitados estén disponibles
    missing_services = [s for s in services if s not in available_services]
    if missing_services:
        print(f"⚠️ DEBUG: Servicios no disponibles: {missing_services}")

    errors, collected_data, messages = {}, {s: [] for s in services}, []
    max_workers = min(10, len(ROLES) * len(Regions))
    total_jobs = len(ROLES) * len(Regions)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(process_account_region, r["id"], r["role"], 
                          r["account"], reg, services)
            for r in ROLES for reg in Regions
        ]
        
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            if i % 10 == 0 or i == total_jobs:
                print(f"[{i}/{total_jobs}]")
            
            if "error" in res:
                print(f"❌ DEBUG: Error procesando {res['account_id']}-{res['region']}: {res['error']}")
                errors.setdefault(res["account_id"], []).append(f"{res['region']}: {res['error']}")
                continue
            
            for s in services:
                key = f"{s}_data" if s != "cloudtrail_events" else s
                service_data = res.get(key, [])
                print(f"📈 DEBUG: Servicio {s} - {len(service_data) if isinstance(service_data, list) else 'N/A'} elementos de {res['account_id']}-{res['region']}")
                collected_data[s].extend([{
                    "data": d, "credentials": res["credentials"],
                    "region": res["region"], "account_id": res["account_id"]
                } for d in service_data])



    insert_funcs = {
        "ec2": insert_or_update_ec2_data,
        "rds": insert_or_update_rds_data,
        "redshift": insert_or_update_redshift_data,
        "vpc": insert_or_update_vpc_data,
        "subnets": insert_or_update_subnet_data,
        "cloudtrail": insert_or_update_cloudtrail_events,
        "s3": insert_or_update_s3_data,
        "eks": insert_or_update_eks_data,
        "ecr": insert_or_update_ecr_data,
        "kms": insert_or_update_kms_data,
        "lambda": insert_or_update_lambda_data,
        "apigateway": insert_or_update_apigateway_data,
        "glue": insert_or_update_glue_data,
        "cloudformation": insert_or_update_cloudformation_data,
        "cloudtrail_trails": insert_or_update_cloudtrail_trails_data,
        "ssm": insert_or_update_ssm_data,
        "tax": insert_or_update_tax_data,
        "stepfunctions": insert_or_update_stepfunctions_data,
        "athena": insert_or_update_athena_data,
        "transfer": insert_or_update_transfer_data,
        "codepipeline": insert_or_update_codepipeline_data,
        "emr": insert_or_update_emr_data,
        "codebuild": insert_or_update_codebuild_data,
        "sns": insert_or_update_sns_data,
        "route53": insert_or_update_route53_data
    }

    for s in services:
        entries = collected_data.get(s, [])
        print(f"💾 DEBUG: Insertando {s} - {len(entries)} entradas totales")
        
        if not entries:
            print(f"⚠️ DEBUG: No hay datos para insertar en {s}")
            messages.append(f"{s.upper()}: 0 cambios")
            continue
        
        grouped = {}
        for e in entries:
            key = (e["region"], tuple(sorted(e["credentials"].items())))
            grouped.setdefault(key, []).append(e["data"])
        
        total_inserted = total_updated = 0
        for (reg, _), data in grouped.items():
            print(f"🔄 DEBUG: Insertando {len(data)} elementos de {s} en región {reg}")
            try:
                res = insert_funcs[s](data)
                inserted = res.get('inserted', 0)
                updated = res.get('updated', 0)
                total_inserted += inserted
                total_updated += updated
                print(f"✅ DEBUG: {s} - {inserted} insertados, {updated} actualizados en {reg}")
            except Exception as e:
                print(f"❌ DEBUG: Error insertando {s} en {reg}: {str(e)}")
        
        # Mostrar estadísticas para todos los servicios
        if total_inserted and total_updated:
            status = f"{total_inserted} nuevos, {total_updated} actualizados"
        elif total_inserted:
            status = f"{total_inserted} nuevos"
        elif total_updated:
            status = f"{total_updated} actualizados"
        else:
            status = "0 cambios"
        
        messages.append(f"{s.upper()}: {status}")

    print(f"✅ Completado: {' | '.join(messages)} | ⏱️ {(datetime.now() - start).total_seconds():.0f}s")
    if errors:
        print(f"❌ {len(errors)} cuentas sin acceso")

if __name__ == "__main__":
    print("🚀 DEBUG: Iniciando script...")
    
    # DEBUG: Verificar importaciones críticas
    try:
        from config import Regions, DB_HOST, DB_NAME, DB_USER, DB_PASSWORD
        print(f"✅ DEBUG: Config importado correctamente")
    except ImportError as e:
        print(f"❌ DEBUG: Error importando config: {e}")
        exit(1)
    
    try:
        from listadoDeRoles import ROLES
        print(f"✅ DEBUG: Roles importados correctamente ({len(ROLES)} roles)")
    except ImportError as e:
        print(f"❌ DEBUG: Error importando roles: {e}")
        exit(1)
    
    parser = argparse.ArgumentParser(description='Recolecta información de recursos AWS')
    parser.add_argument('--services', nargs='+', default=["ec2", "cloudtrail"],
                      choices=["ec2", "rds", "redshift", "vpc", "subnets", "cloudtrail", "s3", "eks", "ecr", "kms", "lambda", "apigateway", "glue", "cloudformation", "cloudtrail_trails", "ssm", "tax", "stepfunctions", "athena", "transfer", "codepipeline", "emr", "codebuild", "sns", "route53", "all"],
                      help='Servicios a consultar')
    args = parser.parse_args()
    services = ["ec2", "rds", "redshift", "vpc", "subnets", "s3", "eks", "ecr", "kms", "lambda", "apigateway", "glue", "cloudformation", "cloudtrail_trails", "ssm", "tax", "stepfunctions",  "athena", "transfer", "codepipeline", "emr", "codebuild", "sns", "route53"] if "all" in args.services else args.services
    
    print(f"🎯 DEBUG: Servicios seleccionados: {services}")
    main(services)