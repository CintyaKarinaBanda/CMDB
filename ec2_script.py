#!/usr/bin/env python3
import boto3
import argparse
import json
from datetime import datetime
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

from listadoDeRoles import ROLES
from Servicios.ec2_functions import get_ec2_instances, insert_or_update_ec2_data
from Servicios.rds_functions import get_rds_instances, insert_or_update_rds_data
from Servicios.redshift_functions import get_redshift_clusters, insert_or_update_redshift_data
from Servicios.vpc_functions import get_vpc_details, insert_or_update_vpc_data
from Servicios.subnets_functions import get_subnets_details, insert_or_update_subnet_data
from Servicios.cloudtrail_functions import get_ec2_cloudtrail_events, insert_or_update_cloudtrail_events

from config import Regions

def assume_role(role_arn):
    """Asume un rol IAM y devuelve credenciales temporales."""
    try:
        response = boto3.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"EC2Session-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            DurationSeconds=900
        )
        credentials = response["Credentials"]
        return {
            "AccessKeyId": credentials["AccessKeyId"],
            "SecretAccessKey": credentials["SecretAccessKey"],
            "SessionToken": credentials["SessionToken"]
        }
    except ClientError as e:
        print(f"Error al asumir el rol {role_arn}: {str(e)}")
        return {"error": str(e)}

def process_account_region(account_id, role_name, account_name, region, requested_services):
    """Procesa una combinación de cuenta/región para los servicios solicitados."""
    start_time = datetime.now()
    print(f"[{account_id}:{region}] Iniciando procesamiento")
    
    # Asumir rol
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    credentials = assume_role(role_arn)

    if "error" in credentials:
        print(f"[{account_id}:{region}] Error al asumir rol: {credentials['error']}")
        return {"account_id": account_id, "region": region, "error": credentials["error"]}

    # Inicializar resultado
    result = {
        "account_id": account_id,
        "region": region,
        "credentials": credentials,
        "ec2_data": [],
        "rds_data": [],
        "redshift_data": [],
        "vpc_data": [],
        "subnets_data": [],
        "cloudtrail_events": []
    }

    # Tiempo límite para procesamiento
    timeout = 300  # 5 minutos
    
    try:
        # Mapeo de servicios a funciones
        service_functions = {
            "ec2": lambda: get_ec2_instances(region, credentials, account_id, account_name),
            "rds": lambda: get_rds_instances(region, credentials, account_id, account_name),
            "redshift": lambda: get_redshift_clusters(region, credentials, account_id, account_name),
            "vpc": lambda: get_vpc_details(region, credentials, account_id, account_name),
            "subnets": lambda: get_subnets_details(region, credentials, account_id, account_name),
            "cloudtrail_events": lambda: get_ec2_cloudtrail_events(region, credentials).get("events", [])
        }
        
        # Procesar cada servicio solicitado
        for service in requested_services:
            if (datetime.now() - start_time).total_seconds() > timeout:
                print(f"[{account_id}:{region}] Tiempo límite excedido")
                break
                
            if service not in service_functions:
                print(f"[{account_id}:{region}] Servicio no soportado: {service}")
                continue
                
            service_start = datetime.now()
            print(f"[{account_id}:{region}] Iniciando {service}")
            
            try:
                # Ejecutar función correspondiente
                result[f"{service}_data" if service != "cloudtrail_events" else service] = service_functions[service]()
                
                # Mostrar resultados
                key = f"{service}_data" if service != "cloudtrail_events" else service
                count = len(result[key])
                duration = (datetime.now() - service_start).total_seconds()
                print(f"[{account_id}:{region}] {service}: {count} items en {duration:.2f}s")
                
            except Exception as e:
                print(f"[{account_id}:{region}] Error en {service}: {str(e)}")
        
        total_duration = (datetime.now() - start_time).total_seconds()
        print(f"[{account_id}:{region}] Completado en {total_duration:.2f}s")
        return result
        
    except Exception as e:
        print(f"[{account_id}:{region}] Error general: {str(e)}")
        return {"account_id": account_id, "region": region, "error": str(e)}

def main(requested_services):
    """Función principal que coordina la recolección de datos."""
    start_time = datetime.now()
    print(f"=== Iniciando proceso: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    print(f"Servicios: {', '.join(requested_services)}")
    
    # Inicializar estructuras de datos
    errors = {}
    collected_data = {service: [] for service in requested_services}
    db_results = {}
    messages = []
    
    # Configuración de procesamiento paralelo
    max_workers = min(10, len(ROLES) * len(Regions))
    total_jobs = len(ROLES) * len(Regions)
    
    print(f"Procesando {len(ROLES)} cuentas × {len(Regions)} regiones = {total_jobs} combinaciones")
    print(f"Usando {max_workers} workers en paralelo")
    
    # Procesar cuentas/regiones en paralelo
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(process_account_region, role["id"], role["role"], 
                           role["account"], region, requested_services)
            for role in ROLES
            for region in Regions
        ]
        
        # Recopilar resultados
        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            account_id = result.get("account_id")
            region = result.get("region")
            
            print(f"[Progreso] {completed}/{total_jobs} ({completed/total_jobs*100:.1f}%)")

            # Manejar errores
            if "error" in result:
                errors.setdefault(account_id, []).append(f"{region}: {result['error']}")
                continue

            # Recopilar datos
            for service in requested_services:
                key = f"{service}_data" if service != "cloudtrail_events" else service
                data_list = result.get(key, [])
                
                if data_list:
                    collected_data[service].extend([{
                        "data": item,
                        "credentials": result["credentials"],
                        "region": region,
                        "account_id": account_id
                    } for item in data_list])
    
    # Mapeo de servicios a funciones de inserción
    service_insert_funcs = {
        "ec2": insert_or_update_ec2_data,
        "rds": insert_or_update_rds_data,
        "redshift": insert_or_update_redshift_data,
        "vpc": insert_or_update_vpc_data,
        "subnets": insert_or_update_subnet_data,
        "cloudtrail_events": insert_or_update_cloudtrail_events
    }
    
    # Insertar datos en la base de datos
    print("\n=== Insertando datos en la base de datos ===")
    
    for service in requested_services:
        if service not in service_insert_funcs:
            messages.append(f"{service.upper()}: Servicio no soportado")
            continue
            
        entries = collected_data.get(service, [])
        if not entries:
            messages.append(f"{service.upper()}: No hay datos para insertar")
            continue
            
        print(f"{service}: Procesando {len(entries)} entradas")
        
        # Agrupar por región y credenciales
        grouped = {}
        for entry in entries:
            key = (entry["region"], tuple(sorted(entry["credentials"].items())))
            grouped.setdefault(key, []).append(entry["data"])
        
        # Insertar cada grupo
        for (region, _), data_list in grouped.items():
            if not data_list:
                continue
                
            credentials = entries[0]["credentials"]
            result = service_insert_funcs[service](data_list, region, credentials)
            db_results.setdefault(service, []).append(result)
            
            messages.append(
                f"{service.upper()} ({region}): {len(data_list)} items "
                f"({result.get('inserted', 0)} insertados, {result.get('updated', 0)} actualizados)"
            )
    
    # Mostrar resultados
    print("\n=== Resultados ===")
    for message in messages:
        print(message)
    
    if errors:
        print(f"\nErrores en {len(errors)} cuentas:")
        for account_id, error_list in errors.items():
            print(f"- Cuenta {account_id}: {len(error_list)} errores")
    
    total_duration = (datetime.now() - start_time).total_seconds()
    print(f"\n=== Proceso completado en {total_duration:.2f} segundos ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Recolecta información de recursos AWS')
    parser.add_argument('--services', nargs='+', default=["ec2"],
                        choices=["ec2", "rds", "redshift", "vpc", "subnets", "cloudtrail_events"],
                        help='Servicios a consultar')
    args = parser.parse_args()
    
    main(args.services)