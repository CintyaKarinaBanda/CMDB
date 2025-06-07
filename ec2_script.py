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
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role(
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
    start_time = datetime.now()
    print(f"[{account_id}:{region}] Iniciando procesamiento")
    
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    credentials = assume_role(role_arn)

    if isinstance(credentials, dict) and "error" in credentials:
        print(f"[{account_id}:{region}] Error al asumir rol: {credentials['error']}")
        return {"account_id": account_id, "region": region, "error": credentials["error"]}

    print(f"[{account_id}:{region}] Rol asumido correctamente")
    
    result = {
        "account_id": account_id,
        "region": region,
        "credentials": credentials,
        "ec2_data": [],
        "ec2_events": [],
        "rds_data": [],
        "redshift_data": [],
        "vpc_data": [],
        "subnets_data": [],
        "cloudtrail_events": []
    }

    try:
        for service in requested_services:
            service_start = datetime.now()
            print(f"[{account_id}:{region}] Iniciando recolección de datos para {service}")
            
            if service == "ec2":
                result["ec2_data"] = get_ec2_instances(region, credentials, account_id, account_name)
                print(f"[{account_id}:{region}] EC2: {len(result['ec2_data'])} instancias encontradas")
            
            elif service == "rds":
                result["rds_data"] = get_rds_instances(region, credentials, account_id, account_name)
                print(f"[{account_id}:{region}] RDS: {len(result['rds_data'])} instancias encontradas")
            
            elif service == "redshift":
                result["redshift_data"] = get_redshift_clusters(region, credentials, account_id, account_name)
                print(f"[{account_id}:{region}] Redshift: {len(result['redshift_data'])} clusters encontrados")
            
            elif service == "vpc":
                result["vpc_data"] = get_vpc_details(region, credentials, account_id, account_name)
                print(f"[{account_id}:{region}] VPC: {len(result['vpc_data'])} VPCs encontradas")
            
            elif service == "subnets":
                result["subnets_data"] = get_subnets_details(region, credentials, account_id, account_name)
                print(f"[{account_id}:{region}] Subnets: {len(result['subnets_data'])} subnets encontradas")
            
            elif service == "cloudtrail_events":
                cloudtrail_result = get_ec2_cloudtrail_events(region, credentials)
                result["cloudtrail_events"] = cloudtrail_result.get("events", [])
                print(f"[{account_id}:{region}] CloudTrail: {len(result['cloudtrail_events'])} eventos encontrados")
            
            service_duration = (datetime.now() - service_start).total_seconds()
            print(f"[{account_id}:{region}] {service} completado en {service_duration:.2f} segundos")

        total_duration = (datetime.now() - start_time).total_seconds()
        print(f"[{account_id}:{region}] Procesamiento completado en {total_duration:.2f} segundos")
        return result

    except Exception as e:
        error_duration = (datetime.now() - start_time).total_seconds()
        print(f"[{account_id}:{region}] Error después de {error_duration:.2f} segundos: {str(e)}")
        return {"account_id": account_id, "region": region, "error": str(e)}


def main(requested_services):
    start_time = datetime.now()
    print(f"=== Iniciando proceso completo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")

    errors = {}
    collected_data = {
        "ec2": [],
        "ec2_events": [],
        "rds": [],
        "redshift": [],
        "vpc": [],
        "subnets": [],
        "cloudtrail_events": []
    }

    db_results = {}
    messages = []

    print(f"Iniciando recolección de datos para servicios: {', '.join(requested_services)}")
    print(f"Total de cuentas: {len(ROLES)}, Regiones: {len(Regions)}, Total de combinaciones: {len(ROLES) * len(Regions)}")
    
    collection_start = datetime.now()
    with ThreadPoolExecutor(max_workers=20) as executor:
        print(f"Iniciando ThreadPoolExecutor con 20 workers")
        
        futures = [
            executor.submit(process_account_region, role["id"], role["role"], role["account"], region, requested_services)
            for role in ROLES
            for region in Regions
        ]
        
        total_futures = len(futures)
        completed = 0
        
        print(f"Enviados {total_futures} trabajos al executor")
        
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            account_id = result.get("account_id")
            region = result.get("region")
            
            print(f"[Progreso] {completed}/{total_futures} ({completed/total_futures*100:.1f}%) completados")

            if "error" in result:
                errors.setdefault(account_id, []).append(f"{region}: {result['error']}")
                continue

            for service in requested_services:
                service_key = f"{service}_data" if service != "cloudtrail_events" else "cloudtrail_events"
                data_list = result.get(service_key, [])
                if data_list:
                    collected_data[service].extend([{
                        "data": item,
                        "credentials": result["credentials"],
                        "region": region,
                        "account_id": account_id
                    } for item in data_list])
    
    collection_duration = (datetime.now() - collection_start).total_seconds()
    print(f"Recolección de datos completada en {collection_duration:.2f} segundos")

    service_insert_funcs = {
        "ec2": insert_or_update_ec2_data,
        "rds": insert_or_update_rds_data,
        "redshift": insert_or_update_redshift_data,
        "vpc": insert_or_update_vpc_data,
        "subnets": insert_or_update_subnet_data,
        "cloudtrail_events": insert_or_update_cloudtrail_events
    }

    print("\n=== Iniciando inserción de datos en la base de datos ===")
    db_start = datetime.now()
    
    for service in requested_services:
        service_start = datetime.now()
        print(f"Procesando servicio: {service}")
        
        insert_func = service_insert_funcs.get(service)
        if not insert_func:
            messages.append(f"{service.upper()}: Servicio no soportado o sin función de inserción")
            continue

        service_entries = collected_data.get(service, [])
        print(f"{service}: {len(service_entries)} entradas recolectadas")
        
        if not service_entries:
            print(f"{service}: No hay datos para insertar")
            continue
            
        # Agrupar por región y credenciales
        group_start = datetime.now()
        grouped = {}
        for entry in service_entries:
            key = (entry["region"], tuple(sorted(entry["credentials"].items())))
            grouped.setdefault(key, []).append(entry["data"])
        
        group_duration = (datetime.now() - group_start).total_seconds()
        print(f"{service}: Agrupación completada en {group_duration:.2f} segundos, {len(grouped)} grupos")

        # Insertar datos por grupo
        for i, ((region, _), data_list) in enumerate(grouped.items()):
            if not data_list:
                continue

            insert_start = datetime.now()
            print(f"{service} ({region}): Insertando {len(data_list)} items (grupo {i+1}/{len(grouped)})")
            
            credentials = service_entries[0]["credentials"] if service_entries else None
            result = insert_func(data_list, region, credentials)
            
            insert_duration = (datetime.now() - insert_start).total_seconds()
            print(f"{service} ({region}): Inserción completada en {insert_duration:.2f} segundos")
            
            db_results.setdefault(service, []).append(result)
            messages.append(
                f"{service.upper()} ({region}): {len(data_list)} items "
                f"({result.get('inserted', 0)} insertados, {result.get('updated', 0)} actualizados)"
            )
        
        service_duration = (datetime.now() - service_start).total_seconds()
        print(f"{service}: Procesamiento completado en {service_duration:.2f} segundos")
    
    db_duration = (datetime.now() - db_start).total_seconds()
    print(f"Inserción en base de datos completada en {db_duration:.2f} segundos")
    
    # Mostrar resumen
    print("\n=== Resumen de resultados ===")
    for message in messages:
        print(message)
    
    if errors:
        print(f"\nSe encontraron errores en {len(errors)} cuentas")
        for account_id, error_list in errors.items():
            print(f"Cuenta {account_id}: {len(error_list)} errores")
    
    total_duration = (datetime.now() - start_time).total_seconds()
    print(f"\n=== Proceso completado en {total_duration:.2f} segundos ===")
    print(f"Hora de finalización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    requested_services=['ec2']
    main(requested_services)