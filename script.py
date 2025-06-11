#!/usr/bin/env python3
import boto3, argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

from listadoDeRoles import ROLES
from config import Regions
from Servicios import *

RESOURCES = ["ec2", "rds", "redshift", "vpc", "subnets"]
EVENTS = ["ec2_cloudtrail", "rds_cloudtrail", "vpc_cloudtrail"]
DEPENDENCIES = {"ec2_cloudtrail": "ec2", "rds_cloudtrail": "rds", "vpc_cloudtrail": "vpc"}

def assume_role(role_arn):
    """Asume un rol IAM y devuelve credenciales temporales."""
    try:
        creds = boto3.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"Session-{datetime.now().strftime('%H%M%S')}",
            DurationSeconds=900
        )["Credentials"]
        return {k: creds[k] for k in ["AccessKeyId", "SecretAccessKey", "SessionToken"]}
    except ClientError as e:
        log(f"ERROR: Rol {role_arn}: {e}")
        return {"error": str(e)}

def process_account_region(account_id, role_name, account_name, region, services):
    """Procesa una combinación de cuenta/región para los servicios solicitados."""
    
    start = datetime.now()
    creds = assume_role(f"arn:aws:iam::{account_id}:role/{role_name}")
    if "error" in creds:
        return {"account_id": account_id, "region": region, "error": creds["error"]}

    ordered_services = [s for s in services if s in RESOURCES] + [s for s in services if s in EVENTS]
    result = {"account_id": account_id, "region": region, "credentials": creds}
    
    for service in ordered_services:
        if (datetime.now() - start).total_seconds() > 300:  # 5 min timeout
            log(f"TIMEOUT: {account_id}:{region}")
            break
        try:
            if service in RESOURCES:
                func_name = f"get_{service}_instances" if service not in ["vpc", "subnets"] else f"get_{service}_details"
                data = globals()[func_name](region, creds, account_id, account_name)
                result[f"{service}_data"] = data
            else:
                func_name = f"get_{service}"
                data = globals()[func_name](region, creds).get("events", [])
                result[service] = data
        except Exception as e:
            log(f"ERROR: {account_id}:{region} - {service}: {str(e)}")
    
    return result

def insert_service_data(service, data, region):
    """Inserta datos de un servicio en la base de datos."""
    
    if not data:
        return f"{service.upper()}: No hay datos para insertar"
    
    if service.endswith("_cloudtrail"):
        res = insert_or_update_cloudtrail_events(data)
    else:
        func_name = f"insert_or_update_{service}_data"
        res = globals()[func_name](data)
    
    return f"{service.upper()} ({region}): {len(data)} items ({res.get('inserted', 0)} insertados, {res.get('updated', 0)} actualizados)"

def resolve_dependencies(services):
    """Añade dependencias necesarias a la lista de servicios."""

    result = list(services)
    for service in services:
        if service in EVENTS and DEPENDENCIES.get(service) not in result:
            result.append(DEPENDENCIES[service])
            log(f"INFO: Añadiendo {DEPENDENCIES[service]} como dependencia de {service}")
    return result

def main(services):
    """Función principal que coordina la recolección de datos."""

    start = datetime.now()
    log(f"INICIO: Procesando servicios: {', '.join(services)}")

    all_services = resolve_dependencies(services)
    errors, data_by_service_region = {}, {}
    total_jobs = len(ROLES) * len(Regions)
    
    with ThreadPoolExecutor(max_workers=min(10, total_jobs)) as executor:
        futures = [
            executor.submit(process_account_region, r["id"], r["role"], r["account"], reg, all_services)
            for r in ROLES for reg in Regions
        ]
        
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            if i % 10 == 0 or i == total_jobs:  # Reducir logs de progreso
                log(f"PROGRESO: {i}/{total_jobs} ({i/total_jobs*100:.1f}%)")
            
            if "error" in res:
                errors.setdefault(res["account_id"], []).append(f"{res['region']}: {res['error']}")
                continue
            
            for s in all_services:
                key = f"{s}_data" if s in RESOURCES else s
                if key in res and res[key]:
                    service_key = (s, res["region"])
                    if service_key not in data_by_service_region:
                        data_by_service_region[service_key] = []
                    data_by_service_region[service_key].extend(res[key])

    log("INSERCIÓN: Iniciando inserción en base de datos")
    results = []
    
    for group in [RESOURCES, EVENTS]:
        for service in [s for s in group if s in all_services]:
            for (svc, region), data in data_by_service_region.items():
                if svc == service and data:
                    result = insert_service_data(service, data, region)
                    results.append(result)
                    log(f"RESULTADO: {result}")

    if errors:
        log(f"ERRORES: {len(errors)} cuentas con errores, {sum(len(e) for e in errors.values())} total")
    
    duration = (datetime.now() - start).total_seconds()
    log(f"FIN: Proceso completado en {duration:.2f} segundos")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Recolecta información de recursos AWS')
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--all', action='store_true', help='Procesar todos los servicios')
    group.add_argument('--ec2', action='store_true', help='Procesar EC2 y sus eventos')
    group.add_argument('--rds', action='store_true', help='Procesar RDS y sus eventos')
    group.add_argument('--vpc', action='store_true', help='Procesar VPC y sus eventos')
    
    parser.add_argument('--services', nargs='+', default=[],
                      choices=RESOURCES + EVENTS,
                      help='Servicios específicos a consultar')
    parser.add_argument('--quiet', action='store_true', help='Reducir mensajes de log')
    
    args = parser.parse_args()
    
    # Configurar nivel de log
    if args.quiet:
        def log(msg):
            if any(level in msg for level in ["ERROR", "INICIO", "FIN"]):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] {msg}")
    
    # Determinar servicios
    if args.all:
        services = RESOURCES + EVENTS
    elif args.ec2:
        services = ["ec2", "ec2_cloudtrail"]
    elif args.rds:
        services = ["rds", "rds_cloudtrail"]
    elif args.vpc:
        services = ["vpc", "vpc_cloudtrail"]
    elif args.services:
        services = args.services
    else:
        services = ["ec2", "ec2_cloudtrail"]
    
    main(services)