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
    print(f"Procesando cuenta {account_id} en la región {region}")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    credentials = assume_role(role_arn)

    print('Credentials',credentials)

    if isinstance(credentials, dict) and "error" in credentials:
        return {"account_id": account_id, "region": region, "error": credentials["error"]}

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
        if "ec2" in requested_services:
            result["ec2_data"] = get_ec2_instances(region, credentials, account_id, account_name)

        if "rds" in requested_services:
            result["rds_data"] = get_rds_instances(region, credentials, account_id, account_name)

        if "redshift" in requested_services:
            result["redshift_data"] = get_redshift_clusters(region, credentials, account_id, account_name)

        if "vpc" in requested_services:
            result["vpc_data"] = get_vpc_details(region, credentials, account_id, account_name)

        if "subnets" in requested_services:
            result["subnets_data"] = get_subnets_details(region, credentials, account_id, account_name)

        if "cloudtrail_events" in requested_services:
            print('Dentro del IF')
            cloudtrail_result = get_ec2_cloudtrail_events(region, credentials)
            result["cloudtrail_events"] = cloudtrail_result.get("events", [])

        return result

    except Exception as e:
        return {"account_id": account_id, "region": region, "error": str(e)}


def main(requested_services):

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
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(process_account_region, role["id"], role["role"], role["account"], region, requested_services)
            for role in ROLES
            for region in Regions
        ]

        for future in as_completed(futures):
            result = future.result()
            account_id = result.get("account_id")
            region = result.get("region")

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

    service_insert_funcs = {
        "ec2": insert_or_update_ec2_data,
        "rds": insert_or_update_rds_data,
        "redshift": insert_or_update_redshift_data,
        "vpc": insert_or_update_vpc_data,
        "subnets": insert_or_update_subnet_data,
        "cloudtrail_events": insert_or_update_cloudtrail_events
    }

    for service in requested_services:
        insert_func = service_insert_funcs.get(service)
        if not insert_func:
            messages.append(f"{service.upper()}: Servicio no soportado o sin función de inserción")
            continue

        service_entries = collected_data.get(service, [])
        grouped = {}
        for entry in service_entries:
            key = (entry["region"], tuple(sorted(entry["credentials"].items())))
            grouped.setdefault(key, []).append(entry["data"])

        for (region, _), data_list in grouped.items():
            if not data_list:
                continue

            credentials = service_entries[0]["credentials"] if service_entries else None

            result = insert_func(data_list, region, credentials)
            db_results.setdefault(service, []).append(result)

            messages.append(
                f"{service.upper()} ({region}): {len(data_list)} items "
                f"({result.get('inserted', 0)} insertados, {result.get('updated', 0)} actualizados)"
            )

    for message in messages:
        print(message)
    
    if errors:
        print(f"Se encontraron errores en {len(errors)} cuentas")
        for account_id, error_list in errors.items():
            print(f"Cuenta {account_id}: {len(error_list)} errores")


if __name__ == "__main__":
    requested_services=['cloudtrail_events']
    main(requested_services)