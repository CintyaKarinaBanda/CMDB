#!/usr/bin/env python3
import boto3
from datetime import datetime
from listadoDeRoles import ROLES
from config import Regions
from services.cloudtrail_functions import get_all_cloudtrail_events, insert_or_update_cloudtrail_events

def assume_role(role_arn):
    try:
        creds = boto3.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"TestSession-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            DurationSeconds=900
        )["Credentials"]
        return {k: creds[k] for k in ["AccessKeyId", "SecretAccessKey", "SessionToken"]}
    except Exception as e:
        return {"error": str(e)}

def test_single_account():
    """Prueba CloudTrail en una sola cuenta/región"""
    # Usar la primera cuenta disponible
    test_account = ROLES[0]
    test_region = "us-east-1"
    
    print(f"🧪 Probando CloudTrail en {test_account['account']} ({test_account['id']}) - {test_region}")
    
    # Asumir rol
    creds = assume_role(f"arn:aws:iam::{test_account['id']}:role/{test_account['role']}")
    if "error" in creds:
        print(f"❌ Error asumiendo rol: {creds['error']}")
        return
    
    print("✅ Rol asumido correctamente")
    
    # Obtener eventos
    result = get_all_cloudtrail_events(test_region, creds, test_account['id'], test_account['account'])
    events = result.get("events", [])
    
    print(f"📊 Eventos encontrados: {len(events)}")
    
    if events:
        # Mostrar algunos ejemplos
        print("\n📋 Primeros 3 eventos:")
        for i, event in enumerate(events[:3]):
            print(f"  {i+1}. {event['event_name']} - {event['resource_name']} ({event['event_source']})")
        
        # Intentar insertar en BD
        print(f"\n💾 Insertando {len(events)} eventos en BD...")
        insert_result = insert_or_update_cloudtrail_events(events)
        
        if "error" in insert_result:
            print(f"❌ Error insertando: {insert_result['error']}")
        else:
            print(f"✅ Insertados: {insert_result['inserted']}/{insert_result['processed']}")
    else:
        print("⚠️  No se encontraron eventos importantes")

if __name__ == "__main__":
    test_single_account()