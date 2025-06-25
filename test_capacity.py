#!/usr/bin/env python3
import boto3
from datetime import datetime, timedelta

def test_bucket_capacity(bucket_name, region='us-east-1'):
    """Prueba la función de capacity para un bucket específico"""
    try:
        # Crear clientes
        s3_client = boto3.client('s3', region_name=region)
        cw_client = boto3.client('cloudwatch', region_name=region)
        
        print(f"Probando capacity para bucket: {bucket_name}")
        print(f"Región: {region}")
        print("-" * 50)
        
        # Verificar que el bucket existe
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            print("✓ Bucket existe")
        except Exception as e:
            print(f"✗ Error accediendo al bucket: {e}")
            return
        
        # Obtener métricas
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=2)
        
        response = cw_client.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Average']
        )
        
        print(f"Datapoints encontrados: {len(response['Datapoints'])}")
        
        if response['Datapoints']:
            latest_datapoint = max(response['Datapoints'], key=lambda x: x['Timestamp'])
            capacity_bytes = int(latest_datapoint['Average'])
            capacity_mb = capacity_bytes / (1024 * 1024)
            capacity_gb = capacity_mb / 1024
            
            print(f"✓ Capacity: {capacity_bytes:,} bytes")
            print(f"✓ Capacity: {capacity_mb:.2f} MB")
            print(f"✓ Capacity: {capacity_gb:.2f} GB")
            print(f"✓ Timestamp: {latest_datapoint['Timestamp']}")
        else:
            print("✗ No hay datos de capacity disponibles")
            print("Posibles causas:")
            print("- El bucket está vacío")
            print("- No hay métricas recientes")
            print("- El bucket no tiene objetos StandardStorage")
        
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    # Cambiar por el nombre de tu bucket
    bucket_name = input("Ingresa el nombre del bucket: ").strip()
    region = input("Ingresa la región (Enter para us-east-1): ").strip() or 'us-east-1'
    
    test_bucket_capacity(bucket_name, region)