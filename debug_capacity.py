#!/usr/bin/env python3
import boto3
from datetime import datetime, timedelta

def debug_bucket_capacity(bucket_name, region='us-east-1'):
    """Debug detallado de la función capacity"""
    try:
        s3_client = boto3.client('s3', region_name=region)
        cw_client = boto3.client('cloudwatch', region_name=region)
        
        print(f"=== DEBUG CAPACITY: {bucket_name} ===")
        
        # Obtener métricas
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=2)
        
        print(f"Consultando desde: {start_time}")
        print(f"Consultando hasta: {end_time}")
        
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
        
        print(f"Datapoints: {len(response['Datapoints'])}")
        
        if response['Datapoints']:
            for dp in response['Datapoints']:
                print(f"  - {dp['Timestamp']}: {dp['Average']} bytes")
            
            latest_datapoint = max(response['Datapoints'], key=lambda x: x['Timestamp'])
            bytes_size = int(latest_datapoint['Average'])
            
            print(f"\nValor más reciente: {bytes_size} bytes")
            
            # Convertir a unidad apropiada
            if bytes_size >= 1024**3:  # GB
                result = f"{bytes_size / (1024**3):.2f} GB"
            elif bytes_size >= 1024**2:  # MB
                result = f"{bytes_size / (1024**2):.2f} MB"
            elif bytes_size >= 1024:  # KB
                result = f"{bytes_size / 1024:.2f} KB"
            else:  # Bytes
                result = f"{bytes_size} B"
            
            print(f"Resultado final: {result}")
            return result
        else:
            print("No hay datapoints - retornando '0 B'")
            return "0 B"
            
    except Exception as e:
        print(f"ERROR: {e}")
        return "0 B"

if __name__ == "__main__":
    result = debug_bucket_capacity("dashboard-and-finops")
    print(f"\nFUNCIÓN RETORNA: '{result}'")