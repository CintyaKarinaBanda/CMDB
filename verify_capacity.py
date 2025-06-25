#!/usr/bin/env python3
import boto3

def verify_bucket_objects(bucket_name):
    """Verifica los objetos del bucket para confirmar el tamaño"""
    s3 = boto3.client('s3')
    
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        
        if 'Contents' not in response:
            print(f"✓ Bucket '{bucket_name}' está vacío")
            return
        
        total_size = sum(obj['Size'] for obj in response['Contents'])
        object_count = len(response['Contents'])
        
        print(f"✓ Bucket: {bucket_name}")
        print(f"✓ Objetos: {object_count}")
        print(f"✓ Tamaño total: {total_size:,} bytes ({total_size/1024:.2f} KB)")
        
        print("\nObjetos:")
        for obj in response['Contents'][:5]:  # Mostrar solo los primeros 5
            print(f"  - {obj['Key']}: {obj['Size']:,} bytes")
        
        if object_count > 5:
            print(f"  ... y {object_count - 5} más")
            
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    verify_bucket_objects("dashboard-and-finops")