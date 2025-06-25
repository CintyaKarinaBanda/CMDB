import boto3
from datetime import datetime, timedelta

def get_bucket_size(bucket_name, region='us-east-1'):
    cw = boto3.client('cloudwatch', region_name=region)

    end_time = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    start_time = end_time - timedelta(days=5)

    try:
        response = cw.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Maximum']
        )

        print(f"Datapoints for {bucket_name}:")
        for dp in sorted(response['Datapoints'], key=lambda x: x['Timestamp']):
            ts = dp['Timestamp']
            size = dp['Maximum']
            print(f" - {ts}: {size / 1024:.2f} KB")

    except Exception as e:
        print(f"Error: {e}")

# 👇 REEMPLAZA con un bucket real
get_bucket_size('dashboard-and-finops', 'us-east-1')