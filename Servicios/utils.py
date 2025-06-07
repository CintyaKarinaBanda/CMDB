import boto3
import pg8000
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import DB_USER, DB_PASSWORD, DB_HOST, DB_NAME

def create_aws_client(service, region, credentials):
    if not credentials or "error" in credentials:
        return None
    try:
        return boto3.client(
            service,
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
    except Exception as e:
        print(f"Error creating {service} client: {str(e)}")
        return None

def get_db_connection():
    try:
        return pg8000.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=5432,
            database=DB_NAME
        )
    except Exception as e:
        print(f"Database connection failed: {str(e)}")
        return None