from datetime import datetime

S3 = {
    'bucket': "infra-xal-poc",
    'keys': {
        'ec2': f"script_test/aws_ec2_inventory_{datetime.now().strftime('%Y-%m-%d')}.csv",
        'rds': f"script_test/aws_rds_inventory_{datetime.now().strftime('%Y-%m-%d')}.csv"
    }
} 

Regions = ["us-east-1", "us-east-2"]

DB_USER = "cmdb"
DB_PASSWORD = "cmdb"
DB_HOST = "3.239.166.161"
DB_NAME = "cmdb"