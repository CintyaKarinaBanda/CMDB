# Configuración de regiones AWS
Regions = [
    "us-east-1",
    "us-west-2",
    # Agregar más regiones según sea necesario
]

# Configuración de base de datos
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "cmdb",
    "user": "username",
    "password": "password"
}

# Configuración de S3 (opcional)
S3_CONFIG = {
    "bucket": "your-bucket-name",
    "region": "us-east-1"
}