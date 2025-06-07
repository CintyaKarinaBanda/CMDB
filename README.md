# Script de Recolección de Datos AWS para EC2

Este script es una versión adaptada del lambda_function.py original para ejecutarse en una instancia EC2 en lugar de una función Lambda.

## Requisitos

- Python 3.6+
- Boto3
- Credenciales AWS configuradas en la instancia EC2 o mediante variables de entorno

## Instalación

1. Asegúrate de tener instaladas las dependencias:

```bash
pip install boto3
```

2. Asegúrate de que la instancia EC2 tenga un rol IAM con permisos para asumir los roles especificados en `listadoDeRoles.py`.

## Uso

```bash
python ec2_script.py [opciones]
```

### Opciones

- `--services`: Lista de servicios a consultar (por defecto: ec2, rds, redshift, vpc, subnets, cloudtrail_events)
  - Ejemplo: `--services ec2 rds vpc`
  
- `--max-workers`: Número máximo de workers para procesamiento paralelo (por defecto: 10)
  - Ejemplo: `--max-workers 20`
  
- `--output`: Archivo de salida para guardar resultados en formato JSON
  - Ejemplo: `--output resultados.json`

### Ejemplos

Ejecutar con todos los servicios predeterminados:
```bash
python ec2_script.py
```

Ejecutar solo para EC2 y RDS:
```bash
python ec2_script.py --services ec2 rds
```

Ejecutar con más workers y guardar resultados:
```bash
python ec2_script.py --max-workers 15 --output resultados.json
```

## Diferencias con la versión Lambda

- Recibe parámetros por línea de comandos en lugar de un evento de Lambda
- Permite especificar el número de workers para el procesamiento paralelo
- Opción para guardar los resultados en un archivo JSON
- Logging mejorado para entorno de EC2

## Configuración

La configuración se mantiene en los archivos:
- `config.py`: Contiene regiones, credenciales de base de datos y configuración de S3
- `listadoDeRoles.py`: Contiene la lista de roles y cuentas AWS a consultar