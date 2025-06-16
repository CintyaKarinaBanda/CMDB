# Script de Recolección de Recursos AWS (EC2, RDS, VPC, etc.)

Este script permite recolectar información de recursos AWS (EC2, RDS, Redshift, VPC, Subnets, CloudTrail) y almacenarla en una base de datos PostgreSQL. Está diseñado para ejecutarse en una instancia EC2, VM o entorno local, no como Lambda.

## Requisitos

- Python 3.7+
- Boto3
- pg8000
- Credenciales AWS configuradas en la instancia EC2, variables de entorno, o mediante roles asumibles

## Instalación

1. Instala las dependencias:

```bash
pip install -r requirements.txt
```

2. Configura los archivos necesarios:
   - `config.py`: Regiones, credenciales de base de datos, configuración de S3, etc.
   - `listadoDeRoles.py`: Lista de cuentas y roles AWS a consultar.

3. Asegúrate de que la instancia EC2 (o el usuario) tenga permisos para asumir los roles definidos.

## Uso

```bash
python script.py --services ec2 rds vpc
```

### Argumentos principales

- `--services`: Lista de servicios a consultar. Opciones válidas:
  - `ec2`, `rds`, `redshift`, `vpc`, `subnets`, `ec2_cloudtrail`, `rds_cloudtrail`, `vpc_cloudtrail`
  - Ejemplo: `--services ec2 rds vpc`

### Ejemplos

Ejecutar con todos los servicios predeterminados:
```bash
python script.py
```

Ejecutar solo para EC2 y RDS:
```bash
python script.py --services ec2 rds
```

## Estructura del Proyecto

- `script.py`: Script principal de ejecución
- `services/`: Lógica de extracción y guardado de datos por servicio
- `config.py`: Configuración de regiones y base de datos
- `listadoDeRoles.py`: Cuentas y roles AWS
- `requirements.txt`: Dependencias Python

## Notas
- El script utiliza procesamiento paralelo para acelerar la recolección.
- Los resultados y logs se muestran por consola.
- Puedes modificar los archivos de configuración para adaptarlo a tu entorno.

---

Actualizado: 13 de junio de 2025