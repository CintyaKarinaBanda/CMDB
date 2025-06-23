# Guía para Agregar Nuevos Servicios AWS

## Estructura del Proyecto

```
services/
├── shared/
│   ├── base_service.py      # Clase base común
│   └── common_functions.py  # Funciones compartidas
├── template/
│   └── service_template.py  # Plantilla para nuevos servicios
├── ec2_functions.py         # Ejemplo de servicio implementado
├── rds_functions.py         # Ejemplo de servicio implementado
├── utils.py                 # Utilidades comunes
└── [nuevo_servicio]_functions.py
```

## Pasos para Agregar un Nuevo Servicio

### 1. Copiar la Plantilla
```bash
cp services/template/service_template.py services/lambda_functions.py
```

### 2. Configurar el Servicio

#### A. Cambiar nombres de clase y servicio:
```python
class LambdaManager(BaseService):
    def __init__(self):
        super().__init__("lambda", "Lambda")
```

#### B. Definir mapeo de eventos CloudTrail:
```python
self.field_event_map = {
    "functionname": ["CreateFunction", "UpdateFunctionConfiguration"],
    "runtime": ["UpdateFunctionConfiguration"],
    "status": ["CreateFunction", "DeleteFunction"],
    "memorysize": ["UpdateFunctionConfiguration"],
    "timeout": ["UpdateFunctionConfiguration"]
}
```

### 3. Implementar Extracción de Datos

```python
def extract_resource_data(self, function, account_name, account_id, region):
    return {
        "AccountName": account_name,
        "AccountID": account_id,
        "FunctionName": function["FunctionName"],
        "Runtime": function.get("Runtime", "N/A"),
        "Status": function.get("State", "N/A"),
        "MemorySize": function.get("MemorySize", 0),
        "Timeout": function.get("Timeout", 0),
        "Region": region
    }
```

### 4. Configurar Cliente AWS

```python
from .utils import create_aws_client
from .shared.base_service import BaseService

def get_resources(self, region, credentials, account_id, account_name):
    client = create_aws_client("lambda", region, credentials)
    
    try:
        paginator = client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page.get("Functions", []):
                # procesar función
```

### 5. Configurar Base de Datos

#### A. Crear tabla principal:
```sql
CREATE TABLE lambda_functions (
    id SERIAL PRIMARY KEY,
    accountname VARCHAR(255),
    accountid VARCHAR(255),
    functionname VARCHAR(255) UNIQUE,
    runtime VARCHAR(100),
    status VARCHAR(50),
    memorysize INTEGER,
    timeout INTEGER,
    region VARCHAR(50),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### B. Crear tabla de historial:
```sql
CREATE TABLE lambda_changes_history (
    id SERIAL PRIMARY KEY,
    functionname VARCHAR(255),
    field_name VARCHAR(255),
    old_value TEXT,
    new_value TEXT,
    changed_by VARCHAR(255),
    change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Servicios Recomendados

### 1. AWS Lambda
- **API**: `list_functions`
- **Eventos**: CreateFunction, UpdateFunctionConfiguration, DeleteFunction

### 2. S3 Buckets
- **API**: `list_buckets`
- **Eventos**: CreateBucket, DeleteBucket, PutBucketPolicy

### 3. CloudFormation Stacks
- **API**: `describe_stacks`
- **Eventos**: CreateStack, UpdateStack, DeleteStack

## Checklist de Implementación

- [ ] Copiar plantilla y renombrar archivo
- [ ] Cambiar nombres de clase y servicio
- [ ] Definir field_event_map
- [ ] Implementar extract_resource_data()
- [ ] Configurar cliente AWS y API calls
- [ ] Crear tablas en base de datos
- [ ] Configurar queries de inserción
- [ ] Probar con datos reales