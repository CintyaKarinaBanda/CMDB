# Template refactorizado para crear nuevos servicios AWS usando BaseService
from botocore.exceptions import ClientError
from ..shared.base_service import BaseService
from ..utils import create_aws_client

class NewService(BaseService):
    """Template para nuevo servicio AWS"""
    
    def __init__(self):
        # TODO: Cambiar SERVICE_NAME y SERVICE_TYPE por los valores correctos
        super().__init__("SERVICE_NAME", "SERVICE_TYPE")
    
    def extract_resource_data(self, resource, client, account_name, account_id, region):
        """Extrae datos relevantes del recurso"""
        # TODO: Implementar extracción de datos específica del servicio
        return {
            "AccountName": account_name,
            "AccountID": account_id,
            "ResourceID": resource["ResourceId"],
            "Region": region,
            # TODO: Agregar más campos según el servicio
        }
    
    def get_resources(self, region, credentials, account_id, account_name):
        """Obtiene recursos del servicio de una región"""
        # TODO: Cambiar "service_name" por el nombre correcto del servicio
        client = create_aws_client("service_name", region, credentials)
        if not client:
            return []

        try:
            # TODO: Implementar lógica específica del servicio
            paginator = client.get_paginator('describe_resources')
            resources_info = []

            for page in paginator.paginate():
                for resource in page.get("Resources", []):
                    info = self.extract_resource_data(resource, client, account_name, account_id, region)
                    resources_info.append(info)
            
            if resources_info:
                self.log_info(region, len(resources_info))
            return resources_info
        except ClientError as e:
            self.log_error(region, account_id, e)
            return []
    
    def insert_or_update_resources(self, service_data):
        """Inserta o actualiza datos del servicio en la base de datos"""
        config = {
            # TODO: Configurar según el servicio específico
            'table_name': 'service_table',
            'history_table': 'service_changes_history',
            'id_field': 'resource_id',
            'resource_id_key': 'ResourceID',
            'insert_query': """
                INSERT INTO service_table (
                    AccountName, AccountID, ResourceID, Field1, Field2,
                    Region, last_updated
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
                )
            """,
            'get_insert_values': lambda item: (
                item["AccountName"], item["AccountID"], item["ResourceID"],
                item["Field1"], item["Field2"], item["Region"]
            ),
            'get_field_mapping': lambda item: {
                "accountname": item["AccountName"],
                "accountid": item["AccountID"],
                "resourceid": item["ResourceID"],
                "field1": item["Field1"],
                "field2": item["Field2"],
                "region": item["Region"]
            }
        }
        
        return self.insert_or_update_data(service_data, config)

# Ejemplo de uso:
# service = NewService()
# resources = service.get_resources(region, credentials, account_id, account_name)
# result = service.insert_or_update_resources(resources)

"""
INSTRUCCIONES PARA USAR ESTE TEMPLATE:

1. Copiar este archivo y renombrarlo según el servicio (ej: lambda_service.py)
2. Cambiar "NewService" por el nombre del servicio (ej: "LambdaService")
3. En __init__(), cambiar SERVICE_NAME y SERVICE_TYPE
4. Actualizar extract_resource_data() con campos específicos del servicio
5. En get_resources(), cambiar "service_name" por el servicio AWS correcto
6. Modificar el método de API y claves de respuesta según el servicio
7. En insert_or_update_resources(), actualizar la configuración:
   - table_name: nombre de la tabla en BD
   - history_table: tabla de historial de cambios
   - id_field: campo ID principal
   - resource_id_key: clave del ID en los datos
   - insert_query: query SQL de inserción
   - get_insert_values: función para obtener valores de inserción
   - get_field_mapping: mapeo de campos para comparación

8. Agregar el mapeo de eventos en field_mappings.py si es necesario
9. Crear las tablas correspondientes en la base de datos

EJEMPLO PARA LAMBDA:
- SERVICE_NAME: "Lambda"
- SERVICE_TYPE: "Lambda"
- service_name: "lambda"
- API method: "list_functions"
- Resource key: "Functions"
- table_name: "lambda_functions"
- history_table: "lambda_changes_history"
"""