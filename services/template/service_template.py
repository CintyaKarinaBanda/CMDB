# Template para nuevos servicios AWS
from botocore.exceptions import ClientError
from datetime import datetime
from ..utils import create_aws_client
from ..shared.base_service import BaseService

class NewServiceManager(BaseService):
    """Plantilla para nuevo servicio AWS"""
    
    def __init__(self):
        super().__init__("new_service", "NEW_SERVICE")
        
        # PASO 1: Definir mapeo de campos a eventos CloudTrail
        self.field_event_map = {
            "field1": ["CreateEvent", "ModifyEvent"],
            "field2": ["StartEvent", "StopEvent"],
            "status": ["CreateEvent", "DeleteEvent", "ModifyEvent"],
            # Agregar más mapeos según el servicio
        }
    
    def extract_resource_data(self, resource, account_name, account_id, region):
        """PASO 2: Extraer datos del recurso AWS"""
        return {
            "AccountName": account_name,
            "AccountID": account_id,
            "ResourceId": resource["ResourceIdentifier"],  # Cambiar según el servicio
            "Field1": resource.get("Field1", "N/A"),
            "Field2": resource.get("Field2", "N/A"),
            "Status": resource.get("Status", "N/A"),
            "Region": region,
            # Agregar más campos según el servicio
        }
    
    def get_resources(self, region, credentials, account_id, account_name):
        """PASO 3: Obtener recursos del servicio AWS"""
        client = create_aws_client("service_name", region, credentials)  # Cambiar service_name
        if not client:
            return []

        try:
            # PASO 3a: Usar paginator si está disponible
            paginator = client.get_paginator('describe_resources')  # Cambiar método
            resources_info = []

            for page in paginator.paginate():
                for resource in page.get("Resources", []):  # Cambiar clave
                    info = self.extract_resource_data(resource, account_name, account_id, region)
                    resources_info.append(info)
            
            if resources_info:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: NewService {region}: {len(resources_info)} encontrados")
            return resources_info
            
        except ClientError as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: NewService {region}/{account_id} - {str(e)}")
            return []
    
    def insert_or_update_resources(self, resources_data):
        """PASO 4: Insertar/actualizar datos en la base de datos"""
        
        # PASO 4a: Definir query de inserción
        insert_query = '''
            INSERT INTO new_service_table (
                AccountName, AccountID, ResourceId, Field1, Field2, 
                Status, Region, last_updated
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
            )
        '''
        
        # PASO 4b: Mapear campos para comparación
        def get_campos_map(resource):
            return {
                "accountname": resource["AccountName"],
                "accountid": resource["AccountID"],
                "resourceid": resource["ResourceId"],
                "field1": resource["Field1"],
                "field2": resource["Field2"],
                "status": resource["Status"],
                "region": resource["Region"]
            }
        
        # PASO 4c: Usar función base para insertar/actualizar
        return self.insert_or_update_data(
            data=resources_data,
            table_name="new_service_table",  # Cambiar nombre de tabla
            history_table="new_service_changes_history",  # Cambiar nombre de tabla de historial
            id_field="resourceid",  # Cambiar campo ID
            insert_query=insert_query,
            campos_map=get_campos_map(resources_data[0]) if resources_data else {}
        )

# PASO 5: Funciones de conveniencia (mantener compatibilidad)
def get_new_service_resources(region, credentials, account_id, account_name):
    """Función de conveniencia para obtener recursos"""
    manager = NewServiceManager()
    return manager.get_resources(region, credentials, account_id, account_name)

def insert_or_update_new_service_data(resources_data):
    """Función de conveniencia para insertar/actualizar datos"""
    manager = NewServiceManager()
    return manager.insert_or_update_resources(resources_data)

# INSTRUCCIONES DE USO:
"""
Para crear un nuevo servicio:

1. Copiar este archivo y renombrarlo (ej: lambda_functions.py)
2. Cambiar "NewService" por el nombre del servicio (ej: "Lambda")
3. Actualizar field_event_map con eventos CloudTrail específicos
4. Modificar extract_resource_data() con campos del servicio
5. Cambiar service_name en create_aws_client()
6. Actualizar método de API y claves en get_resources()
7. Modificar queries y nombres de tabla en insert_or_update_resources()
8. Crear tabla en base de datos con estructura correspondiente

Ejemplo para Lambda:
- service_name: "lambda"
- API method: "list_functions"
- Resource key: "Functions"
- Table: "lambda_functions"
- History table: "lambda_changes_history"
"""