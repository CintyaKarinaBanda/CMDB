from .database_operations import DatabaseOperations
from .service_logger import ServiceLogger
from .field_mappings import get_field_event_map

class BaseService:
    """Clase base para servicios AWS con funcionalidad común"""
    
    def __init__(self, service_name, resource_type):
        self.service_name = service_name
        self.resource_type = resource_type
        self.field_event_map = get_field_event_map(resource_type)
        self.db_ops = DatabaseOperations()
        self.logger = ServiceLogger()
    
    def get_changed_by(self, resource_id, field_name):
        """Busca el usuario que cambió un campo específico"""
        return self.db_ops.get_changed_by(resource_id, field_name, self.resource_type, self.field_event_map)
    
    def insert_or_update_data(self, data, config):
        """Función genérica para insertar/actualizar datos con historial"""
        config.update({
            'resource_type': self.resource_type,
            'field_event_map': self.field_event_map
        })
        return self.db_ops.insert_or_update_data(data, config)
    
    def log_info(self, region, count, message_type="encontrados"):
        """Log de información del servicio"""
        self.logger.log_info(self.service_name, region, count, message_type)
    
    def log_error(self, region, account_id, error):
        """Log de error del servicio"""
        self.logger.log_error(self.service_name, region, account_id, error)