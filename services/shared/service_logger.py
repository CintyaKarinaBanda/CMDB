from datetime import datetime

class ServiceLogger:
    """Logger centralizado para todos los servicios"""
    
    @staticmethod
    def log_info(service_name, region, count, message_type="encontrados"):
        """Log estándar para información de servicios"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: {service_name} {region}: {count} {message_type}")
    
    @staticmethod
    def log_error(service_name, region, account_id, error):
        """Log estándar para errores de servicios"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {service_name} {region}/{account_id} - {str(error)}")
    
    @staticmethod
    def log_db_error(operation, resource_id, field_name, error):
        """Log para errores específicos de base de datos"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {operation} {resource_id}/{field_name} - {str(error)}")
    
    @staticmethod
    def log_client_error(service_name, resource_id, error):
        """Log para errores de cliente AWS"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {service_name} {resource_id} - {str(error)}")