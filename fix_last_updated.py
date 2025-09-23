import os
import re

# Lista de archivos que ya fueron corregidos
fixed_files = [
    'ec2_functions.py', 'rds_functions.py', 'vpc_functions.py', 
    'subnets_functions.py', 'eks_functions.py', 'redshift_functions.py',
    's3_functions.py', 'lambda_functions.py', 'apigateway_functions.py',
    'ecr_functions.py'
]

services_dir = '/Users/karinabanda/Desktop/Proyectos/CMDB/Copia de lambda/services'

for filename in os.listdir(services_dir):
    if filename.endswith('_functions.py') and filename not in fixed_files:
        filepath = os.path.join(services_dir, filename)
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Buscar el patrón "if updates:" seguido de actualización
        pattern = r'(\s+)(if updates:)\s*\n(\s+)(.*UPDATE.*last_updated.*)\n(\s+)(.*updated \+= 1.*)'
        
        def replacement(match):
            indent1 = match.group(1)
            indent3 = match.group(3)
            indent5 = match.group(5)
            update_line = match.group(4)
            updated_line = match.group(6)
            
            # Extraer el identificador de la tabla y campo clave
            table_match = re.search(r'UPDATE (\w+)', update_line)
            where_match = re.search(r'WHERE (\w+) = %s', update_line)
            
            if table_match and where_match:
                table = table_match.group(1)
                key_field = where_match.group(1)
                
                # Determinar la variable que contiene el ID
                if 'api_id' in update_line:
                    id_var = 'api_id'
                elif 'cluster_name' in update_line:
                    id_var = 'cluster_name'
                elif 'function_name' in update_line:
                    id_var = 'function_name'
                elif 'bucket_name' in update_line:
                    id_var = 'bucket_name'
                else:
                    # Usar el nombre del campo como variable
                    id_var = key_field
                
                return f'''{indent1}if updates:
{indent3}{update_line}
{indent5}{updated_line}
{indent1}else:
{indent3}cursor.execute("UPDATE {table} SET last_updated = NOW() WHERE {key_field} = %s", [{id_var}])'''
            
            return match.group(0)  # No cambiar si no se puede parsear
        
        new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        
        if new_content != content:
            with open(filepath, 'w') as f:
                f.write(new_content)
            print(f"Fixed: {filename}")
        else:
            print(f"No changes needed: {filename}")

