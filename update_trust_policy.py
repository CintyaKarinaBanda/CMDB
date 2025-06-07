#!/usr/bin/env python3
import boto3
import json
import argparse
from botocore.exceptions import ClientError

def update_trust_policy(account_id, role_name, trusted_entity_arn):
    """
    Actualiza la política de confianza de un rol para permitir que una entidad específica lo asuma.
    
    Args:
        account_id (str): ID de la cuenta donde está el rol
        role_name (str): Nombre del rol a actualizar
        trusted_entity_arn (str): ARN de la entidad que debe confiar (tu rol de EC2)
    """
    # Primero intentamos asumir el rol con credenciales de administrador
    # Esto requiere que tengas permisos para asumir este rol inicialmente
    sts_client = boto3.client('sts')
    
    try:
        print(f"Intentando asumir el rol {role_name} en la cuenta {account_id}...")
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="UpdateTrustPolicy",
            DurationSeconds=900
        )
        
        # Usar las credenciales temporales para actualizar la política de confianza
        temp_credentials = response['Credentials']
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=temp_credentials['AccessKeyId'],
            aws_secret_access_key=temp_credentials['SecretAccessKey'],
            aws_session_token=temp_credentials['SessionToken']
        )
        
        # Obtener la política de confianza actual
        role_info = iam_client.get_role(RoleName=role_name)
        current_policy = role_info['Role']['AssumeRolePolicyDocument']
        
        print("Política de confianza actual:")
        print(json.dumps(current_policy, indent=2))
        
        # Verificar si la entidad ya está en la política
        entity_exists = False
        for statement in current_policy.get('Statement', []):
            if statement.get('Effect') == 'Allow' and statement.get('Action') == 'sts:AssumeRole':
                principal = statement.get('Principal', {})
                aws_principal = principal.get('AWS', [])
                
                if isinstance(aws_principal, str):
                    if aws_principal == trusted_entity_arn:
                        entity_exists = True
                        break
                elif isinstance(aws_principal, list):
                    if trusted_entity_arn in aws_principal:
                        entity_exists = True
                        break
        
        # Si la entidad no existe, añadirla
        if not entity_exists:
            # Añadir un nuevo statement si es necesario
            new_statement = {
                "Effect": "Allow",
                "Principal": {"AWS": trusted_entity_arn},
                "Action": "sts:AssumeRole"
            }
            
            current_policy['Statement'].append(new_statement)
            
            # Actualizar la política
            print("\nActualizando política de confianza...")
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(current_policy)
            )
            
            print("✅ Política de confianza actualizada exitosamente")
            print("Nueva política:")
            print(json.dumps(current_policy, indent=2))
        else:
            print(f"\n✅ La entidad {trusted_entity_arn} ya está en la política de confianza")
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'No message')
        
        print(f"❌ Error: {error_code}")
        print(f"Mensaje: {error_message}")
        
        if error_code == "AccessDenied":
            print("\nNo tienes permisos para actualizar la política de confianza.")
            print("Necesitas contactar al administrador de la cuenta de destino y pedirle que actualice la política de confianza manualmente.")
            print("\nPolítica de confianza que debe añadir:")
            trust_policy = {
                "Effect": "Allow",
                "Principal": {"AWS": trusted_entity_arn},
                "Action": "sts:AssumeRole"
            }
            print(json.dumps(trust_policy, indent=2))

def main():
    parser = argparse.ArgumentParser(description='Actualiza la política de confianza de un rol')
    parser.add_argument('--account-id', required=True, help='ID de la cuenta donde está el rol')
    parser.add_argument('--role-name', required=True, help='Nombre del rol a actualizar')
    parser.add_argument('--trusted-entity', required=True, help='ARN de la entidad que debe confiar (tu rol de EC2)')
    
    args = parser.parse_args()
    
    update_trust_policy(args.account_id, args.role_name, args.trusted_entity)

if __name__ == "__main__":
    main()