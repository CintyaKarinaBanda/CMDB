#!/usr/bin/env python3
import boto3
import json
from botocore.exceptions import ClientError
from listadoDeRoles import ROLES

def check_trust_policy(account_id, role_name):
    """
    Verifica la política de confianza de un rol en otra cuenta.
    """
    # Primero obtenemos nuestra identidad actual
    sts_client = boto3.client('sts')
    current_identity = sts_client.get_caller_identity()
    current_account = current_identity['Account']
    current_role_arn = current_identity['Arn']
    
    print(f"\nVerificando política de confianza para: {account_id}:{role_name}")
    
    # Intentamos asumir el rol para ver si tenemos permiso
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="TrustPolicyCheck",
            DurationSeconds=900
        )
        print(f"✅ Éxito al asumir el rol {role_arn}")
        
        # Si podemos asumir el rol, usamos esas credenciales para obtener la política de confianza
        temp_credentials = response['Credentials']
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=temp_credentials['AccessKeyId'],
            aws_secret_access_key=temp_credentials['SecretAccessKey'],
            aws_session_token=temp_credentials['SessionToken']
        )
        
        try:
            role_info = iam_client.get_role(RoleName=role_name)
            trust_policy = role_info['Role']['AssumeRolePolicyDocument']
            
            print("Política de confianza:")
            print(json.dumps(trust_policy, indent=2))
            
            # Verificar si nuestra cuenta/rol está en la política de confianza
            is_trusted = False
            for statement in trust_policy.get('Statement', []):
                if statement.get('Effect') == 'Allow' and statement.get('Action') == 'sts:AssumeRole':
                    principal = statement.get('Principal', {})
                    aws_principal = principal.get('AWS', [])
                    
                    if isinstance(aws_principal, str):
                        aws_principal = [aws_principal]
                    
                    for principal_arn in aws_principal:
                        if current_account in principal_arn or '*' in principal_arn:
                            is_trusted = True
                            print(f"✅ Tu cuenta {current_account} está en la política de confianza")
                            break
            
            if not is_trusted:
                print(f"❌ Tu cuenta {current_account} NO está en la política de confianza")
                print(f"Sugerencia: Añade '{current_role_arn}' a la política de confianza")
            
        except Exception as e:
            print(f"Error al obtener la política de confianza: {str(e)}")
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'No message')
        
        print(f"❌ Error al asumir el rol: {error_code}")
        print(f"Mensaje: {error_message}")
        
        if error_code == "AccessDenied":
            print("Problema probable: La política de confianza del rol no permite a tu cuenta/rol asumirlo")
            print(f"Sugerencia: El rol {role_name} en la cuenta {account_id} debe tener una política de confianza que incluya:")
            print(f'{{')
            print(f'  "Effect": "Allow",')
            print(f'  "Principal": {{ "AWS": "{current_role_arn}" }},')
            print(f'  "Action": "sts:AssumeRole"')
            print(f'}}')

def main():
    print("=== Verificando políticas de confianza de roles ===")
    print(f"Total de roles a verificar: {len(ROLES)}")
    
    # Verificar solo el primer rol para prueba
    if ROLES:
        role = ROLES[0]
        check_trust_policy(role['id'], role['role'])
        
        # Preguntar si quiere verificar todos los roles
        response = input("\n¿Quieres verificar todos los roles? (s/n): ")
        if response.lower() == 's':
            for role in ROLES[1:]:
                check_trust_policy(role['id'], role['role'])

if __name__ == "__main__":
    main()