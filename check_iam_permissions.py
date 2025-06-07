#!/usr/bin/env python3
import boto3
import json

def check_iam_permissions():
    """
    Verifica los permisos IAM de la identidad actual y muestra información relevante
    para diagnosticar problemas con assume_role.
    """
    try:
        # Obtener la identidad actual
        sts_client = boto3.client('sts')
        identity = sts_client.get_caller_identity()
        
        print("=== Identidad actual ===")
        print(f"ARN: {identity['Arn']}")
        print(f"Cuenta: {identity['Account']}")
        print(f"UserId: {identity['UserId']}")
        
        # Determinar si es un rol de instancia EC2
        if ":assumed-role/" in identity['Arn']:
            print("\n✅ Estás usando un rol asumido (posiblemente un rol de instancia EC2)")
            role_name = identity['Arn'].split("/")[1]
            print(f"Nombre del rol: {role_name}")
            
            # Obtener las políticas adjuntas al rol
            iam_client = boto3.client('iam')
            try:
                # Intentar obtener las políticas adjuntas al rol
                attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                
                print("\n=== Políticas adjuntas al rol ===")
                for policy in attached_policies['AttachedPolicies']:
                    print(f"- {policy['PolicyName']}")
                    
                    # Obtener detalles de la política
                    policy_version = iam_client.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                    )
                    
                    # Buscar permisos de AssumeRole
                    policy_doc = policy_version['PolicyVersion']['Document']
                    has_assume_role = False
                    
                    for statement in policy_doc.get('Statement', []):
                        if 'Action' in statement and ('sts:AssumeRole' in statement['Action'] or 
                                                     'sts:*' in statement['Action'] or 
                                                     '*' in statement['Action']):
                            has_assume_role = True
                            print(f"  ✅ Esta política permite sts:AssumeRole")
                            print(f"  Recursos: {statement.get('Resource', 'No especificado')}")
                            break
                    
                    if not has_assume_role:
                        print(f"  ❌ Esta política NO permite explícitamente sts:AssumeRole")
                
                # Verificar políticas en línea
                inline_policies = iam_client.list_role_policies(RoleName=role_name)
                
                if inline_policies['PolicyNames']:
                    print("\n=== Políticas en línea del rol ===")
                    for policy_name in inline_policies['PolicyNames']:
                        print(f"- {policy_name}")
                        
                        policy_doc = iam_client.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )['PolicyDocument']
                        
                        has_assume_role = False
                        for statement in policy_doc.get('Statement', []):
                            if 'Action' in statement and ('sts:AssumeRole' in statement['Action'] or 
                                                         'sts:*' in statement['Action'] or 
                                                         '*' in statement['Action']):
                                has_assume_role = True
                                print(f"  ✅ Esta política permite sts:AssumeRole")
                                print(f"  Recursos: {statement.get('Resource', 'No especificado')}")
                                break
                        
                        if not has_assume_role:
                            print(f"  ❌ Esta política NO permite explícitamente sts:AssumeRole")
                
            except Exception as e:
                print(f"\n❌ No se pudieron obtener detalles del rol: {str(e)}")
                print("Esto puede ocurrir si estás usando credenciales de usuario y no un rol de instancia EC2.")
        
        else:
            print("\n❌ No estás usando un rol de instancia EC2. Esto puede causar problemas para asumir roles.")
            print("Recomendación: Asigna un rol IAM a tu instancia EC2 con los permisos adecuados.")
        
        print("\n=== Recomendaciones ===")
        print("1. El rol de la instancia EC2 debe tener una política con:")
        print('   {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::*:role/ExtractData"}')
        print("2. Los roles de destino deben tener una política de confianza que permita a tu cuenta asumirlos:")
        print('   {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::TU_CUENTA_ID:role/TU_ROL_EC2"}, "Action": "sts:AssumeRole"}')
        
    except Exception as e:
        print(f"Error al verificar permisos: {str(e)}")

if __name__ == "__main__":
    check_iam_permissions()