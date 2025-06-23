"""Mapeos de campos y eventos para todos los servicios AWS"""

# Mapeos de eventos CloudTrail por servicio
FIELD_EVENT_MAPPINGS = {
    'EC2': {
        "instancename": ["CreateTags", "DeleteTags"],
        "instancetype": ["ModifyInstanceAttribute"],
        "state": ["StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"],
        "iamrole": ["AssociateIamInstanceProfile", "DisassociateIamInstanceProfile"],
        "securitygroups": ["ModifyInstanceAttribute", "AuthorizeSecurityGroupIngress", "StartInstances", "StopInstances", "TerminateInstances"],
        "publicip": ["AssociateAddress", "DisassociateAddress", "StartInstances", "StopInstances", "TerminateInstances"],
        "privateip": ["ModifyInstanceAttribute", "StartInstances", "StopInstances", "TerminateInstances"],
        "vpc": ["ModifyInstanceAttribute", "StartInstances", "StopInstances", "TerminateInstances"],
        "subnet": ["ModifyInstanceAttribute", "StartInstances", "StopInstances", "TerminateInstances"],
        "storagevolumes": ["AttachVolume", "DetachVolume"]
    },
    
    'RDS': {
        "dbname": ["CreateDBInstance", "ModifyDBInstance"],
        "enginetype": ["CreateDBInstance"],
        "engineversion": ["ModifyDBInstance"],
        "storagesize": ["ModifyDBInstance"],
        "instancetype": ["ModifyDBInstance"],
        "status": ["StartDBInstance", "StopDBInstance", "RebootDBInstance", "CreateDBInstance", "DeleteDBInstance"],
        "endpoint": ["CreateDBInstance", "ModifyDBInstance"],
        "port": ["CreateDBInstance", "ModifyDBInstance"],
        "hasreplica": ["CreateDBInstanceReadReplica", "DeleteDBInstance"]
    },
    
    'Redshift': {
        "database_name": ["CreateCluster", "ModifyCluster"],
        "node_type": ["CreateCluster", "ModifyCluster"],
        "node_count": ["ResizeCluster", "ModifyCluster"],
        "engine_version": ["ModifyCluster"],
        "storage_size": ["ModifyCluster"],
        "status": ["CreateCluster", "DeleteCluster", "PauseCluster", "ResumeCluster", "RebootCluster"],
        "endpoint": ["CreateCluster", "ModifyCluster"],
        "port": ["CreateCluster", "ModifyCluster"],
        "replication": ["CreateCluster", "ModifyCluster"]
    },
    
    'VPC': {
        "vpc_name": ["CreateTags", "DeleteTags"],
        "state": ["CreateVpc", "DeleteVpc"],
        "subnets": ["CreateSubnet", "DeleteSubnet"],
        "security_groups": ["CreateSecurityGroup", "DeleteSecurityGroup"],
        "network_acls": ["CreateNetworkAcl", "DeleteNetworkAcl"],
        "internet_gateways": ["CreateInternetGateway", "AttachInternetGateway", "DetachInternetGateway"],
        "vpn_connections": ["CreateVpnConnection", "DeleteVpnConnection"],
        "vpc_endpoints": ["CreateVpcEndpoint", "DeleteVpcEndpoint"],
        "vpc_peerings": ["CreateVpcPeeringConnection", "DeleteVpcPeeringConnection"],
        "route_rules": ["CreateRouteTable", "DeleteRouteTable"]
    },
    
    'Subnet': {
        "vpcname": ["CreateTags", "DeleteTags"],
        "state": ["CreateSubnet", "DeleteSubnet"],
        "securitygroups": ["ModifyNetworkInterfaceAttribute", "AuthorizeSecurityGroupIngress"],
        "acls": ["CreateNetworkAcl", "DeleteNetworkAcl", "ReplaceNetworkAclAssociation"],
        "internetgateways": ["CreateInternetGateway", "AttachInternetGateway", "DetachInternetGateway"],
        "vpnconnections": ["CreateVpnConnection", "DeleteVpnConnection"],
        "vpceendpoints": ["CreateVpcEndpoint", "DeleteVpcEndpoint"],
        "vpcpeerings": ["CreateVpcPeeringConnection", "DeleteVpcPeeringConnection"],
        "routetables": ["CreateRouteTable", "AssociateRouteTable", "DisassociateRouteTable"],
        "subnetname": ["CreateTags", "DeleteTags"]
    }
}

def get_field_event_map(service_type):
    """Obtiene el mapeo de eventos para un tipo de servicio"""
    return FIELD_EVENT_MAPPINGS.get(service_type, {})