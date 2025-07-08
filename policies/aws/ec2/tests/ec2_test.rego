# =============================================================================
# EC2 Policy Tests
# =============================================================================
# Purpose: Test cases for EC2 security policies
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.ec2.tests

import data.aws.ec2.security_groups
import data.aws.ec2.instance_compliance
import data.aws.ec2.ebs_encryption

# -----------------------------------------------------------------------------
# SECURITY GROUP POLICY TESTS
# -----------------------------------------------------------------------------

# Test: Security group with SSH open to internet should be denied
test_deny_ssh_open_to_internet if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "description": "Test security group",
            "ingress": [{
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
            }]
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 1
    contains(result[_], "SSH")
}

# Test: Security group with RDP open to internet should be denied
test_deny_rdp_open_to_internet if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "description": "Test security group",
            "ingress": [{
                "from_port": 3389,
                "to_port": 3389,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
            }]
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 1
    contains(result[_], "RDP")
}

# Test: Security group with all ports open should be denied
test_deny_all_ports_open if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "description": "Test security group",
            "ingress": [{
                "from_port": 0,
                "to_port": 65535,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
            }]
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 1
    contains(result[_], "all ports")
}

# Test: Security group with database port open should be denied
test_deny_database_port_open if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "description": "Test security group",
            "ingress": [{
                "from_port": 3306,
                "to_port": 3306,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
            }]
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 1
    contains(result[_], "database port")
}

# Test: Security group without description should be denied
test_deny_sg_without_description if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "ingress": [{
                "from_port": 80,
                "to_port": 80,
                "protocol": "tcp",
                "cidr_blocks": ["10.0.0.0/8"]
            }]
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 1
    contains(result[_], "description")
}

# Test: Security group with proper configuration should be allowed
test_allow_proper_security_group if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "web-sg",
        "config": {
            "description": "Security group for web servers",
            "ingress": [{
                "from_port": 80,
                "to_port": 80,
                "protocol": "tcp",
                "cidr_blocks": ["10.0.0.0/8"]
            }],
            "egress": [{
                "from_port": 0,
                "to_port": 65535,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
            }],
            "tags": {
                "Environment": "production",
                "Owner": "web-team",
                "Purpose": "web-server"
            }
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 0
}

# Test: Security group without required tags should be denied
test_deny_sg_without_tags if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "description": "Test security group",
            "ingress": [{
                "from_port": 80,
                "to_port": 80,
                "protocol": "tcp",
                "cidr_blocks": ["10.0.0.0/8"]
            }]
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 2  # No tags and missing required tags
}

# Test: Security group with IPv6 SSH access should be denied
test_deny_ssh_ipv6_open if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "description": "Test security group",
            "ingress": [{
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "ipv6_cidr_blocks": ["::/0"]
            }]
        }
    }
    
    result := security_groups.deny with input as input
    count(result) == 1
    contains(result[_], "IPv6")
}

# -----------------------------------------------------------------------------
# INSTANCE COMPLIANCE POLICY TESTS
# -----------------------------------------------------------------------------

# Test: Instance without required tags should be denied
test_deny_instance_without_tags if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678"
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 1
    contains(result[_], "tags")
}

# Test: Instance with missing required tags should be denied
test_deny_instance_missing_required_tags if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678",
            "tags": {
                "Environment": "dev"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 1
    contains(result[_], "missing required tags")
}

# Test: Instance with prohibited instance type should be denied
test_deny_prohibited_instance_type if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "instance_type": "t1.micro",
            "ami": "ami-12345678",
            "tags": {
                "Environment": "dev",
                "Owner": "test-user",
                "Project": "test-project",
                "CostCenter": "123"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 1
    contains(result[_], "prohibited instance type")
}

# Test: Instance with unencrypted root volume should be denied
test_deny_unencrypted_root_volume if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678",
            "root_block_device": [{
                "encrypted": false,
                "volume_size": 20
            }],
            "tags": {
                "Environment": "dev",
                "Owner": "test-user",
                "Project": "test-project",
                "CostCenter": "123"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 1
    contains(result[_], "unencrypted root EBS volume")
}

# Test: Instance without monitoring should be denied
test_deny_instance_without_monitoring if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678",
            "monitoring": false,
            "tags": {
                "Environment": "dev",
                "Owner": "test-user",
                "Project": "test-project",
                "CostCenter": "123"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 1
    contains(result[_], "monitoring")
}

# Test: Instance without IAM instance profile should be denied
test_deny_instance_without_iam_profile if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678",
            "tags": {
                "Environment": "dev",
                "Owner": "test-user",
                "Project": "test-project",
                "CostCenter": "123"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 1
    contains(result[_], "IAM instance profile")
}

# Test: Instance with public IP should be denied (unless public-facing)
test_deny_instance_with_public_ip if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678",
            "associate_public_ip_address": true,
            "tags": {
                "Environment": "dev",
                "Owner": "test-user",
                "Project": "test-project",
                "CostCenter": "123"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 1
    contains(result[_], "public IP")
}

# Test: Public-facing instance with public IP should be allowed
test_allow_public_facing_instance_with_public_ip if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "web-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678",
            "associate_public_ip_address": true,
            "root_block_device": [{
                "encrypted": true,
                "volume_size": 20
            }],
            "monitoring": true,
            "iam_instance_profile": "web-instance-profile",
            "vpc_security_group_ids": ["sg-12345678"],
            "tags": {
                "Environment": "dev",
                "Owner": "test-user",
                "Project": "test-project",
                "CostCenter": "123",
                "Purpose": "web-server"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 0
}

# Test: Production instance without backup policy should be denied
test_deny_production_instance_without_backup if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "prod-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-12345678",
            "tags": {
                "Environment": "production",
                "Owner": "prod-team",
                "Project": "critical-app",
                "CostCenter": "456"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) >= 1
    contains(result[_], "backup policy")
}

# Test: Fully compliant instance should pass all policies
test_fully_compliant_instance if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "compliant-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-amazon-linux-2023",
            "root_block_device": [{
                "encrypted": true,
                "volume_size": 20
            }],
            "monitoring": true,
            "iam_instance_profile": "compliant-instance-profile",
            "vpc_security_group_ids": ["sg-12345678"],
            "tags": {
                "Environment": "production",
                "Owner": "dev-team",
                "Project": "web-app",
                "CostCenter": "123",
                "BackupPolicy": "daily"
            }
        }
    }
    
    result := instance_compliance.deny with input as input
    count(result) == 0
}

# -----------------------------------------------------------------------------
# EBS ENCRYPTION POLICY TESTS
# -----------------------------------------------------------------------------

# Test: Unencrypted EBS volume should be denied
test_deny_unencrypted_ebs_volume if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "test-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": false
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 1
    contains(result[_], "not encrypted")
}

# Test: Encrypted EBS volume should be allowed
test_allow_encrypted_ebs_volume if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "test-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": true
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 0
}

# Test: Sensitive volume without customer managed key should be denied
test_deny_sensitive_volume_without_cmk if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "sensitive-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": true,
            "tags": {
                "Sensitivity": "high"
            }
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 1
    contains(result[_], "customer managed KMS key")
}

# Test: Sensitive volume with customer managed key should be allowed
test_allow_sensitive_volume_with_cmk if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "sensitive-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": true,
            "kms_key_id": "alias/sensitive-data-key",
            "tags": {
                "Sensitivity": "high"
            }
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 0
}

# Test: Unencrypted snapshot should be denied
test_deny_unencrypted_snapshot if {
    input := {
        "resource_type": "aws_ebs_snapshot",
        "resource_name": "test-snapshot",
        "config": {
            "volume_id": "vol-12345678",
            "encrypted": false
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 1
    contains(result[_], "not encrypted")
}

# Test: Launch template with unencrypted volume should be denied
test_deny_launch_template_unencrypted_volume if {
    input := {
        "resource_type": "aws_launch_template",
        "resource_name": "test-template",
        "config": {
            "block_device_mappings": [{
                "device_name": "/dev/xvda",
                "ebs": [{
                    "volume_size": 20,
                    "volume_type": "gp3",
                    "encrypted": false
                }]
            }]
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 1
    contains(result[_], "unencrypted EBS volume")
}

# Test: Production volume without customer managed key should be denied
test_deny_production_volume_without_cmk if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "prod-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": true,
            "tags": {
                "Environment": "production"
            }
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 1
    contains(result[_], "customer managed KMS key")
}

# Test: RDS instance without encryption should be denied
test_deny_rds_without_encryption if {
    input := {
        "resource_type": "aws_db_instance",
        "resource_name": "test-db",
        "config": {
            "engine": "mysql",
            "instance_class": "db.t3.micro",
            "storage_encrypted": false
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) == 1
    contains(result[_], "storage encryption")
}

# Test: PCI DSS compliance volume without encryption should be denied
test_deny_pci_dss_volume_without_encryption if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "pci-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": false,
            "tags": {
                "Compliance": "PCI-DSS"
            }
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) >= 1
    contains(result[_], "PCI DSS")
}

# Test: HIPAA compliance volume without encryption should be denied
test_deny_hipaa_volume_without_encryption if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "hipaa-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": false,
            "tags": {
                "Compliance": "HIPAA"
            }
        }
    }
    
    result := ebs_encryption.deny with input as input
    count(result) >= 1
    contains(result[_], "HIPAA")
}

# -----------------------------------------------------------------------------
# HELPER FUNCTION TESTS
# -----------------------------------------------------------------------------

# Test: ami_is_approved helper function
test_ami_is_approved if {
    input := {
        "resource_type": "aws_instance",
        "resource_name": "test-instance",
        "config": {
            "ami": "ami-amazon-linux-2023"
        }
    }
    
    result := instance_compliance.ami_is_approved("ami-amazon-linux-2023") with input as input
    result == true
}

# Test: is_sensitive_volume helper function
test_is_sensitive_volume if {
    input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "sensitive-volume",
        "config": {
            "tags": {
                "Sensitivity": "confidential"
            }
        }
    }
    
    result := ebs_encryption.is_sensitive_volume with input as input
    result == true
}

# Test: is_database_port helper function
test_is_database_port if {
    result := security_groups.is_database_port(3306)
    result == true
}

# Test: allows_internet_access helper function
test_allows_internet_access if {
    input := {
        "resource_type": "aws_security_group",
        "resource_name": "test-sg",
        "config": {
            "ingress": [{
                "from_port": 80,
                "to_port": 80,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
            }]
        }
    }
    
    result := security_groups.allows_internet_access with input as input
    result == true
}

# -----------------------------------------------------------------------------
# INTEGRATION TESTS
# -----------------------------------------------------------------------------

# Test: Fully compliant infrastructure should pass all policies
test_fully_compliant_infrastructure if {
    # Test security group
    sg_input := {
        "resource_type": "aws_security_group",
        "resource_name": "web-sg",
        "config": {
            "description": "Security group for web servers",
            "ingress": [{
                "from_port": 80,
                "to_port": 80,
                "protocol": "tcp",
                "cidr_blocks": ["10.0.0.0/8"]
            }],
            "tags": {
                "Environment": "production",
                "Owner": "web-team",
                "Purpose": "web-server"
            }
        }
    }
    
    # Test instance
    instance_input := {
        "resource_type": "aws_instance",
        "resource_name": "web-instance",
        "config": {
            "instance_type": "t3.micro",
            "ami": "ami-amazon-linux-2023",
            "root_block_device": [{
                "encrypted": true,
                "volume_size": 20
            }],
            "monitoring": true,
            "iam_instance_profile": "web-instance-profile",
            "vpc_security_group_ids": ["sg-12345678"],
            "tags": {
                "Environment": "production",
                "Owner": "web-team",
                "Project": "web-app",
                "CostCenter": "123",
                "BackupPolicy": "daily"
            }
        }
    }
    
    # Test EBS volume
    volume_input := {
        "resource_type": "aws_ebs_volume",
        "resource_name": "web-volume",
        "config": {
            "size": 100,
            "type": "gp3",
            "encrypted": true,
            "kms_key_id": "alias/web-app-key",
            "tags": {
                "Environment": "production"
            }
        }
    }
    
    sg_result := security_groups.deny with input as sg_input
    instance_result := instance_compliance.deny with input as instance_input
    volume_result := ebs_encryption.deny with input as volume_input
    
    count(sg_result) == 0
    count(instance_result) == 0
    count(volume_result) == 0
}