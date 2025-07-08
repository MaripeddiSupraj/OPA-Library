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
import future.keywords.in

# Test: Security group with SSH open to internet should be denied
test_deny_ssh_open_to_internet {
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
}

# Test: Security group with proper configuration should be allowed
test_allow_proper_security_group {
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

# Test: Instance without required tags should be denied
test_deny_instance_without_tags {
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
}

# Test: Fully compliant instance should pass all policies
test_fully_compliant_instance {
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

# Test: Unencrypted EBS volume should be denied
test_deny_unencrypted_ebs_volume {
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
}

# Test: Encrypted EBS volume should be allowed
test_allow_encrypted_ebs_volume {
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

# Test: Helper function tests
test_is_database_port {
    result := security_groups.is_database_port(3306)
    result == true
}

test_allows_internet_access {
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