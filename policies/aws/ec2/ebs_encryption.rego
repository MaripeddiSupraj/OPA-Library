# =============================================================================
# EBS Encryption Policy
# =============================================================================
# Purpose: Ensure all EBS volumes are encrypted at rest for data protection
# Rationale: EBS encryption protects data at rest and in transit between
#           instances and EBS volumes, meeting compliance requirements
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.ec2.ebs_encryption

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# POLICY: Require encryption for all EBS volumes
# -----------------------------------------------------------------------------
# This policy ensures that all EBS volumes are encrypted at rest using
# either AWS managed keys or customer managed keys.

deny[msg] if {
    # Check if the resource is an EBS volume
    input.resource_type == "aws_ebs_volume"
    
    # Check if encryption is disabled
    not input.config.encrypted == true
    
    msg := sprintf("EBS volume '%s' is not encrypted. Enable encryption to protect data at rest and meet compliance requirements.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require encryption for EC2 instance root volumes
# -----------------------------------------------------------------------------
# This policy ensures that root EBS volumes of EC2 instances are encrypted.

deny[msg] if {
    # Check if the resource is an EC2 instance
    input.resource_type == "aws_instance"
    
    # Check root block device encryption
    root_block_device := input.config.root_block_device[_]
    not root_block_device.encrypted == true
    
    msg := sprintf("EC2 instance '%s' has an unencrypted root EBS volume. Enable encryption for the root volume to protect the operating system and application data.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require encryption for additional EBS volumes on EC2 instances
# -----------------------------------------------------------------------------
# This policy ensures that additional EBS volumes attached to EC2 instances
# are encrypted.

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check additional EBS volumes
    ebs_block_device := input.config.ebs_block_device[_]
    not ebs_block_device.encrypted == true
    
    msg := sprintf("EC2 instance '%s' has an unencrypted EBS volume at device '%s'. Enable encryption for all EBS volumes to protect data at rest.", [
        input.resource_name,
        ebs_block_device.device_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require customer managed KMS keys for sensitive data
# -----------------------------------------------------------------------------
# This policy ensures that EBS volumes containing sensitive data use
# customer managed KMS keys instead of AWS managed keys.

deny[msg] if {
    input.resource_type == "aws_ebs_volume"
    
    # Check if volume contains sensitive data
    is_sensitive_volume
    
    # Check if encryption is enabled
    input.config.encrypted == true
    
    # Check if using AWS managed key (no kms_key_id specified)
    not input.config.kms_key_id
    
    msg := sprintf("EBS volume '%s' contains sensitive data and must use a customer managed KMS key. Specify a kms_key_id for enhanced security control.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if instance handles sensitive data
    is_sensitive_instance
    
    # Check root volume encryption with customer managed key
    root_block_device := input.config.root_block_device[_]
    root_block_device.encrypted == true
    not root_block_device.kms_key_id
    
    msg := sprintf("EC2 instance '%s' handles sensitive data and must use a customer managed KMS key for root volume encryption. Specify a kms_key_id for enhanced security.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate KMS key configuration
# -----------------------------------------------------------------------------
# This policy ensures that when KMS keys are used, they are properly configured.

deny[msg] if {
    input.resource_type == "aws_ebs_volume"
    
    # Check if encryption is enabled with KMS key
    input.config.encrypted == true
    kms_key_id := input.config.kms_key_id
    
    # Check if KMS key is using alias format (recommended)
    not startswith(kms_key_id, "alias/")
    not startswith(kms_key_id, "arn:aws:kms:")
    
    msg := sprintf("EBS volume '%s' uses KMS key '%s' which appears to be a key ID. Use key aliases (alias/key-name) or ARNs for better key management.", [
        input.resource_name,
        kms_key_id
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require encryption for snapshots
# -----------------------------------------------------------------------------
# This policy ensures that EBS snapshots are encrypted when created from
# encrypted volumes.

deny[msg] if {
    input.resource_type == "aws_ebs_snapshot"
    
    # Check if snapshot is not encrypted
    not input.config.encrypted == true
    
    msg := sprintf("EBS snapshot '%s' is not encrypted. Ensure snapshots are encrypted to protect data at rest.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate volume types for encryption
# -----------------------------------------------------------------------------
# This policy ensures that appropriate volume types are used with encryption.

warn[msg] if {
    input.resource_type == "aws_ebs_volume"
    
    # Check if using old volume types
    volume_type := input.config.type
    volume_type in ["standard", "io1"]
    
    # Check if encryption is enabled
    input.config.encrypted == true
    
    msg := sprintf("EBS volume '%s' uses older volume type '%s' with encryption. Consider upgrading to gp3 or io2 for better performance and cost efficiency.", [
        input.resource_name,
        volume_type
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require encryption for launch templates
# -----------------------------------------------------------------------------
# This policy ensures that launch templates specify encrypted EBS volumes.

deny[msg] if {
    input.resource_type == "aws_launch_template"
    
    # Check block device mappings in launch template
    block_device := input.config.block_device_mappings[_]
    ebs_config := block_device.ebs[_]
    
    # Check if encryption is not enabled
    not ebs_config.encrypted == true
    
    msg := sprintf("Launch template '%s' has unencrypted EBS volume configuration for device '%s'. Enable encryption in launch template to ensure all instances use encrypted volumes.", [
        input.resource_name,
        block_device.device_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require encryption for Auto Scaling Groups
# -----------------------------------------------------------------------------
# This policy ensures that Auto Scaling Groups use launch templates or
# configurations with encrypted EBS volumes.

deny[msg] if {
    input.resource_type == "aws_autoscaling_group"
    
    # Check if using launch configuration (deprecated)
    launch_config := input.config.launch_configuration
    launch_config
    
    msg := sprintf("Auto Scaling Group '%s' uses launch configuration instead of launch template. Use launch templates for better EBS encryption control and modern features.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate encryption in transit
# -----------------------------------------------------------------------------
# This policy provides guidance on encryption in transit for EBS volumes.

info[msg] if {
    input.resource_type == "aws_ebs_volume"
    
    # Check if volume is encrypted
    input.config.encrypted == true
    
    msg := sprintf("EBS volume '%s' is encrypted at rest. Note that encryption in transit between EC2 and EBS is automatically enabled for supported instance types.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Check for unencrypted volume attachments
# -----------------------------------------------------------------------------
# This policy checks for volume attachments that might bypass encryption.

deny[msg] if {
    input.resource_type == "aws_volume_attachment"
    
    # This would require cross-referencing with the actual volume
    # In practice, you would need to check the referenced volume's encryption status
    # This is a placeholder for such validation
    
    msg := sprintf("Volume attachment '%s' should be validated to ensure the attached volume is encrypted.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require encryption for database instances with EBS
# -----------------------------------------------------------------------------
# This policy ensures that database instances using EBS storage are encrypted.

deny[msg] if {
    input.resource_type == "aws_db_instance"
    
    # Check if storage is not encrypted
    not input.config.storage_encrypted == true
    
    msg := sprintf("RDS instance '%s' does not have storage encryption enabled. Enable storage encryption to protect database data at rest.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

# Check if EBS volume contains sensitive data based on tags or naming
is_sensitive_volume if {
    input.resource_type == "aws_ebs_volume"
    input.config.tags.Sensitivity in ["high", "confidential", "restricted"]
}

is_sensitive_volume if {
    input.resource_type == "aws_ebs_volume"
    input.config.tags.DataClassification in ["sensitive", "confidential", "restricted"]
}

is_sensitive_volume if {
    input.resource_type == "aws_ebs_volume"
    contains(lower(input.resource_name), "sensitive")
}

is_sensitive_volume if {
    input.resource_type == "aws_ebs_volume"
    contains(lower(input.resource_name), "confidential")
}

# Check if EC2 instance handles sensitive data
is_sensitive_instance if {
    input.resource_type == "aws_instance"
    input.config.tags.Sensitivity in ["high", "confidential", "restricted"]
}

is_sensitive_instance if {
    input.resource_type == "aws_instance"
    input.config.tags.DataClassification in ["sensitive", "confidential", "restricted"]
}

is_sensitive_instance if {
    input.resource_type == "aws_instance"
    input.config.tags.Purpose in ["database", "file-server", "application-server"]
}

# Check if volume is in production environment
is_production_volume if {
    input.config.tags.Environment == "production"
}

# Check if KMS key is customer managed
is_customer_managed_key(kms_key_id) if {
    startswith(kms_key_id, "alias/")
    not startswith(kms_key_id, "alias/aws/")
}

is_customer_managed_key(kms_key_id) if {
    startswith(kms_key_id, "arn:aws:kms:")
    not contains(kms_key_id, "alias/aws/")
}

# Check if volume type is modern
is_modern_volume_type(volume_type) if {
    volume_type in ["gp3", "io2", "io2-block-express"]
}

# Get encryption status for volume
get_encryption_status := status if {
    input.resource_type == "aws_ebs_volume"
    input.config.encrypted == true
    input.config.kms_key_id
    status := "encrypted_with_cmk"
}

get_encryption_status := status if {
    input.resource_type == "aws_ebs_volume"
    input.config.encrypted == true
    not input.config.kms_key_id
    status := "encrypted_with_aws_managed_key"
}

get_encryption_status := status if {
    input.resource_type == "aws_ebs_volume"
    not input.config.encrypted == true
    status := "not_encrypted"
}

# Check if instance type supports encryption in transit
supports_encryption_in_transit(instance_type) if {
    # Most modern instance types support encryption in transit
    # This is a simplified check - in practice, you'd maintain a comprehensive list
    instance_family := split(instance_type, ".")[0]
    instance_family in ["m5", "m5a", "m5n", "m5dn", "m6i", "m6a", "c5", "c5a", "c5n", "c6i", "c6a", "r5", "r5a", "r5n", "r5dn", "r6i", "r6a"]
}

# -----------------------------------------------------------------------------
# INFORMATIONAL RULES
# -----------------------------------------------------------------------------
# These rules provide information about encryption configuration

info[msg] if {
    input.resource_type == "aws_ebs_volume"
    input.config.encrypted == true
    input.config.kms_key_id
    
    msg := sprintf("EBS volume '%s' is encrypted with customer managed KMS key: %s", [
        input.resource_name,
        input.config.kms_key_id
    ])
}

info[msg] if {
    input.resource_type == "aws_ebs_volume"
    input.config.encrypted == true
    not input.config.kms_key_id
    
    msg := sprintf("EBS volume '%s' is encrypted with AWS managed key", [
        input.resource_name
    ])
}

info[msg] if {
    input.resource_type == "aws_instance"
    
    # Count encrypted volumes
    encrypted_count := count([1 |
        root_block_device := input.config.root_block_device[_]
        root_block_device.encrypted == true
    ]) + count([1 |
        ebs_block_device := input.config.ebs_block_device[_]
        ebs_block_device.encrypted == true
    ])
    
    total_count := count(input.config.root_block_device) + count(input.config.ebs_block_device)
    
    msg := sprintf("EC2 instance '%s' has %d/%d encrypted EBS volumes", [
        input.resource_name,
        encrypted_count,
        total_count
    ])
}

# -----------------------------------------------------------------------------
# ENVIRONMENT-SPECIFIC RULES
# -----------------------------------------------------------------------------
# These rules apply different encryption requirements based on environment

# Production environment requires customer managed keys
deny[msg] if {
    input.resource_type == "aws_ebs_volume"
    is_production_volume
    
    # Check if encrypted but not with customer managed key
    input.config.encrypted == true
    not input.config.kms_key_id
    
    msg := sprintf("Production EBS volume '%s' must use customer managed KMS key. AWS managed keys are not sufficient for production environments.", [
        input.resource_name
    ])
}

# Development environment warnings
warn[msg] if {
    input.resource_type == "aws_ebs_volume"
    input.config.tags.Environment == "development"
    not input.config.encrypted == true
    
    msg := sprintf("Development EBS volume '%s' is not encrypted. While not strictly required for development, encryption is recommended for consistency with production.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# COMPLIANCE RULES
# -----------------------------------------------------------------------------
# These rules help meet specific compliance requirements

# PCI DSS compliance requires encryption for systems handling cardholder data
deny[msg] if {
    input.resource_type == "aws_ebs_volume"
    input.config.tags.Compliance == "PCI-DSS"
    not input.config.encrypted == true
    
    msg := sprintf("EBS volume '%s' is marked for PCI DSS compliance and must be encrypted. Encryption is required for systems handling cardholder data.", [
        input.resource_name
    ])
}

# HIPAA compliance requires encryption for PHI data
deny[msg] if {
    input.resource_type == "aws_ebs_volume"
    input.config.tags.Compliance == "HIPAA"
    not input.config.encrypted == true
    
    msg := sprintf("EBS volume '%s' is marked for HIPAA compliance and must be encrypted. Encryption is required for systems handling PHI data.", [
        input.resource_name
    ])
}

# SOC 2 compliance recommendations
warn[msg] if {
    input.resource_type == "aws_ebs_volume"
    input.config.tags.Compliance == "SOC2"
    input.config.encrypted == true
    not input.config.kms_key_id
    
    msg := sprintf("EBS volume '%s' is marked for SOC 2 compliance. Consider using customer managed KMS keys for enhanced security controls and audit capabilities.", [
        input.resource_name
    ])
}