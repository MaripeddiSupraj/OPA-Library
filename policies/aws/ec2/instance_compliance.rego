# =============================================================================
# EC2 Instance Compliance Policy
# =============================================================================
# Purpose: Ensure EC2 instances follow security and compliance best practices
# Rationale: EC2 instances are the core compute resources and must be properly
#           configured for security, monitoring, and compliance requirements
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.ec2.instance_compliance

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# POLICY: Require proper tagging for EC2 instances
# -----------------------------------------------------------------------------
# This policy ensures all EC2 instances have required tags for management,
# cost allocation, and compliance tracking.

# Required tags for all EC2 instances
required_instance_tags := ["Environment", "Owner", "Project", "CostCenter"]

deny[msg] if {
    # Check if the resource is an EC2 instance
    input.resource_type == "aws_instance"
    
    # Check if tags are missing entirely
    not input.config.tags
    
    msg := sprintf("EC2 instance '%s' does not have any tags. Add required tags: %v for compliance and resource management.", [
        input.resource_name,
        required_instance_tags
    ])
}

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if required tags are missing
    existing_tags := object.keys(input.config.tags)
    missing_tags := [tag | tag := required_instance_tags[_]; not tag in existing_tags]
    count(missing_tags) > 0
    
    msg := sprintf("EC2 instance '%s' is missing required tags: %v. Add these tags for compliance and cost tracking.", [
        input.resource_name,
        missing_tags
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require approved AMI usage
# -----------------------------------------------------------------------------
# This policy ensures instances use only approved AMIs from your organization's
# golden image pipeline or trusted sources.

# Approved AMI patterns - customize these for your organization
approved_ami_patterns := [
    "ami-amazon-linux-*",
    "ami-ubuntu-*-official",
    "ami-windows-*-official",
    "ami-golden-*"  # Your organization's golden images
]

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if AMI is specified
    ami := input.config.ami
    
    # Check if AMI matches any approved pattern
    not ami_is_approved(ami)
    
    msg := sprintf("EC2 instance '%s' uses unapproved AMI '%s'. Use AMIs matching these patterns: %v", [
        input.resource_name,
        ami,
        approved_ami_patterns
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require specific instance types
# -----------------------------------------------------------------------------
# This policy restricts the use of instance types to approved ones and
# prevents the use of expensive or inappropriate instance types.

# Approved instance type families
approved_instance_families := ["t3", "t3a", "m5", "m5a", "c5", "c5a", "r5", "r5a"]

# Prohibited instance types (expensive or deprecated)
prohibited_instance_types := ["t1.micro", "m1.small", "m1.medium", "m1.large", "m1.xlarge", "c1.medium", "c1.xlarge"]

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if instance type is prohibited
    instance_type := input.config.instance_type
    instance_type in prohibited_instance_types
    
    msg := sprintf("EC2 instance '%s' uses prohibited instance type '%s'. Use newer generation instance types for better performance and cost efficiency.", [
        input.resource_name,
        instance_type
    ])
}

warn[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if instance type family is not in approved list
    instance_type := input.config.instance_type
    instance_family := split(instance_type, ".")[0]
    not instance_family in approved_instance_families
    
    msg := sprintf("EC2 instance '%s' uses instance type '%s' which is not in the approved families: %v. Consider using approved instance types.", [
        input.resource_name,
        instance_type,
        approved_instance_families
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require EBS encryption
# -----------------------------------------------------------------------------
# This policy ensures that all EBS volumes attached to instances are encrypted.

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check root block device encryption
    root_block_device := input.config.root_block_device[_]
    not root_block_device.encrypted == true
    
    msg := sprintf("EC2 instance '%s' has an unencrypted root EBS volume. Enable encryption for all EBS volumes to protect data at rest.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check additional EBS volumes
    ebs_block_device := input.config.ebs_block_device[_]
    not ebs_block_device.encrypted == true
    
    msg := sprintf("EC2 instance '%s' has an unencrypted EBS volume '%s'. Enable encryption for all EBS volumes to protect data at rest.", [
        input.resource_name,
        ebs_block_device.device_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require monitoring and logging
# -----------------------------------------------------------------------------
# This policy ensures instances have proper monitoring and logging enabled.

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if detailed monitoring is disabled
    not input.config.monitoring == true
    
    msg := sprintf("EC2 instance '%s' does not have detailed monitoring enabled. Enable monitoring for better observability and troubleshooting.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require IAM instance profile
# -----------------------------------------------------------------------------
# This policy ensures instances have IAM instance profiles attached for
# secure access to AWS services.

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if IAM instance profile is missing
    not input.config.iam_instance_profile
    
    msg := sprintf("EC2 instance '%s' does not have an IAM instance profile. Attach an IAM instance profile for secure access to AWS services.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate network configuration
# -----------------------------------------------------------------------------
# This policy ensures instances are launched in private subnets and have
# appropriate network configuration.

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if instance has public IP (should be avoided in most cases)
    input.config.associate_public_ip_address == true
    
    # Allow public IP for specific use cases (web servers, bastion hosts)
    not is_public_facing_instance
    
    msg := sprintf("EC2 instance '%s' is configured to receive a public IP address. Use private subnets and NAT gateways for better security.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require security group validation
# -----------------------------------------------------------------------------
# This policy ensures instances are associated with properly configured
# security groups.

deny[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if security groups are specified
    not input.config.vpc_security_group_ids
    not input.config.security_groups
    
    msg := sprintf("EC2 instance '%s' does not have any security groups assigned. Assign appropriate security groups for network access control.", [
        input.resource_name
    ])
}

warn[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if using default security group
    security_group := input.config.security_groups[_]
    security_group == "default"
    
    msg := sprintf("EC2 instance '%s' is using the default security group. Use custom security groups with specific rules for better security.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require proper sizing
# -----------------------------------------------------------------------------
# This policy warns about potential over-provisioning or under-provisioning.

warn[msg] if {
    input.resource_type == "aws_instance"
    
    # Check for large instance types that might be over-provisioned
    instance_type := input.config.instance_type
    contains(instance_type, "xlarge")
    
    # Check if this is not marked as a high-performance workload
    not input.config.tags.WorkloadType in ["high-performance", "memory-intensive", "compute-intensive"]
    
    msg := sprintf("EC2 instance '%s' uses large instance type '%s' but is not tagged as high-performance workload. Verify if this sizing is appropriate.", [
        input.resource_name,
        instance_type
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require backup configuration
# -----------------------------------------------------------------------------
# This policy ensures instances have proper backup and disaster recovery setup.

warn[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if instance is marked as persistent but has no backup configuration
    input.config.tags.Persistence == "persistent"
    not input.config.tags.BackupPolicy
    
    msg := sprintf("EC2 instance '%s' is marked as persistent but has no backup policy configured. Configure AWS Backup or snapshot schedules.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate placement and availability
# -----------------------------------------------------------------------------
# This policy ensures instances are properly distributed for high availability.

warn[msg] if {
    input.resource_type == "aws_instance"
    
    # Check if instance is not in a placement group for high availability
    input.config.tags.Criticality == "high"
    not input.config.placement_group
    
    msg := sprintf("EC2 instance '%s' is marked as high criticality but is not in a placement group. Consider using placement groups for better availability.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

# Check if AMI is approved based on patterns
ami_is_approved(ami) if {
    pattern := approved_ami_patterns[_]
    regex.match(pattern, ami)
}

# Check if instance is intended to be public-facing
is_public_facing_instance if {
    input.config.tags.Purpose in ["web-server", "bastion", "load-balancer"]
}

is_public_facing_instance if {
    input.config.tags.Tier == "public"
}

# Check if instance has proper naming convention
has_proper_naming if {
    name := input.resource_name
    contains(name, "-")
    count(split(name, "-")) >= 3  # Expected format: env-purpose-instance
}

# Check if instance is in approved subnet
is_in_approved_subnet if {
    # This would require additional context about subnet configuration
    # Implementation depends on your specific subnet naming/tagging strategy
    subnet_id := input.config.subnet_id
    # Add your subnet validation logic here
    true  # Placeholder
}

# Get instance family from instance type
get_instance_family(instance_type) := family if {
    family := split(instance_type, ".")[0]
}

# Check if instance is properly sized for workload
is_properly_sized if {
    instance_type := input.config.instance_type
    workload_type := input.config.tags.WorkloadType
    
    # Add your sizing validation logic here
    # This could include checking instance type against workload requirements
    true  # Placeholder
}

# -----------------------------------------------------------------------------
# INFORMATIONAL RULES
# -----------------------------------------------------------------------------
# These rules provide information about instance configuration

info[msg] if {
    input.resource_type == "aws_instance"
    
    # Count required tags that are present
    existing_tags := object.keys(input.config.tags)
    present_tags := [tag | tag := required_instance_tags[_]; tag in existing_tags]
    
    msg := sprintf("EC2 instance '%s' has %d/%d required tags: %v", [
        input.resource_name,
        count(present_tags),
        count(required_instance_tags),
        present_tags
    ])
}

info[msg] if {
    input.resource_type == "aws_instance"
    
    # Report encryption status
    root_block_device := input.config.root_block_device[_]
    root_block_device.encrypted == true
    
    msg := sprintf("EC2 instance '%s' has encrypted root volume", [
        input.resource_name
    ])
}

info[msg] if {
    input.resource_type == "aws_instance"
    
    # Report monitoring status
    input.config.monitoring == true
    
    msg := sprintf("EC2 instance '%s' has detailed monitoring enabled", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# ENVIRONMENT-SPECIFIC RULES
# -----------------------------------------------------------------------------
# These rules apply different policies based on environment

# Production environment specific rules
deny[msg] if {
    input.resource_type == "aws_instance"
    input.config.tags.Environment == "production"
    
    # Production instances must have backup configured
    not input.config.tags.BackupPolicy
    
    msg := sprintf("Production EC2 instance '%s' must have a backup policy configured. Add BackupPolicy tag with appropriate backup schedule.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_instance"
    input.config.tags.Environment == "production"
    
    # Production instances should not use spot instances for critical workloads
    input.config.instance_market_options[_].market_type == "spot"
    input.config.tags.Criticality == "high"
    
    msg := sprintf("Production EC2 instance '%s' with high criticality should not use spot instances. Use on-demand instances for critical workloads.", [
        input.resource_name
    ])
}