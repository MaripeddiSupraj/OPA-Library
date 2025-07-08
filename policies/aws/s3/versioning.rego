# =============================================================================
# S3 Versioning Policy
# =============================================================================
# Purpose: Ensure S3 buckets have versioning enabled for data protection
# Rationale: Versioning protects against accidental deletion and modification
#           of objects, enabling recovery and audit trails
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.s3.versioning

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# POLICY: Require versioning for S3 buckets
# -----------------------------------------------------------------------------
# This policy ensures that all S3 buckets have versioning enabled to protect
# against accidental deletion and provide object history.

deny[msg] if {
    # Check if the resource is an S3 bucket
    input.resource_type == "aws_s3_bucket"
    
    # Check if versioning configuration is missing
    not input.config.versioning
    
    # Generate violation message
    msg := sprintf("S3 bucket '%s' does not have versioning configured. Enable versioning to protect against accidental deletion and modification.", [
        input.resource_name
    ])
}

deny[msg] if {
    # Check if the resource is an S3 bucket
    input.resource_type == "aws_s3_bucket"
    
    # Check if versioning exists but is disabled
    versioning := input.config.versioning[_]
    not versioning.enabled == true
    
    msg := sprintf("S3 bucket '%s' has versioning disabled. Enable versioning to protect against data loss.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require MFA Delete for sensitive buckets
# -----------------------------------------------------------------------------
# This policy ensures that buckets containing sensitive data have MFA Delete
# enabled to prevent unauthorized deletion of object versions.

# Uncomment to enforce MFA Delete for sensitive buckets
# deny[msg] if {
#     input.resource_type == "aws_s3_bucket"
#     
#     # Check if bucket is marked as sensitive
#     is_sensitive_bucket
#     
#     # Check if versioning is enabled
#     versioning := input.config.versioning[_]
#     versioning.enabled == true
#     
#     # Check if MFA Delete is not enabled
#     not versioning.mfa_delete == true
#     
#     msg := sprintf("S3 bucket '%s' contains sensitive data and must have MFA Delete enabled. Configure MFA Delete for additional security.", [
#         input.resource_name
#     ])
# }

# -----------------------------------------------------------------------------
# POLICY: Warn about lifecycle configuration
# -----------------------------------------------------------------------------
# This policy provides warnings about lifecycle configuration to help manage
# versioned objects and storage costs.

warn[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Check if versioning is enabled
    versioning := input.config.versioning[_]
    versioning.enabled == true
    
    # Check if lifecycle configuration is missing
    not input.config.lifecycle_configuration
    
    msg := sprintf("S3 bucket '%s' has versioning enabled but no lifecycle configuration. Consider adding lifecycle rules to manage object versions and costs.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate lifecycle configuration for versioned buckets
# -----------------------------------------------------------------------------
# This policy ensures that versioned buckets have appropriate lifecycle rules
# to manage noncurrent versions and prevent excessive storage costs.

warn[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Check if versioning is enabled
    versioning := input.config.versioning[_]
    versioning.enabled == true
    
    # Check if lifecycle configuration exists
    lifecycle_config := input.config.lifecycle_configuration[_]
    
    # Check if there are no rules for noncurrent versions
    not has_noncurrent_version_rules(lifecycle_config)
    
    msg := sprintf("S3 bucket '%s' has versioning enabled but no lifecycle rules for noncurrent versions. Add rules to manage old versions and control costs.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Temporary bucket exemptions
# -----------------------------------------------------------------------------
# This policy allows temporary buckets to skip versioning requirements
# based on specific tags or naming patterns.

# Allow temporary buckets to skip versioning
allow if {
    input.resource_type == "aws_s3_bucket"
    input.config.tags.Purpose == "temporary"
    input.config.tags.TTL  # Has Time-To-Live tag
}

allow if {
    input.resource_type == "aws_s3_bucket"
    startswith(input.resource_name, "temp-")
    input.config.tags.AutoDelete == "true"
}

# Allow logging buckets to skip versioning (they have their own retention)
allow if {
    input.resource_type == "aws_s3_bucket"
    input.config.tags.Purpose == "logging"
}

allow if {
    input.resource_type == "aws_s3_bucket"
    contains(input.resource_name, "logs")
    input.config.tags.LogRetention  # Has log retention configured
}

# -----------------------------------------------------------------------------
# POLICY: Cross-region replication requirements
# -----------------------------------------------------------------------------
# This policy ensures that critical buckets with versioning also have
# cross-region replication for disaster recovery.

# Uncomment to enforce cross-region replication for critical buckets
# deny[msg] if {
#     input.resource_type == "aws_s3_bucket"
#     
#     # Check if bucket is marked as critical
#     is_critical_bucket
#     
#     # Check if versioning is enabled
#     versioning := input.config.versioning[_]
#     versioning.enabled == true
#     
#     # Check if replication configuration is missing
#     not input.config.replication_configuration
#     
#     msg := sprintf("S3 bucket '%s' is critical and must have cross-region replication enabled. Configure replication for disaster recovery.", [
#         input.resource_name
#     ])
# }

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

# Check if bucket is marked as sensitive based on tags or naming
is_sensitive_bucket if {
    input.resource_type == "aws_s3_bucket"
    input.config.tags.Sensitivity in ["high", "confidential", "restricted"]
}

is_sensitive_bucket if {
    input.resource_type == "aws_s3_bucket"
    input.config.tags.DataClassification in ["sensitive", "confidential"]
}

# Check if bucket is marked as critical
is_critical_bucket if {
    input.resource_type == "aws_s3_bucket"
    input.config.tags.Criticality in ["high", "critical"]
}

is_critical_bucket if {
    input.resource_type == "aws_s3_bucket"
    input.config.tags.BusinessImpact == "critical"
}

# Check if bucket has lifecycle rules for noncurrent versions
has_noncurrent_version_rules(lifecycle_config) if {
    rule := lifecycle_config.rule[_]
    rule.noncurrent_version_expiration[_]
}

has_noncurrent_version_rules(lifecycle_config) if {
    rule := lifecycle_config.rule[_]
    rule.noncurrent_version_transition[_]
}

# Check if bucket has versioning enabled
has_versioning if {
    input.resource_type == "aws_s3_bucket"
    versioning := input.config.versioning[_]
    versioning.enabled == true
}

# Check if bucket has MFA Delete enabled
has_mfa_delete if {
    input.resource_type == "aws_s3_bucket"
    versioning := input.config.versioning[_]
    versioning.mfa_delete == true
}

# Check if bucket has replication configured
has_replication if {
    input.resource_type == "aws_s3_bucket"
    input.config.replication_configuration[_]
}

# Get versioning status
get_versioning_status := status if {
    input.resource_type == "aws_s3_bucket"
    versioning := input.config.versioning[_]
    versioning.enabled == true
    status := "enabled"
}

get_versioning_status := status if {
    input.resource_type == "aws_s3_bucket"
    versioning := input.config.versioning[_]
    not versioning.enabled == true
    status := "disabled"
}

get_versioning_status := status if {
    input.resource_type == "aws_s3_bucket"
    not input.config.versioning
    status := "not_configured"
}

# -----------------------------------------------------------------------------
# INFORMATIONAL RULES
# -----------------------------------------------------------------------------
# These rules provide information about versioning configuration

info[msg] if {
    input.resource_type == "aws_s3_bucket"
    has_versioning
    
    msg := sprintf("S3 bucket '%s' has versioning enabled", [
        input.resource_name
    ])
}

info[msg] if {
    input.resource_type == "aws_s3_bucket"
    has_versioning
    has_mfa_delete
    
    msg := sprintf("S3 bucket '%s' has versioning and MFA Delete enabled", [
        input.resource_name
    ])
}

info[msg] if {
    input.resource_type == "aws_s3_bucket"
    has_versioning
    has_replication
    
    msg := sprintf("S3 bucket '%s' has versioning and cross-region replication enabled", [
        input.resource_name
    ])
}

# Warning for buckets with versioning but no lifecycle management
warn[msg] if {
    input.resource_type == "aws_s3_bucket"
    has_versioning
    not input.config.lifecycle_configuration
    not input.config.tags.Purpose == "temporary"
    
    msg := sprintf("S3 bucket '%s' has versioning enabled but no lifecycle configuration. This may result in increased storage costs over time.", [
        input.resource_name
    ])
}