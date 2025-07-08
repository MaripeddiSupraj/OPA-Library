# =============================================================================
# S3 Encryption Policy
# =============================================================================
# Purpose: Ensure S3 buckets have encryption at rest enabled
# Rationale: Encryption at rest protects data stored in S3 from unauthorized
#           access and is required for compliance with many security standards
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.s3.encryption

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# POLICY: Require encryption at rest for S3 buckets
# -----------------------------------------------------------------------------
# This policy ensures that all S3 buckets have server-side encryption enabled
# with either AES256 or aws:kms encryption methods.

deny[msg] if {
    # Check if the resource is an S3 bucket
    input.resource_type == "aws_s3_bucket"
    
    # Check if server-side encryption configuration is missing
    not input.config.server_side_encryption_configuration
    
    # Generate violation message
    msg := sprintf("S3 bucket '%s' does not have server-side encryption enabled. Enable encryption at rest to protect stored data.", [
        input.resource_name
    ])
}

deny[msg] if {
    # Check if the resource is an S3 bucket
    input.resource_type == "aws_s3_bucket"
    
    # Check if encryption configuration exists but is empty
    encryption_config := input.config.server_side_encryption_configuration[_]
    count(encryption_config.rule) == 0
    
    msg := sprintf("S3 bucket '%s' has empty encryption configuration. Configure encryption rules to protect stored data.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate encryption algorithm
# -----------------------------------------------------------------------------
# This policy ensures that only approved encryption algorithms are used
# (AES256 or aws:kms).

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Get encryption configuration
    encryption_config := input.config.server_side_encryption_configuration[_]
    rule := encryption_config.rule[_]
    
    # Check if encryption method is specified but not approved
    sse_algorithm := rule.apply_server_side_encryption_by_default[_].sse_algorithm
    not sse_algorithm in ["AES256", "aws:kms"]
    
    msg := sprintf("S3 bucket '%s' uses unsupported encryption algorithm '%s'. Use 'AES256' or 'aws:kms' for encryption.", [
        input.resource_name,
        sse_algorithm
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require KMS encryption for sensitive data
# -----------------------------------------------------------------------------
# This policy can be enabled to require KMS encryption for buckets containing
# sensitive data, identified by specific tags or naming patterns.

# Uncomment to enforce KMS encryption for sensitive buckets
# deny[msg] if {
#     input.resource_type == "aws_s3_bucket"
#     
#     # Check if bucket is marked as sensitive
#     is_sensitive_bucket
#     
#     # Get encryption configuration
#     encryption_config := input.config.server_side_encryption_configuration[_]
#     rule := encryption_config.rule[_]
#     sse_algorithm := rule.apply_server_side_encryption_by_default[_].sse_algorithm
#     
#     # Require KMS encryption for sensitive buckets
#     sse_algorithm != "aws:kms"
#     
#     msg := sprintf("S3 bucket '%s' contains sensitive data and must use KMS encryption. Change encryption to 'aws:kms'.", [
#         input.resource_name
#     ])
# }

# -----------------------------------------------------------------------------
# POLICY: Require bucket key for KMS encryption
# -----------------------------------------------------------------------------
# This policy ensures that buckets using KMS encryption have bucket key enabled
# to reduce KMS API calls and costs.

warn[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Get encryption configuration
    encryption_config := input.config.server_side_encryption_configuration[_]
    rule := encryption_config.rule[_]
    
    # Check if using KMS encryption
    rule.apply_server_side_encryption_by_default[_].sse_algorithm == "aws:kms"
    
    # Check if bucket key is not enabled
    not rule.bucket_key_enabled == true
    
    msg := sprintf("S3 bucket '%s' uses KMS encryption but bucket key is not enabled. Enable bucket key to reduce costs and improve performance.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate KMS key configuration
# -----------------------------------------------------------------------------
# This policy ensures that when KMS encryption is used, proper key management
# practices are followed.

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Get encryption configuration
    encryption_config := input.config.server_side_encryption_configuration[_]
    rule := encryption_config.rule[_]
    encryption_default := rule.apply_server_side_encryption_by_default[_]
    
    # Check if using KMS encryption
    encryption_default.sse_algorithm == "aws:kms"
    
    # Check if KMS key is not specified (uses default key)
    not encryption_default.kms_master_key_id
    
    msg := sprintf("S3 bucket '%s' uses KMS encryption with default key. Specify a customer-managed KMS key for better security control.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require encryption in transit
# -----------------------------------------------------------------------------
# This policy ensures that S3 buckets have policies that enforce encryption
# in transit (HTTPS).

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Check if bucket policy exists
    bucket_policy := input.config.policy
    
    # If no policy exists, we cannot enforce HTTPS
    not bucket_policy
    
    msg := sprintf("S3 bucket '%s' does not have a bucket policy to enforce HTTPS. Add a bucket policy to require encrypted connections.", [
        input.resource_name
    ])
}

# Check if bucket policy enforces HTTPS
deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Parse bucket policy
    bucket_policy := input.config.policy
    policy_doc := json.unmarshal(bucket_policy)
    
    # Check if there's a statement that denies non-HTTPS requests
    not has_https_enforcement(policy_doc)
    
    msg := sprintf("S3 bucket '%s' bucket policy does not enforce HTTPS. Add a statement to deny requests without encryption in transit.", [
        input.resource_name
    ])
}

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
    contains(lower(input.resource_name), "sensitive")
}

is_sensitive_bucket if {
    input.resource_type == "aws_s3_bucket"
    contains(lower(input.resource_name), "confidential")
}

# Check if bucket policy enforces HTTPS
has_https_enforcement(policy_doc) if {
    # Look for a statement that denies non-HTTPS requests
    statement := policy_doc.Statement[_]
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
}

has_https_enforcement(policy_doc) if {
    # Alternative check for HTTPS enforcement
    statement := policy_doc.Statement[_]
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == false
}

# Check if bucket has encryption enabled
has_encryption if {
    input.resource_type == "aws_s3_bucket"
    input.config.server_side_encryption_configuration[_]
}

# Get encryption algorithm for bucket
get_encryption_algorithm := algorithm if {
    input.resource_type == "aws_s3_bucket"
    encryption_config := input.config.server_side_encryption_configuration[_]
    rule := encryption_config.rule[_]
    algorithm := rule.apply_server_side_encryption_by_default[_].sse_algorithm
}

# Check if bucket uses KMS encryption
uses_kms_encryption if {
    get_encryption_algorithm == "aws:kms"
}

# -----------------------------------------------------------------------------
# INFORMATIONAL RULES
# -----------------------------------------------------------------------------
# These rules provide information about encryption configuration

info[msg] if {
    input.resource_type == "aws_s3_bucket"
    has_encryption
    
    msg := sprintf("S3 bucket '%s' has encryption enabled with algorithm: %s", [
        input.resource_name,
        get_encryption_algorithm
    ])
}

warn[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Check if bucket has public access and no encryption
    input.config.acl in ["public-read", "public-read-write"]
    not has_encryption
    
    msg := sprintf("S3 bucket '%s' has public access AND no encryption. This is a critical security risk.", [
        input.resource_name
    ])
}