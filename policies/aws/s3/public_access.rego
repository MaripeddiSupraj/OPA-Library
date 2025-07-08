# =============================================================================
# S3 Public Access Policy
# =============================================================================
# Purpose: Prevent S3 buckets from being publicly accessible
# Rationale: Public S3 buckets are a common source of data breaches and
#           should be avoided unless explicitly required for static website hosting
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.s3.public_access

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# POLICY: Deny S3 buckets with public ACL
# -----------------------------------------------------------------------------
# This policy prevents S3 buckets from having public-read or public-read-write ACLs
# which would make the bucket contents publicly accessible on the internet.

deny[msg] if {
    # Check if the resource is an S3 bucket
    input.resource_type == "aws_s3_bucket"
    
    # Check if ACL is set to public-read or public-read-write
    input.config.acl in ["public-read", "public-read-write"]
    
    # Generate violation message
    msg := sprintf("S3 bucket '%s' has public ACL '%s'. Public ACLs expose bucket contents to the internet and should be avoided for security.", [
        input.resource_name,
        input.config.acl
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Deny S3 buckets with public access block disabled
# -----------------------------------------------------------------------------
# This policy ensures that S3 buckets have public access block settings enabled
# to prevent accidental public exposure through bucket policies or ACLs.

deny[msg] if {
    # Check if the resource is an S3 bucket
    input.resource_type == "aws_s3_bucket"
    
    # Check if public access block is not configured or disabled
    not input.config.public_access_block
    
    # Generate violation message
    msg := sprintf("S3 bucket '%s' does not have public access block configured. Enable public access block to prevent accidental public exposure.", [
        input.resource_name
    ])
}

deny[msg] if {
    # Check if the resource is an S3 bucket
    input.resource_type == "aws_s3_bucket"
    
    # Check if public access block exists but settings are disabled
    public_access_block := input.config.public_access_block[_]
    
    # Any of these settings being false is a security risk
    not public_access_block.block_public_acls
    
    msg := sprintf("S3 bucket '%s' has 'block_public_acls' disabled. This allows public ACLs to be applied to the bucket.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    public_access_block := input.config.public_access_block[_]
    not public_access_block.block_public_policy
    
    msg := sprintf("S3 bucket '%s' has 'block_public_policy' disabled. This allows public bucket policies to be applied.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    public_access_block := input.config.public_access_block[_]
    not public_access_block.ignore_public_acls
    
    msg := sprintf("S3 bucket '%s' has 'ignore_public_acls' disabled. This allows public ACLs to grant public access.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    public_access_block := input.config.public_access_block[_]
    not public_access_block.restrict_public_buckets
    
    msg := sprintf("S3 bucket '%s' has 'restrict_public_buckets' disabled. This allows public bucket policies to grant public access.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Deny S3 buckets with public bucket policies
# -----------------------------------------------------------------------------
# This policy checks bucket policies for statements that grant public access
# through Principal: "*" or conditions that allow public access.

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Check if bucket policy exists
    bucket_policy := input.config.policy
    
    # Parse the policy document (assuming it's a JSON string)
    policy_doc := json.unmarshal(bucket_policy)
    
    # Check each statement in the policy
    statement := policy_doc.Statement[_]
    
    # Check if statement has Effect: "Allow" and Principal: "*"
    statement.Effect == "Allow"
    statement.Principal == "*"
    
    msg := sprintf("S3 bucket '%s' has a bucket policy that grants public access with Principal: '*'. Remove public access from bucket policy.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    bucket_policy := input.config.policy
    policy_doc := json.unmarshal(bucket_policy)
    statement := policy_doc.Statement[_]
    
    # Check for Principal with AWS: "*"
    statement.Effect == "Allow"
    statement.Principal.AWS == "*"
    
    msg := sprintf("S3 bucket '%s' has a bucket policy that grants public access with Principal.AWS: '*'. Remove public access from bucket policy.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# EXCEPTIONS: Allow public access for specific use cases
# -----------------------------------------------------------------------------
# These rules define exceptions where public access might be acceptable,
# such as for static website hosting or public content distribution.

# Exception: Allow public access for static website hosting
# Uncomment and modify this rule if you need to allow public access for websites
# allow if {
#     input.resource_type == "aws_s3_bucket"
#     input.config.website[_]  # Bucket is configured for website hosting
#     
#     # Additional conditions can be added here, such as:
#     # - Specific naming pattern for website buckets
#     # - Specific tags indicating approved public access
#     # - Specific account or environment restrictions
# }

# Exception: Allow public access for buckets with specific tags
# allow if {
#     input.resource_type == "aws_s3_bucket"
#     input.config.tags.PublicAccess == "approved"
#     input.config.tags.Environment == "production"
#     
#     # Additional validation can be added here
# }

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

# Check if a bucket has any form of public access
has_public_access if {
    input.resource_type == "aws_s3_bucket"
    input.config.acl in ["public-read", "public-read-write"]
}

has_public_access if {
    input.resource_type == "aws_s3_bucket"
    not input.config.public_access_block
}

has_public_access if {
    input.resource_type == "aws_s3_bucket"
    public_access_block := input.config.public_access_block[_]
    not public_access_block.block_public_acls
}

has_public_access if {
    input.resource_type == "aws_s3_bucket"
    public_access_block := input.config.public_access_block[_]
    not public_access_block.block_public_policy
}

# Check if bucket is configured for website hosting
is_website_bucket if {
    input.resource_type == "aws_s3_bucket"
    input.config.website[_]
}

# -----------------------------------------------------------------------------
# INFORMATIONAL RULES
# -----------------------------------------------------------------------------
# These rules provide information about bucket configuration but don't deny

warn[msg] if {
    input.resource_type == "aws_s3_bucket"
    
    # Check if bucket has website configuration but no public access
    input.config.website[_]
    not has_public_access
    
    msg := sprintf("S3 bucket '%s' is configured for website hosting but has no public access. This may prevent the website from being accessible.", [
        input.resource_name
    ])
}