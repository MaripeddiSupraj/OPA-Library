# =============================================================================
# S3 Policy Tests
# =============================================================================
# Purpose: Test cases for S3 security policies
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.s3.tests

import data.aws.s3.public_access
import data.aws.s3.encryption
import data.aws.s3.versioning
import future.keywords.in

# Test: Public bucket with public-read ACL should be denied
test_deny_public_read_bucket {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-public-bucket",
        "config": {
            "acl": "public-read"
        }
    }
    
    result := public_access.deny with input as input
    count(result) == 1
}

# Test: Private bucket should be allowed
test_allow_private_bucket {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-private-bucket",
        "config": {
            "acl": "private",
            "public_access_block": [{
                "block_public_acls": true,
                "block_public_policy": true,
                "ignore_public_acls": true,
                "restrict_public_buckets": true
            }]
        }
    }
    
    result := public_access.deny with input as input
    count(result) == 0
}

# Test: Bucket without encryption should be denied
test_deny_bucket_without_encryption {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private"
        }
    }
    
    result := encryption.deny with input as input
    count(result) == 1
}

# Test: Bucket with AES256 encryption should be allowed
test_allow_bucket_with_aes256_encryption {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "sse_algorithm": "AES256"
                    }]
                }]
            }]
        }
    }
    
    result := encryption.deny with input as input
    count(result) == 0
}

# Test: Bucket without versioning should be denied
test_deny_bucket_without_versioning {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private"
        }
    }
    
    result := versioning.deny with input as input
    count(result) == 1
}

# Test: Bucket with versioning enabled should be allowed
test_allow_bucket_with_versioning_enabled {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "versioning": [{
                "enabled": true
            }]
        }
    }
    
    result := versioning.deny with input as input
    count(result) == 0
}

# Test: Fully compliant bucket should pass all policies
test_fully_compliant_bucket {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "compliant-bucket",
        "config": {
            "acl": "private",
            "public_access_block": [{
                "block_public_acls": true,
                "block_public_policy": true,
                "ignore_public_acls": true,
                "restrict_public_buckets": true
            }],
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "sse_algorithm": "aws:kms",
                        "kms_master_key_id": "alias/s3-key"
                    }],
                    "bucket_key_enabled": true
                }]
            }],
            "versioning": [{
                "enabled": true
            }]
        }
    }
    
    public_access_result := public_access.deny with input as input
    encryption_result := encryption.deny with input as input
    versioning_result := versioning.deny with input as input
    
    count(public_access_result) == 0
    count(encryption_result) == 0
    count(versioning_result) == 0
}

# Test: Helper function tests
test_has_encryption {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "encrypted-bucket",
        "config": {
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "sse_algorithm": "AES256"
                    }]
                }]
            }]
        }
    }
    
    result := encryption.has_encryption with input as input
    result == true
}

test_has_versioning {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "versioned-bucket",
        "config": {
            "versioning": [{
                "enabled": true
            }]
        }
    }
    
    result := versioning.has_versioning with input as input
    result == true
}