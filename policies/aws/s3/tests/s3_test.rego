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

# -----------------------------------------------------------------------------
# PUBLIC ACCESS POLICY TESTS
# -----------------------------------------------------------------------------

# Test: Public bucket with public-read ACL should be denied
test_deny_public_read_bucket if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-public-bucket",
        "config": {
            "acl": "public-read"
        }
    }
    
    result := public_access.deny with input as input
    count(result) == 1
    contains(result[_], "public ACL")
}

# Test: Public bucket with public-read-write ACL should be denied
test_deny_public_read_write_bucket if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-public-bucket",
        "config": {
            "acl": "public-read-write"
        }
    }
    
    result := public_access.deny with input as input
    count(result) == 1
    contains(result[_], "public ACL")
}

# Test: Private bucket should be allowed
test_allow_private_bucket if {
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

# Test: Bucket without public access block should be denied
test_deny_bucket_without_public_access_block if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private"
        }
    }
    
    result := public_access.deny with input as input
    count(result) == 1
    contains(result[_], "public access block")
}

# Test: Bucket with disabled public access block settings should be denied
test_deny_bucket_with_disabled_public_access_block if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "public_access_block": [{
                "block_public_acls": false,
                "block_public_policy": true,
                "ignore_public_acls": true,
                "restrict_public_buckets": true
            }]
        }
    }
    
    result := public_access.deny with input as input
    count(result) == 1
    contains(result[_], "block_public_acls")
}

# Test: Bucket with public bucket policy should be denied
test_deny_bucket_with_public_policy if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::test-bucket/*\"}]}"
        }
    }
    
    result := public_access.deny with input as input
    count(result) == 1
    contains(result[_], "public access")
}

# -----------------------------------------------------------------------------
# ENCRYPTION POLICY TESTS
# -----------------------------------------------------------------------------

# Test: Bucket without encryption should be denied
test_deny_bucket_without_encryption if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private"
        }
    }
    
    result := encryption.deny with input as input
    count(result) == 1
    contains(result[_], "encryption")
}

# Test: Bucket with AES256 encryption should be allowed
test_allow_bucket_with_aes256_encryption if {
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

# Test: Bucket with KMS encryption should be allowed
test_allow_bucket_with_kms_encryption if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "sse_algorithm": "aws:kms",
                        "kms_master_key_id": "alias/s3-key"
                    }],
                    "bucket_key_enabled": true
                }]
            }]
        }
    }
    
    result := encryption.deny with input as input
    count(result) == 0
}

# Test: Bucket with unsupported encryption algorithm should be denied
test_deny_bucket_with_unsupported_encryption if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "sse_algorithm": "unsupported-algorithm"
                    }]
                }]
            }]
        }
    }
    
    result := encryption.deny with input as input
    count(result) == 1
    contains(result[_], "unsupported encryption algorithm")
}

# Test: KMS encryption without bucket key should generate warning
test_warn_kms_without_bucket_key if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "sse_algorithm": "aws:kms",
                        "kms_master_key_id": "alias/s3-key"
                    }],
                    "bucket_key_enabled": false
                }]
            }]
        }
    }
    
    result := encryption.warn with input as input
    count(result) == 1
    contains(result[_], "bucket key")
}

# -----------------------------------------------------------------------------
# VERSIONING POLICY TESTS
# -----------------------------------------------------------------------------

# Test: Bucket without versioning should be denied
test_deny_bucket_without_versioning if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private"
        }
    }
    
    result := versioning.deny with input as input
    count(result) == 1
    contains(result[_], "versioning")
}

# Test: Bucket with versioning disabled should be denied
test_deny_bucket_with_versioning_disabled if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "versioning": [{
                "enabled": false
            }]
        }
    }
    
    result := versioning.deny with input as input
    count(result) == 1
    contains(result[_], "versioning disabled")
}

# Test: Bucket with versioning enabled should be allowed
test_allow_bucket_with_versioning_enabled if {
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

# Test: Versioned bucket without lifecycle should generate warning
test_warn_versioned_bucket_without_lifecycle if {
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
    
    result := versioning.warn with input as input
    count(result) == 1
    contains(result[_], "lifecycle")
}

# Test: Temporary bucket should be allowed without versioning
test_allow_temporary_bucket_without_versioning if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "temp-bucket",
        "config": {
            "acl": "private",
            "tags": {
                "Purpose": "temporary",
                "TTL": "7d"
            }
        }
    }
    
    result := versioning.allow with input as input
    count(result) == 1
}

# Test: Logging bucket should be allowed without versioning
test_allow_logging_bucket_without_versioning if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "access-logs-bucket",
        "config": {
            "acl": "private",
            "tags": {
                "Purpose": "logging",
                "LogRetention": "90d"
            }
        }
    }
    
    result := versioning.allow with input as input
    count(result) == 1
}

# -----------------------------------------------------------------------------
# INTEGRATION TESTS
# -----------------------------------------------------------------------------

# Test: Fully compliant bucket should pass all policies
test_fully_compliant_bucket if {
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
            }],
            "lifecycle_configuration": [{
                "rule": [{
                    "id": "cleanup-old-versions",
                    "status": "Enabled",
                    "noncurrent_version_expiration": [{
                        "days": 30
                    }]
                }]
            }],
            "tags": {
                "Environment": "production",
                "Owner": "security-team"
            }
        }
    }
    
    public_access_result := public_access.deny with input as input
    encryption_result := encryption.deny with input as input
    versioning_result := versioning.deny with input as input
    
    count(public_access_result) == 0
    count(encryption_result) == 0
    count(versioning_result) == 0
}

# Test: Non-compliant bucket should fail multiple policies
test_non_compliant_bucket if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "non-compliant-bucket",
        "config": {
            "acl": "public-read"
        }
    }
    
    public_access_result := public_access.deny with input as input
    encryption_result := encryption.deny with input as input
    versioning_result := versioning.deny with input as input
    
    count(public_access_result) > 0
    count(encryption_result) > 0
    count(versioning_result) > 0
}

# -----------------------------------------------------------------------------
# HELPER FUNCTION TESTS
# -----------------------------------------------------------------------------

# Test: is_sensitive_bucket helper function
test_is_sensitive_bucket if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "sensitive-data-bucket",
        "config": {
            "tags": {
                "Sensitivity": "high"
            }
        }
    }
    
    result := versioning.is_sensitive_bucket with input as input
    result == true
}

# Test: has_encryption helper function
test_has_encryption if {
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

# Test: has_versioning helper function
test_has_versioning if {
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