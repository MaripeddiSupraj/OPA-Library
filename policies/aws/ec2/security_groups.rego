# =============================================================================
# EC2 Security Groups Policy
# =============================================================================
# Purpose: Ensure EC2 security groups follow security best practices
# Rationale: Security groups are the first line of defense for EC2 instances
#           and should be configured with least privilege principles
# Author: OPA Cloud Security Library
# Version: 1.0.0
# =============================================================================

package aws.ec2.security_groups

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# POLICY: Deny security groups with SSH open to the internet
# -----------------------------------------------------------------------------
# This policy prevents SSH (port 22) from being accessible from anywhere
# on the internet (0.0.0.0/0), which is a common attack vector.

deny[msg] if {
    # Check if the resource is a security group
    input.resource_type == "aws_security_group"
    
    # Check ingress rules for SSH access
    rule := input.config.ingress[_]
    
    # Check if SSH port (22) is open
    rule.from_port <= 22
    rule.to_port >= 22
    
    # Check if accessible from anywhere
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    
    # Generate violation message
    msg := sprintf("Security group '%s' allows SSH (port 22) access from anywhere (0.0.0.0/0). Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.", [
        input.resource_name
    ])
}

# Check for SSH access via IPv6
deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    rule.from_port <= 22
    rule.to_port >= 22
    cidr := rule.ipv6_cidr_blocks[_]
    cidr == "::/0"
    
    msg := sprintf("Security group '%s' allows SSH (port 22) access from anywhere via IPv6 (::/0). Restrict SSH access to specific IP ranges.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Deny security groups with RDP open to the internet
# -----------------------------------------------------------------------------
# This policy prevents RDP (port 3389) from being accessible from anywhere
# on the internet, which is a security risk for Windows instances.

deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    
    # Check if RDP port (3389) is open
    rule.from_port <= 3389
    rule.to_port >= 3389
    
    # Check if accessible from anywhere
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    
    msg := sprintf("Security group '%s' allows RDP (port 3389) access from anywhere (0.0.0.0/0). Restrict RDP access to specific IP ranges or use AWS Systems Manager Session Manager.", [
        input.resource_name
    ])
}

# Check for RDP access via IPv6
deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    rule.from_port <= 3389
    rule.to_port >= 3389
    cidr := rule.ipv6_cidr_blocks[_]
    cidr == "::/0"
    
    msg := sprintf("Security group '%s' allows RDP (port 3389) access from anywhere via IPv6 (::/0). Restrict RDP access to specific IP ranges.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Deny security groups with all ports open to the internet
# -----------------------------------------------------------------------------
# This policy prevents security groups from having rules that open all ports
# to the internet, which is extremely dangerous.

deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    
    # Check if all ports are open (0-65535 or -1 for all)
    rule.from_port == 0
    rule.to_port == 65535
    
    # Check if accessible from anywhere
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    
    msg := sprintf("Security group '%s' allows all ports (0-65535) access from anywhere (0.0.0.0/0). This is extremely dangerous and should be removed immediately.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    
    # Check for protocol -1 (all protocols)
    rule.protocol == "-1"
    
    # Check if accessible from anywhere
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    
    msg := sprintf("Security group '%s' allows all protocols and ports access from anywhere (0.0.0.0/0). This is extremely dangerous and should be removed immediately.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Deny security groups with database ports open to the internet
# -----------------------------------------------------------------------------
# This policy prevents common database ports from being accessible from
# the internet, which could expose sensitive data.

# Common database ports to check
database_ports := [
    3306,  # MySQL
    5432,  # PostgreSQL
    1433,  # SQL Server
    1521,  # Oracle
    27017, # MongoDB
    6379,  # Redis
    11211, # Memcached
    5984,  # CouchDB
    9200,  # Elasticsearch
    8086,  # InfluxDB
]

deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    
    # Check if any database port is open
    db_port := database_ports[_]
    rule.from_port <= db_port
    rule.to_port >= db_port
    
    # Check if accessible from anywhere
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    
    msg := sprintf("Security group '%s' allows database port %d access from anywhere (0.0.0.0/0). Database ports should only be accessible from application servers.", [
        input.resource_name,
        db_port
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Deny security groups with overly broad CIDR ranges
# -----------------------------------------------------------------------------
# This policy warns about CIDR blocks that are too broad and might indicate
# overly permissive access.

warn[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    
    # Check for large CIDR blocks (less than /16)
    cidr := rule.cidr_blocks[_]
    cidr != "0.0.0.0/0"  # Already handled above
    
    # Extract subnet mask
    cidr_parts := split(cidr, "/")
    mask := to_number(cidr_parts[1])
    
    # Warn if subnet mask is too broad
    mask < 16
    
    msg := sprintf("Security group '%s' allows access from a very broad IP range (%s). Consider using more specific IP ranges for better security.", [
        input.resource_name,
        cidr
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require security group descriptions
# -----------------------------------------------------------------------------
# This policy ensures that security groups have meaningful descriptions
# for better documentation and compliance.

deny[msg] if {
    input.resource_type == "aws_security_group"
    
    # Check if description is missing or empty
    not input.config.description
    
    msg := sprintf("Security group '%s' does not have a description. Add a meaningful description to document the purpose of this security group.", [
        input.resource_name
    ])
}

deny[msg] if {
    input.resource_type == "aws_security_group"
    
    # Check if description is too generic
    description := input.config.description
    description in ["default", "Default security group", ""]
    
    msg := sprintf("Security group '%s' has a generic description: '%s'. Provide a meaningful description that explains the purpose and rules.", [
        input.resource_name,
        description
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate egress rules
# -----------------------------------------------------------------------------
# This policy checks egress rules to ensure they follow security best practices.

warn[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.config.egress[_]
    
    # Check for overly permissive egress rules
    rule.protocol == "-1"
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    
    msg := sprintf("Security group '%s' has overly permissive egress rule allowing all traffic to anywhere. Consider restricting egress to specific destinations.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Check for unused security groups
# -----------------------------------------------------------------------------
# This policy identifies security groups that might be unused and should
# be reviewed or removed.

# Note: This check requires additional context about EC2 instances
# In a real implementation, you would cross-reference with instance data
warn[msg] if {
    input.resource_type == "aws_security_group"
    
    # Check if security group has no ingress or egress rules
    count(input.config.ingress) == 0
    count(input.config.egress) == 0
    
    msg := sprintf("Security group '%s' has no ingress or egress rules. Review if this security group is still needed.", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Validate security group naming
# -----------------------------------------------------------------------------
# This policy ensures security groups follow naming conventions.

deny[msg] if {
    input.resource_type == "aws_security_group"
    
    # Check if name is too generic
    name := input.resource_name
    name in ["default", "sg-default", "test", "temp"]
    
    msg := sprintf("Security group '%s' uses a generic name. Use descriptive names that indicate the purpose and environment.", [
        input.resource_name
    ])
}

warn[msg] if {
    input.resource_type == "aws_security_group"
    
    # Check if name doesn't follow convention (example: env-purpose-sg)
    name := input.resource_name
    not contains(name, "-")
    
    msg := sprintf("Security group '%s' doesn't follow naming conventions. Consider using format: environment-purpose-sg", [
        input.resource_name
    ])
}

# -----------------------------------------------------------------------------
# POLICY: Require tags for security groups
# -----------------------------------------------------------------------------
# This policy ensures security groups have proper tags for management.

deny[msg] if {
    input.resource_type == "aws_security_group"
    
    # Check if tags are missing
    not input.config.tags
    
    msg := sprintf("Security group '%s' does not have any tags. Add tags for Environment, Owner, and Purpose for better resource management.", [
        input.resource_name
    ])
}

# Required tags for security groups
required_sg_tags := ["Environment", "Owner", "Purpose"]

deny[msg] if {
    input.resource_type == "aws_security_group"
    
    # Check if required tags are missing
    existing_tags := object.keys(input.config.tags)
    missing_tags := [tag | tag := required_sg_tags[_]; not tag in existing_tags]
    count(missing_tags) > 0
    
    msg := sprintf("Security group '%s' is missing required tags: %v. Add these tags for compliance and resource management.", [
        input.resource_name,
        missing_tags
    ])
}

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

# Check if a port is a database port
is_database_port(port) if {
    port in database_ports
}

# Check if CIDR is overly broad
is_overly_broad_cidr(cidr) if {
    cidr != "0.0.0.0/0"
    cidr_parts := split(cidr, "/")
    mask := to_number(cidr_parts[1])
    mask < 16
}

# Check if security group allows internet access
allows_internet_access if {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    cidr := rule.cidr_blocks[_]
    cidr in ["0.0.0.0/0", "::/0"]
}

# Check if security group has proper description
has_proper_description if {
    input.resource_type == "aws_security_group"
    description := input.config.description
    description != ""
    not description in ["default", "Default security group"]
    count(description) > 10  # Reasonable length
}

# Get all open ports for a security group
get_open_ports := ports if {
    input.resource_type == "aws_security_group"
    ports := [port | 
        rule := input.config.ingress[_]
        cidr := rule.cidr_blocks[_]
        cidr == "0.0.0.0/0"
        port := rule.from_port
    ]
}

# -----------------------------------------------------------------------------
# INFORMATIONAL RULES
# -----------------------------------------------------------------------------
# These rules provide information about security group configuration

info[msg] if {
    input.resource_type == "aws_security_group"
    count(input.config.ingress) > 0
    not allows_internet_access
    
    msg := sprintf("Security group '%s' has %d ingress rules with no internet access - good security posture.", [
        input.resource_name,
        count(input.config.ingress)
    ])
}

info[msg] if {
    input.resource_type == "aws_security_group"
    has_proper_description
    
    msg := sprintf("Security group '%s' has a proper description: '%s'", [
        input.resource_name,
        input.config.description
    ])
}