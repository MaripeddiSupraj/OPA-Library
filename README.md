# OPA Cloud Security Library

A comprehensive collection of Open Policy Agent (OPA) policies for securing cloud infrastructure on AWS and GCP.

## Table of Contents

1. [What is Open Policy Agent (OPA)?](#what-is-open-policy-agent-opa)
2. [Why Use OPA for Cloud Security?](#why-use-opa-for-cloud-security)
3. [Quick Start Examples](#quick-start-examples)
4. [Industry Best Practices](#industry-best-practices)
5. [CI/CD Integration](#cicd-integration)
6. [AWS Policies](#aws-policies)
7. [GCP Policies (Coming Soon)](#gcp-policies-coming-soon)
8. [Contributing](#contributing)
9. [License](#license)

## What is Open Policy Agent (OPA)?

Open Policy Agent (OPA) is an open-source, general-purpose policy engine that enables unified, context-aware policy enforcement across your entire stack. OPA provides a high-level declarative language (Rego) that lets you specify policy as code and simple APIs to offload policy decision-making from your software.

### Key Benefits:
- **Policy as Code**: Version control, test, and deploy policies like any other code
- **Unified Policy Language**: One language (Rego) for all your policy needs
- **Decoupled Architecture**: Separate policy logic from application logic
- **Rich Context**: Make decisions based on rich context and external data
- **Performance**: Fast policy evaluation with in-memory decision making

### Basic Example:

```rego
# Example: Deny public S3 buckets
package aws.s3.public_access

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.config.acl == "public-read"
    msg := "S3 bucket should not have public-read ACL"
}
```

## Why Use OPA for Cloud Security?

Modern cloud environments are complex, with hundreds of resources and configurations that need to comply with security policies. Traditional approaches often lead to:

- **Inconsistent Policy Enforcement**: Different tools with different policy languages
- **Late Detection**: Finding issues in production rather than during development
- **Manual Processes**: Time-consuming manual reviews and approvals
- **Compliance Gaps**: Difficulty proving compliance across environments

OPA solves these challenges by providing:

### 1. **Shift-Left Security**
Catch policy violations early in the development cycle:
```bash
# During Terraform planning
terraform plan -out=plan.json
opa eval -d policies/ -i plan.json "data.terraform.deny[x]"
```

### 2. **Consistent Policy Across Environments**
Same policies work across development, staging, and production:
```rego
# Works for both live resources and Infrastructure as Code
package aws.ec2.security_groups

deny[msg] {
    input.resource_type == "aws_security_group"
    rule := input.config.ingress[_]
    rule.from_port == 22
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg := "SSH should not be open to the internet"
}
```

### 3. **Automated Compliance**
Automatically verify compliance without manual intervention:
```yaml
# GitHub Actions example
- name: OPA Policy Check
  run: |
    opa fmt --diff policies/
    opa test policies/
    conftest verify --policy policies/ terraform-plan.json
```

## Quick Start Examples

### Example 1: S3 Bucket Security
```rego
package aws.s3.security

import future.keywords.if
import future.keywords.in

# Deny S3 buckets with public read access
deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    input.config.acl in ["public-read", "public-read-write"]
    msg := sprintf("S3 bucket '%s' should not have public ACL: %s", [
        input.resource_name,
        input.config.acl
    ])
}

# Require versioning for S3 buckets
deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    not input.config.versioning[_].enabled
    msg := sprintf("S3 bucket '%s' must have versioning enabled", [input.resource_name])
}

# Require encryption at rest
deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    not input.config.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%s' must have encryption at rest enabled", [input.resource_name])
}
```

### Example 2: EC2 Instance Security
```rego
package aws.ec2.security

import future.keywords.if
import future.keywords.in

# Deny instances without proper tags
required_tags := ["Environment", "Owner", "Project"]

deny[msg] if {
    input.resource_type == "aws_instance"
    missing_tags := required_tags - object.keys(input.config.tags)
    count(missing_tags) > 0
    msg := sprintf("EC2 instance '%s' missing required tags: %v", [
        input.resource_name,
        missing_tags
    ])
}

# Require instances to use approved AMIs
approved_ami_pattern := "ami-amazon-linux-*"

deny[msg] if {
    input.resource_type == "aws_instance"
    not regex.match(approved_ami_pattern, input.config.ami)
    msg := sprintf("EC2 instance '%s' must use approved AMI pattern: %s", [
        input.resource_name,
        approved_ami_pattern
    ])
}
```

## Industry Best Practices

### 1. **Policy Organization**

Structure your policies with clear separation of concerns:

```
policies/
├── aws/
│   ├── s3/
│   │   ├── public_access.rego
│   │   ├── encryption.rego
│   │   └── versioning.rego
│   ├── ec2/
│   │   ├── security_groups.rego
│   │   ├── instance_compliance.rego
│   │   └── ebs_encryption.rego
│   └── iam/
│       ├── user_policies.rego
│       └── role_policies.rego
├── gcp/
│   └── (coming soon)
└── common/
    ├── tagging.rego
    └── naming_conventions.rego
```

### 2. **Testing Strategy**

Always include comprehensive tests:

```rego
package aws.s3.security_test

import data.aws.s3.security

# Test: Public bucket should be denied
test_deny_public_bucket if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {"acl": "public-read"}
    }
    count(security.deny) == 1
}

# Test: Private bucket should be allowed
test_allow_private_bucket if {
    input := {
        "resource_type": "aws_s3_bucket",
        "resource_name": "test-bucket",
        "config": {
            "acl": "private",
            "versioning": [{"enabled": true}],
            "server_side_encryption_configuration": [{}]
        }
    }
    count(security.deny) == 0
}
```

### 3. **Documentation Standards**

Each policy should include:
- **Purpose**: What the policy enforces
- **Rationale**: Why this policy is important
- **Examples**: Valid and invalid configurations
- **Exceptions**: When the policy might not apply

### 4. **Gradual Rollout**

Implement policies with a phased approach:

1. **Warn Mode**: Log violations without blocking
2. **Enforce for New Resources**: Block new violations
3. **Full Enforcement**: Block all violations

```rego
package aws.s3.security

import future.keywords.if

# Configuration for gradual rollout
enforcement_mode := "warn"  # "warn", "enforce_new", "enforce_all"

violation[msg] if {
    # Policy logic here
    msg := "Policy violation detected"
}

# In warn mode, just log violations
warn[msg] if {
    enforcement_mode == "warn"
    msg := violation[_]
}

# In enforce mode, deny violations
deny[msg] if {
    enforcement_mode in ["enforce_new", "enforce_all"]
    msg := violation[_]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Policy Validation

on:
  pull_request:
    paths: ['infrastructure/**', 'policies/**']

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup OPA
        uses: open-policy-agent/setup-opa@v2
        with:
          version: latest
          
      - name: Install Conftest
        run: |
          wget https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_Linux_x86_64.tar.gz
          tar xzf conftest_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin
          
      - name: Validate Policies
        run: |
          # Format check
          opa fmt --list policies/
          
          # Run policy tests
          opa test policies/
          
      - name: Terraform Plan
        run: |
          cd infrastructure
          terraform init
          terraform plan -out=plan.tfplan
          terraform show -json plan.tfplan > plan.json
          
      - name: Policy Evaluation
        run: |
          conftest verify --policy policies/ infrastructure/plan.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Policy Validation') {
            steps {
                script {
                    // Install OPA and Conftest
                    sh '''
                        wget -O opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
                        chmod +x opa
                        sudo mv opa /usr/local/bin/
                        
                        wget https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_Linux_x86_64.tar.gz
                        tar xzf conftest_Linux_x86_64.tar.gz
                        sudo mv conftest /usr/local/bin
                    '''
                    
                    // Validate policies
                    sh '''
                        opa fmt --list policies/
                        opa test policies/
                    '''
                }
            }
        }
        
        stage('Infrastructure Plan') {
            steps {
                dir('infrastructure') {
                    sh '''
                        terraform init
                        terraform plan -out=plan.tfplan
                        terraform show -json plan.tfplan > plan.json
                    '''
                }
            }
        }
        
        stage('Policy Check') {
            steps {
                sh 'conftest verify --policy policies/ infrastructure/plan.json'
            }
        }
    }
}
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/open-policy-agent/conftest
    rev: v0.46.0
    hooks:
      - id: conftest-fmt
      - id: conftest-verify
        files: \.(json|yaml|yml)$
        args: ['--policy', 'policies/']
        
  - repo: local
    hooks:
      - id: opa-test
        name: OPA Test
        entry: opa test
        language: system
        files: \.rego$
        args: ['policies/']
```

## AWS Policies

This library includes comprehensive policies for AWS services:

### Core Services
- **[S3](./policies/aws/s3/)**: Bucket security, encryption, access controls
- **[EC2](./policies/aws/ec2/)**: Instance compliance, security groups, EBS encryption
- **[IAM](./policies/aws/iam/)**: User and role policies, privilege escalation prevention
- **[VPC](./policies/aws/vpc/)**: Network security, subnet configurations
- **[RDS](./policies/aws/rds/)**: Database security, encryption, backup policies

### Security Services
- **[CloudTrail](./policies/aws/cloudtrail/)**: Logging and monitoring compliance
- **[Config](./policies/aws/config/)**: Configuration compliance rules
- **[GuardDuty](./policies/aws/guardduty/)**: Threat detection policies
- **[Security Hub](./policies/aws/security-hub/)**: Security standards compliance

### Compute Services
- **[Lambda](./policies/aws/lambda/)**: Function security and configuration
- **[ECS](./policies/aws/ecs/)**: Container security policies
- **[EKS](./policies/aws/eks/)**: Kubernetes cluster security

## GCP Policies (Coming Soon)

We're actively working on comprehensive GCP policies covering:
- Compute Engine
- Cloud Storage
- Cloud SQL
- GKE
- IAM
- VPC

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Steps:
1. Fork the repository
2. Create a feature branch
3. Add your policy with tests
4. Run the test suite
5. Submit a pull request

### Policy Guidelines:
- Include comprehensive comments
- Add test cases for all scenarios
- Follow our naming conventions
- Include documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Star this repository** if you find it useful! 🌟

For questions or support, please open an issue or reach out to the maintainers.
