# Cloud Integration Guide

This guide provides comprehensive instructions for integrating CloudSentinel with AWS, Azure, and Google Cloud Platform to enable automated security scanning and monitoring.

## Table of Contents

1. [AWS Integration](#aws-integration)
2. [Azure Integration](#azure-integration)
3. [Google Cloud Platform Integration](#gcp-integration)
4. [Multi-Cloud Setup](#multi-cloud-setup)
5. [Permissions and Policies](#permissions-and-policies)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

## AWS Integration

### Prerequisites

- AWS Account with appropriate permissions
- AWS CLI installed and configured (optional)
- CloudSentinel deployed and running

### Setup Methods

#### Method 1: IAM User with Access Keys

1. **Create IAM User**
   ```bash
   aws iam create-user --user-name cloudsentinel-scanner
   ```

2. **Attach Security Audit Policy**
   ```bash
   aws iam attach-user-policy \
     --user-name cloudsentinel-scanner \
     --policy-arn arn:aws:iam::aws:policy/SecurityAudit
   ```

3. **Create Access Keys**
   ```bash
   aws iam create-access-key --user-name cloudsentinel-scanner
   ```

4. **Configure in CloudSentinel**
   - Navigate to Settings > Cloud Providers
   - Add AWS configuration:
     ```json
     {
       "provider": "aws",
       "access_key_id": "AKIAIOSFODNN7EXAMPLE",
       "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
       "region": "us-east-1"
     }
     ```

#### Method 2: IAM Role with Cross-Account Access

1. **Create Trust Policy**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::CLOUDSENTINEL-ACCOUNT:root"
         },
         "Action": "sts:AssumeRole",
         "Condition": {
           "StringEquals": {
             "sts:ExternalId": "unique-external-id"
           }
         }
       }
     ]
   }
   ```

2. **Create IAM Role**
   ```bash
   aws iam create-role \
     --role-name CloudSentinelScannerRole \
     --assume-role-policy-document file://trust-policy.json
   ```

3. **Attach Security Audit Policy**
   ```bash
   aws iam attach-role-policy \
     --role-name CloudSentinelScannerRole \
     --policy-arn arn:aws:iam::aws:policy/SecurityAudit
   ```

#### Method 3: AWS Organization Integration

For multi-account AWS Organizations:

1. **Create Organizational Unit**
2. **Deploy StackSet for Role Creation**
3. **Configure Cross-Account Access**

### Required Permissions

CloudSentinel requires read-only access to scan AWS resources:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:GetBucket*",
        "s3:GetObject*",
        "s3:List*",
        "iam:Get*",
        "iam:List*",
        "rds:Describe*",
        "lambda:Get*",
        "lambda:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "config:Describe*",
        "config:Get*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "vpc:Describe*",
        "sns:Get*",
        "sns:List*",
        "sqs:Get*",
        "sqs:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Services Scanned

CloudSentinel scans the following AWS services:

- **Compute**: EC2, Lambda, ECS, EKS
- **Storage**: S3, EBS, EFS
- **Database**: RDS, DynamoDB, ElastiCache
- **Network**: VPC, Security Groups, NACLs, Load Balancers
- **IAM**: Users, Roles, Policies, Access Keys
- **Security**: CloudTrail, Config, GuardDuty, SecurityHub
- **Monitoring**: CloudWatch, CloudWatch Logs

## Azure Integration

### Prerequisites

- Azure Subscription
- Azure CLI installed (optional)
- Service Principal or Managed Identity

### Setup Methods

#### Method 1: Service Principal

1. **Create Service Principal**
   ```bash
   az ad sp create-for-rbac \
     --name "CloudSentinel-Scanner" \
     --role "Security Reader" \
     --scopes "/subscriptions/{subscription-id}"
   ```

2. **Note the Output**
   ```json
   {
     "appId": "12345678-1234-1234-1234-123456789012",
     "displayName": "CloudSentinel-Scanner",
     "name": "http://CloudSentinel-Scanner",
     "password": "random-password",
     "tenant": "87654321-4321-4321-4321-210987654321"
   }
   ```

3. **Configure in CloudSentinel**
   ```json
   {
     "provider": "azure",
     "subscription_id": "your-subscription-id",
     "tenant_id": "87654321-4321-4321-4321-210987654321",
     "client_id": "12345678-1234-1234-1234-123456789012",
     "client_secret": "random-password"
   }
   ```

#### Method 2: Managed Identity

For CloudSentinel running on Azure:

1. **Enable System-Assigned Managed Identity**
2. **Assign Security Reader Role**
3. **Configure Environment Variables**

### Required Permissions

CloudSentinel requires the following Azure roles:

- **Security Reader**: Read security-related information
- **Reader**: Read all resources in subscription
- **Monitoring Reader**: Read monitoring data

### Services Scanned

- **Compute**: Virtual Machines, App Service, Container Instances
- **Storage**: Storage Accounts, Blob Storage, File Storage
- **Database**: SQL Database, Cosmos DB, PostgreSQL
- **Network**: Virtual Networks, Network Security Groups, Load Balancers
- **Identity**: Azure Active Directory, Key Vault
- **Security**: Security Center, Defender for Cloud
- **Monitoring**: Monitor, Log Analytics

## Google Cloud Platform Integration

### Prerequisites

- GCP Project with billing enabled
- gcloud CLI installed (optional)
- Service Account with appropriate permissions

### Setup Methods

#### Method 1: Service Account Key

1. **Create Service Account**
   ```bash
   gcloud iam service-accounts create cloudsentinel-scanner \
     --display-name="CloudSentinel Scanner"
   ```

2. **Grant Permissions**
   ```bash
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member="serviceAccount:cloudsentinel-scanner@PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/security.securityReviewer"
   
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member="serviceAccount:cloudsentinel-scanner@PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/viewer"
   ```

3. **Create and Download Key**
   ```bash
   gcloud iam service-accounts keys create cloudsentinel-key.json \
     --iam-account=cloudsentinel-scanner@PROJECT_ID.iam.gserviceaccount.com
   ```

4. **Configure in CloudSentinel**
   ```json
   {
     "provider": "gcp",
     "project_id": "your-project-id",
     "service_account_path": "/path/to/cloudsentinel-key.json"
   }
   ```

#### Method 2: Workload Identity (for GKE)

1. **Create Kubernetes Service Account**
2. **Bind to Google Service Account**
3. **Configure Pod Annotations**

### Required Permissions

```yaml
roles:
  - roles/security.securityReviewer
  - roles/viewer
  - roles/compute.viewer
  - roles/storage.objectViewer
  - roles/iam.securityReviewer
```

### Services Scanned

- **Compute**: Compute Engine, App Engine, Cloud Functions
- **Storage**: Cloud Storage, Persistent Disks
- **Database**: Cloud SQL, Firestore, BigQuery
- **Network**: VPC, Firewall Rules, Load Balancers
- **IAM**: Service Accounts, IAM Policies
- **Security**: Security Command Center, Binary Authorization
- **Monitoring**: Cloud Monitoring, Cloud Logging

## Multi-Cloud Setup

### Configuration Example

```json
{
  "cloud_providers": [
    {
      "name": "aws-production",
      "provider": "aws",
      "config": {
        "access_key_id": "...",
        "secret_access_key": "...",
        "region": "us-east-1"
      },
      "scan_schedule": "0 2 * * *",
      "enabled": true
    },
    {
      "name": "azure-development",
      "provider": "azure",
      "config": {
        "subscription_id": "...",
        "tenant_id": "...",
        "client_id": "...",
        "client_secret": "..."
      },
      "scan_schedule": "0 3 * * *",
      "enabled": true
    },
    {
      "name": "gcp-staging",
      "provider": "gcp",
      "config": {
        "project_id": "...",
        "service_account_path": "/path/to/key.json"
      },
      "scan_schedule": "0 4 * * *",
      "enabled": true
    }
  ]
}
```

### Unified Dashboard

CloudSentinel provides a unified view across all cloud providers:

- **Risk Score Aggregation**
- **Cross-Cloud Compliance Reporting**
- **Unified Alert Management**
- **Centralized Remediation Tracking**

## Permissions and Policies

### Security Considerations

1. **Principle of Least Privilege**: Grant only necessary permissions
2. **Regular Rotation**: Rotate access keys and secrets regularly
3. **Monitoring**: Monitor API usage and access patterns
4. **Encryption**: Encrypt credentials at rest and in transit

### AWS IAM Policy Template

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudSentinelSecurityAudit",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:List*",
        "account:Get*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "ec2:Describe*",
        "guardduty:Get*",
        "guardduty:List*",
        "iam:Generate*",
        "iam:Get*",
        "iam:List*",
        "iam:Simulate*",
        "inspector:Describe*",
        "inspector:Get*",
        "inspector:List*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "lambda:Get*",
        "lambda:List*",
        "logs:Describe*",
        "organizations:Describe*",
        "organizations:List*",
        "rds:Describe*",
        "s3:GetBucket*",
        "s3:GetObject*",
        "s3:List*",
        "securityhub:Describe*",
        "securityhub:Get*",
        "securityhub:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:Get*",
        "sqs:List*",
        "ssm:Describe*",
        "ssm:Get*",
        "ssm:List*",
        "sts:Get*",
        "support:Describe*",
        "trustedadvisor:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
```

## Troubleshooting

### Common Issues

#### AWS Integration Issues

1. **Access Denied Errors**
   - Verify IAM permissions
   - Check policy attachments
   - Validate region restrictions

2. **Rate Limiting**
   - Implement exponential backoff
   - Use multiple regions
   - Consider AWS Organizations limits

3. **MFA Requirements**
   - Use assume role with MFA
   - Implement session tokens
   - Configure temporary credentials

#### Azure Integration Issues

1. **Authentication Failures**
   - Verify service principal credentials
   - Check tenant ID and subscription ID
   - Validate Azure AD permissions

2. **Insufficient Permissions**
   - Assign Security Reader role
   - Grant Resource Group access
   - Enable required APIs

3. **Network Restrictions**
   - Configure firewall rules
   - Allow CloudSentinel IP ranges
   - Check NSG configurations

#### GCP Integration Issues

1. **Service Account Issues**
   - Verify key file format
   - Check service account permissions
   - Validate project ID

2. **API Enablement**
   - Enable required GCP APIs
   - Check quota limits
   - Verify billing account

3. **Network Access**
   - Configure VPC firewall rules
   - Check IAP settings
   - Validate private Google access

### Debugging Steps

1. **Enable Debug Logging**
   ```bash
   export LOG_LEVEL=DEBUG
   ```

2. **Test Credentials**
   ```bash
   # AWS
   aws sts get-caller-identity
   
   # Azure
   az account show
   
   # GCP
   gcloud auth list
   ```

3. **Validate Permissions**
   ```bash
   # Run permission test scans
   python test_cloud_permissions.py
   ```

## Best Practices

### Security Best Practices

1. **Credential Management**
   - Use cloud-native secret managers
   - Rotate credentials regularly
   - Monitor credential usage

2. **Network Security**
   - Use private endpoints when available
   - Implement IP whitelisting
   - Enable encryption in transit

3. **Access Control**
   - Implement role-based access
   - Use temporary credentials
   - Enable audit logging

### Operational Best Practices

1. **Monitoring**
   - Set up alerting for scan failures
   - Monitor API rate limits
   - Track cost implications

2. **Scaling**
   - Use parallel scanning
   - Implement queue management
   - Configure auto-scaling

3. **Maintenance**
   - Regular permission reviews
   - Update scanning policies
   - Archive old scan data

### Cost Optimization

1. **API Usage**
   - Cache scan results
   - Use incremental scanning
   - Optimize API calls

2. **Resource Management**
   - Clean up temporary resources
   - Use spot instances where applicable
   - Implement cost budgets

3. **Scheduling**
   - Run scans during off-peak hours
   - Use different schedules per environment
   - Implement scan prioritization

## Support and Resources

### Documentation Links

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Azure RBAC Documentation](https://docs.microsoft.com/en-us/azure/role-based-access-control/)
- [GCP IAM Documentation](https://cloud.google.com/iam/docs)

### Community Resources

- CloudSentinel GitHub Repository
- Community Forum
- Security Compliance Guides

### Professional Support

For enterprise support and custom integrations:
- Email: support@cloudsentinel.com
- Documentation: docs.cloudsentinel.com
- Status Page: status.cloudsentinel.com
