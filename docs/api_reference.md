# CloudSentinel API Reference

## Base URL
```
Production: https://cloudsentinel.yourdomain.com/api/v1
Development: http://localhost:8000/api/v1
```

## Authentication

All API endpoints (except authentication endpoints) require a valid JWT token in the Authorization header:

```http
Authorization: Bearer <your-jwt-token>
```

### Obtaining a Token

**POST /auth/token**

Request:
```json
{
    "username": "user@example.com",
    "password": "your-password"
}
```

Response:
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "bearer",
    "expires_in": 3600,
    "user_id": 1,
    "role": "admin"
}
```

## Authentication Endpoints

### Register User
**POST /auth/register**

Create a new user account.

Request:
```json
{
    "email": "user@example.com",
    "username": "username",
    "password": "secure-password",
    "full_name": "Full Name",
    "role": "viewer"
}
```

Response:
```json
{
    "id": 1,
    "email": "user@example.com",
    "username": "username",
    "full_name": "Full Name",
    "role": "viewer",
    "is_active": true,
    "created_at": "2024-01-01T12:00:00Z"
}
```

### Get Current User
**GET /auth/me**

Get information about the currently authenticated user.

Response:
```json
{
    "id": 1,
    "email": "user@example.com",
    "username": "username",
    "full_name": "Full Name",
    "role": "admin",
    "is_active": true,
    "created_at": "2024-01-01T12:00:00Z",
    "last_login": "2024-01-15T10:30:00Z"
}
```

### Validate Token
**GET /auth/validate**

Validate the current authentication token.

Response:
```json
{
    "valid": true,
    "user_id": 1,
    "email": "user@example.com",
    "role": "admin",
    "expires_at": "2024-01-15T15:30:00Z"
}
```

## Scanning Endpoints

### Get Scans
**GET /scan/scans**

Retrieve a list of scans with optional filtering.

Query Parameters:
- `skip` (int): Number of records to skip (default: 0)
- `limit` (int): Maximum number of records to return (default: 100)
- `status` (string): Filter by scan status (running, completed, failed)
- `cloud_provider` (string): Filter by cloud provider (aws, azure, gcp)

Response:
```json
{
    "items": [
        {
            "id": "scan-123",
            "cloud_provider": "aws",
            "status": "completed",
            "created_at": "2024-01-15T10:00:00Z",
            "completed_at": "2024-01-15T10:15:00Z",
            "total_resources": 1250,
            "findings_count": 45,
            "critical_findings": 3,
            "high_findings": 12,
            "region": "us-east-1"
        }
    ],
    "total": 1,
    "skip": 0,
    "limit": 100
}
```

### Start Scan
**POST /scan/start**

Initiate a new security scan.

Request:
```json
{
    "cloud_provider": "aws",
    "credentials": {
        "access_key_id": "AKIA...",
        "secret_access_key": "secret...",
        "region": "us-east-1",
        "session_token": "optional-session-token"
    },
    "scan_config": {
        "services": ["s3", "iam", "ec2", "vpc"],
        "regions": ["us-east-1", "us-west-2"],
        "deep_scan": false,
        "compliance_frameworks": ["cis", "nist"]
    }
}
```

Response:
```json
{
    "scan_id": "scan-456",
    "status": "initiated",
    "message": "Scan initiated successfully",
    "estimated_duration": "15-20 minutes",
    "services_to_scan": ["s3", "iam", "ec2", "vpc"]
}
```

### Get Scan Status
**GET /scan/status/{scan_id}**

Get the current status of a specific scan.

Response:
```json
{
    "scan_id": "scan-456",
    "status": "running",
    "progress": 65,
    "current_service": "s3",
    "services_completed": ["iam", "ec2"],
    "services_remaining": ["vpc", "cloudtrail"],
    "findings_so_far": 23,
    "started_at": "2024-01-15T14:00:00Z",
    "estimated_completion": "2024-01-15T14:20:00Z"
}
```

### Get Scan Results
**GET /scan/results/{scan_id}**

Retrieve detailed results from a completed scan.

Query Parameters:
- `severity` (string): Filter by severity (critical, high, medium, low)
- `service` (string): Filter by cloud service
- `skip` (int): Pagination offset
- `limit` (int): Results per page

Response:
```json
{
    "scan_id": "scan-456",
    "scan_summary": {
        "total_resources": 1250,
        "total_findings": 45,
        "by_severity": {
            "critical": 3,
            "high": 12,
            "medium": 18,
            "low": 12
        },
        "by_service": {
            "s3": 15,
            "iam": 20,
            "ec2": 8,
            "vpc": 2
        }
    },
    "findings": [
        {
            "finding_id": "aws-s3-001",
            "severity": "critical",
            "title": "Public S3 Bucket Detected",
            "description": "S3 bucket 'company-data' allows public read access",
            "resource_id": "company-data",
            "resource_type": "s3_bucket",
            "service": "s3",
            "region": "us-east-1",
            "risk_score": 9.2,
            "compliance_violations": ["CIS-2.1.1", "NIST-SC-13"],
            "remediation": {
                "steps": [
                    "Review bucket policy and ACLs",
                    "Remove public access permissions",
                    "Enable bucket-level public access block"
                ],
                "priority": "immediate",
                "estimated_effort": "15 minutes"
            },
            "evidence": {
                "bucket_policy": {...},
                "bucket_acl": {...}
            }
        }
    ],
    "total": 45,
    "skip": 0,
    "limit": 10
}
```

### Get Supported Cloud Providers
**GET /scan/providers**

Get information about supported cloud providers and their services.

Response:
```json
{
    "aws": {
        "name": "Amazon Web Services",
        "services": ["s3", "iam", "ec2", "vpc", "rds", "cloudtrail", "kms"],
        "regions": ["us-east-1", "us-west-2", "eu-west-1", "..."],
        "credential_types": ["access_key", "role_arn", "instance_profile"]
    },
    "azure": {
        "name": "Microsoft Azure",
        "services": ["storage", "identity", "compute", "network", "keyvault"],
        "regions": ["East US", "West US 2", "West Europe", "..."],
        "credential_types": ["service_principal", "managed_identity"]
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "services": ["storage", "iam", "compute", "network", "kms"],
        "regions": ["us-central1", "us-east1", "europe-west1", "..."],
        "credential_types": ["service_account_key", "application_default"]
    }
}
```

## Alert Endpoints

### Get Alerts
**GET /alerts/**

Retrieve security alerts with filtering and pagination.

Query Parameters:
- `severity` (string): Filter by severity
- `status` (string): Filter by status (open, acknowledged, resolved, suppressed)
- `service` (string): Filter by cloud service
- `skip` (int): Pagination offset
- `limit` (int): Results per page

Response:
```json
{
    "items": [
        {
            "id": 1,
            "title": "Critical S3 Bucket Exposure",
            "description": "S3 bucket with public read access contains sensitive data",
            "severity": "critical",
            "status": "open",
            "resource_id": "sensitive-data-bucket",
            "service": "s3",
            "cloud_provider": "aws",
            "region": "us-east-1",
            "risk_score": 9.5,
            "created_at": "2024-01-15T14:30:00Z",
            "scan_id": "scan-456",
            "finding_id": "aws-s3-001",
            "compliance_violations": ["CIS-2.1.1"]
        }
    ],
    "total": 25,
    "skip": 0,
    "limit": 10
}
```

### Update Alert Status
**PATCH /alerts/{alert_id}/status**

Update the status of a specific alert.

Request:
```json
{
    "status": "acknowledged",
    "notes": "Investigating with security team"
}
```

Response:
```json
{
    "id": 1,
    "status": "acknowledged",
    "acknowledged_at": "2024-01-15T15:00:00Z",
    "acknowledged_by": 1,
    "notes": "Investigating with security team"
}
```

### Bulk Update Alerts
**PATCH /alerts/bulk**

Update multiple alerts at once.

Request:
```json
{
    "alert_ids": [1, 2, 3],
    "updates": {
        "status": "acknowledged",
        "notes": "Bulk acknowledged for review"
    }
}
```

Response:
```json
{
    "updated_count": 3,
    "message": "Successfully updated 3 alerts"
}
```

### Get Alert Statistics
**GET /alerts/stats**

Get aggregated statistics about alerts.

Response:
```json
{
    "total_alerts": 125,
    "by_severity": {
        "critical": 8,
        "high": 25,
        "medium": 52,
        "low": 40
    },
    "by_status": {
        "open": 85,
        "acknowledged": 25,
        "resolved": 15
    },
    "by_service": {
        "s3": 35,
        "iam": 45,
        "ec2": 30,
        "vpc": 15
    },
    "trends": {
        "new_today": 5,
        "resolved_today": 8,
        "weekly_trend": -12
    }
}
```

## Reports Endpoints

### Dashboard Statistics
**GET /reports/dashboard**

Get high-level statistics for the main dashboard.

Response:
```json
{
    "total_scans": 156,
    "active_alerts": 85,
    "risk_score": 6.8,
    "resources_monitored": 12500,
    "recent_scans": [
        {
            "id": "scan-456",
            "cloud_provider": "aws",
            "completed_at": "2024-01-15T14:15:00Z",
            "findings": 45,
            "risk_score": 7.2
        }
    ],
    "alert_trends": [
        {"date": "2024-01-15", "count": 12},
        {"date": "2024-01-14", "count": 8}
    ],
    "compliance_summary": {
        "cis": 85.5,
        "nist": 78.2,
        "iso27001": 92.1
    }
}
```

### Security Score
**GET /reports/security-score**

Get detailed security posture scoring.

Response:
```json
{
    "overall_score": 6.8,
    "score_trend": "improving",
    "by_provider": {
        "aws": {
            "score": 7.2,
            "trend": "stable",
            "last_scan": "2024-01-15T14:15:00Z"
        },
        "azure": {
            "score": 6.1,
            "trend": "declining",
            "last_scan": "2024-01-15T12:30:00Z"
        }
    },
    "trends": [
        {"date": "2024-01-15", "score": 6.8},
        {"date": "2024-01-14", "score": 6.5}
    ],
    "improvement_areas": [
        {
            "category": "IAM Policies",
            "current_score": 5.2,
            "potential_improvement": 2.1
        }
    ]
}
```

### Compliance Report
**GET /reports/compliance**

Get compliance status for specific frameworks.

Query Parameters:
- `framework` (string): Compliance framework (cis, nist, iso27001, soc2)
- `cloud_provider` (string): Filter by provider

Response:
```json
{
    "framework": "cis",
    "compliance_percentage": 85.5,
    "total_controls": 200,
    "passed_controls": 171,
    "failed_controls": 29,
    "controls": [
        {
            "control_id": "CIS-1.1",
            "title": "Maintain Inventory of Authorized Devices",
            "status": "passed",
            "evidence": "Automated inventory system in place"
        },
        {
            "control_id": "CIS-2.1.1",
            "title": "Ensure S3 buckets are not publicly readable",
            "status": "failed",
            "findings_count": 3,
            "affected_resources": ["bucket-1", "bucket-2", "bucket-3"]
        }
    ]
}
```

### Export Report
**GET /reports/export**

Export reports in various formats.

Query Parameters:
- `format` (string): Export format (json, csv, pdf, xlsx)
- `report_type` (string): Type of report (vulnerabilities, alerts, compliance)
- `filters` (object): Additional filters

Response:
- For CSV/XLSX: Returns file download
- For JSON: Returns structured data
- For PDF: Returns binary PDF file

## Error Responses

All endpoints return consistent error responses:

### 400 Bad Request
```json
{
    "detail": "Validation error message",
    "errors": [
        {
            "field": "cloud_provider",
            "message": "Invalid cloud provider specified"
        }
    ]
}
```

### 401 Unauthorized
```json
{
    "detail": "Could not validate credentials"
}
```

### 403 Forbidden
```json
{
    "detail": "Insufficient permissions for this operation"
}
```

### 404 Not Found
```json
{
    "detail": "Resource not found"
}
```

### 422 Validation Error
```json
{
    "detail": [
        {
            "loc": ["body", "email"],
            "msg": "field required",
            "type": "value_error.missing"
        }
    ]
}
```

### 500 Internal Server Error
```json
{
    "detail": "Internal server error",
    "request_id": "req-12345-abcde"
}
```

## Rate Limiting

API endpoints are rate limited to prevent abuse:

- **Authentication endpoints**: 5 requests per minute
- **Scan endpoints**: 10 requests per minute
- **General endpoints**: 100 requests per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642262400
```

## Webhooks

CloudSentinel supports webhooks for real-time notifications:

### Webhook Events
- `scan.completed`: When a scan finishes
- `alert.created`: When a new alert is generated
- `alert.resolved`: When an alert is marked as resolved

### Webhook Payload Example
```json
{
    "event": "scan.completed",
    "timestamp": "2024-01-15T14:15:00Z",
    "data": {
        "scan_id": "scan-456",
        "cloud_provider": "aws",
        "findings_count": 45,
        "critical_findings": 3
    }
}
```

## SDK and Client Libraries

CloudSentinel provides official SDKs for popular programming languages:

- **Python**: `pip install cloudsentinel-python`
- **Node.js**: `npm install cloudsentinel-node`
- **Go**: `go get github.com/cloudsentinel/go-sdk`

### Python SDK Example
```python
from cloudsentinel import CloudSentinelClient

client = CloudSentinelClient(
    api_url="https://api.cloudsentinel.com",
    token="your-api-token"
)

# Start a scan
scan = client.scans.create({
    "cloud_provider": "aws",
    "credentials": {...},
    "config": {...}
})

# Get scan results
results = client.scans.get_results(scan.id)
```
