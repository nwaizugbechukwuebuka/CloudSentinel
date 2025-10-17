# CloudSentinel Architecture Documentation

## Overview

CloudSentinel is a comprehensive cloud infrastructure security scanner designed to detect misconfigurations, weak IAM policies, public storage buckets, and exposed endpoints across AWS, Azure, and GCP environments.

## System Architecture

### High-Level Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   React Web     │    │   FastAPI        │    │   PostgreSQL    │
│   Frontend      │◄──►│   Backend API    │◄──►│   Database      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                         
                                ▼                         
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Celery Worker  │    │   Redis Broker  │
                       │   Background     │◄──►│   & Cache       │
                       │   Tasks          │    └─────────────────┘
                       └──────────────────┘              
                                │                         
                                ▼                         
                    ┌─────────────────────────┐           
                    │   Cloud Scanners        │           
                    │   ┌───────────────────┐ │           
                    │   │   AWS Scanner     │ │           
                    │   │   Azure Scanner   │ │           
                    │   │   GCP Scanner     │ │           
                    │   └───────────────────┘ │           
                    └─────────────────────────┘           
```

### Component Details

#### 1. Frontend Layer (React)
- **Technology**: React 18 with Vite build system
- **Styling**: Tailwind CSS for responsive design
- **State Management**: React Query for server state
- **Authentication**: JWT token-based authentication
- **Visualization**: Recharts for security metrics and dashboards

**Key Components:**
- Dashboard: Security overview and metrics
- Scan Management: Initiate and monitor scans
- Alert Management: View and manage security alerts
- Settings: Configure scanning parameters and notifications

#### 2. API Layer (FastAPI)
- **Framework**: FastAPI 0.104.1 with async/await support
- **Authentication**: JWT tokens with role-based access control
- **Documentation**: Auto-generated OpenAPI/Swagger docs
- **Validation**: Pydantic models for request/response validation
- **Middleware**: CORS, security headers, rate limiting

**API Modules:**
- `/auth`: User authentication and authorization
- `/scan`: Scanning operations and management
- `/alerts`: Security alert management
- `/reports`: Reporting and analytics

#### 3. Database Layer (PostgreSQL)
- **Database**: PostgreSQL 15 with advanced features
- **ORM**: SQLAlchemy 2.0 with async support
- **Migrations**: Alembic for database schema management
- **Connection Pooling**: Optimized connection management

**Data Models:**
- Users: Authentication and authorization
- ScanResults: Security findings and vulnerabilities
- Alerts: Security alerts and notifications
- ScanJobs: Scan execution tracking

#### 4. Task Processing (Celery)
- **Message Broker**: Redis for task queuing
- **Worker Architecture**: Distributed task processing
- **Scheduling**: Periodic scans with Celery Beat
- **Monitoring**: Task status and progress tracking

**Background Tasks:**
- Cloud security scanning
- Alert processing and notifications
- Report generation
- Data cleanup and archival

#### 5. Cloud Scanner Modules

##### AWS Scanner
- **SDK**: boto3 for AWS API interactions
- **Services Covered**:
  - S3: Bucket permissions, encryption, versioning
  - IAM: Policies, roles, users, access keys
  - EC2: Security groups, instances, AMIs
  - VPC: Network ACLs, flow logs, endpoints
  - RDS: Database security, encryption
  - CloudTrail: Logging and monitoring
  - KMS: Key management and rotation

##### Azure Scanner  
- **SDK**: Azure SDK for Python
- **Services Covered**:
  - Storage Accounts: Access policies, encryption
  - Identity: Azure AD, roles, permissions
  - Virtual Machines: Security configurations
  - Network Security Groups: Traffic rules
  - Key Vault: Secret management
  - SQL Database: Security configurations
  - Activity Logs: Audit and monitoring

##### GCP Scanner
- **SDK**: Google Cloud Client Libraries
- **Services Covered**:
  - Cloud Storage: Bucket permissions, encryption
  - IAM: Policies, service accounts, roles
  - Compute Engine: Instance security
  - VPC: Firewall rules, network security
  - Cloud SQL: Database security
  - Cloud KMS: Key management
  - Cloud Audit Logs: Security monitoring

### Security Features

#### 1. Vulnerability Detection
- **Public Storage**: Detects publicly accessible storage buckets
- **IAM Misconfigurations**: Overprivileged policies and roles
- **Network Exposure**: Open security groups and firewall rules
- **Encryption Issues**: Unencrypted resources and weak encryption
- **Access Control**: Improper resource permissions

#### 2. Compliance Frameworks
- **CIS Benchmarks**: Center for Internet Security controls
- **NIST Cybersecurity Framework**: Risk management guidelines
- **ISO 27001**: Information security management
- **SOC 2**: Security and availability controls
- **GDPR**: Data protection regulations

#### 3. Risk Assessment
- **Risk Scoring**: Weighted risk calculation (0-10 scale)
- **Severity Classification**: Critical, High, Medium, Low, Info
- **Exploitability Analysis**: Attack vector assessment
- **Business Impact**: Resource criticality evaluation
- **Remediation Prioritization**: Risk-based remediation ordering

### Deployment Architecture

#### Container Strategy
```
┌─────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                       │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Frontend      │  │   API Gateway   │  │   API Services  │ │
│  │   (Nginx +      │  │   (Ingress)     │  │   (FastAPI)     │ │
│  │   React)        │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Celery        │  │   PostgreSQL    │  │   Redis         │ │
│  │   Workers       │  │   Database      │  │   Cache/Broker  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Infrastructure Components
- **Load Balancer**: Nginx ingress controller
- **Service Mesh**: Internal service communication
- **Persistent Storage**: PostgreSQL data persistence
- **Horizontal Scaling**: Auto-scaling based on load
- **Health Checks**: Liveness and readiness probes
- **Secrets Management**: Kubernetes secrets for credentials

### Data Flow

#### 1. Scan Initiation Flow
```
User → Frontend → API → Database → Celery → Cloud Scanner → Results → Database → Alerts
```

#### 2. Real-time Updates
```
Scanner → Results → WebSocket → Frontend Dashboard
```

#### 3. Report Generation
```
Scheduler → Celery → Data Aggregation → Report Builder → Storage → Notification
```

### Performance Characteristics

#### Scalability Metrics
- **Concurrent Scans**: Up to 100 simultaneous cloud scans
- **Resource Coverage**: 10,000+ resources per scan
- **Response Time**: <200ms API response time
- **Throughput**: 1000+ API requests per second
- **Data Volume**: Handle 1TB+ of security data

#### Optimization Strategies
- **Caching**: Redis for frequently accessed data
- **Connection Pooling**: Database connection optimization
- **Async Processing**: Non-blocking I/O operations
- **Resource Partitioning**: Distributed scanning across regions
- **Data Compression**: Efficient storage and transmission

### Monitoring and Observability

#### Application Metrics
- **Scan Performance**: Execution time and success rates
- **API Metrics**: Request/response metrics and error rates
- **Resource Utilization**: CPU, memory, and storage usage
- **Alert Metrics**: Alert volume and resolution times

#### Logging Strategy
- **Structured Logging**: JSON-formatted logs with correlation IDs
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Log Aggregation**: Centralized logging with search capabilities
- **Audit Trails**: Complete security event tracking

#### Health Checks
- **Service Health**: API endpoint availability
- **Database Health**: Connection and query performance
- **External Dependencies**: Cloud provider API status
- **Background Tasks**: Celery worker status and queue health

### Security Considerations

#### Application Security
- **Authentication**: Multi-factor authentication support
- **Authorization**: Role-based access control (RBAC)
- **Data Encryption**: TLS 1.3 for data in transit
- **Storage Encryption**: AES-256 for data at rest
- **Input Validation**: Comprehensive input sanitization

#### Infrastructure Security
- **Network Segmentation**: Isolated network zones
- **Secrets Management**: Encrypted credential storage
- **Image Security**: Container image vulnerability scanning
- **Access Control**: Principle of least privilege
- **Audit Logging**: Comprehensive security event logging

### Extensibility Framework

#### Plugin Architecture
- **Scanner Plugins**: Custom cloud provider support
- **Alert Plugins**: Integration with external systems
- **Report Plugins**: Custom report formats and destinations
- **Compliance Plugins**: Additional regulatory frameworks

#### API Extensions
- **Webhook Integration**: Real-time event notifications
- **Custom Endpoints**: Organization-specific APIs
- **Data Export**: Multiple formats (JSON, CSV, XML, PDF)
- **Integration APIs**: Third-party security tools

#### Configuration Management
- **Environment-based Config**: Development, staging, production
- **Feature Flags**: Runtime feature toggle capability
- **Dynamic Configuration**: Hot-reload configuration changes
- **Multi-tenancy**: Organization isolation and customization
