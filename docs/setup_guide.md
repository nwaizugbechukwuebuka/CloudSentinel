# CloudSentinel Setup Guide

## Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows with WSL2
- **Memory**: Minimum 8GB RAM (16GB recommended)
- **Storage**: 20GB available disk space
- **Network**: Internet connectivity for cloud API access

### Software Dependencies
- **Python**: 3.9 or higher
- **Node.js**: 16.x or higher
- **PostgreSQL**: 13 or higher
- **Redis**: 6.x or higher
- **Docker**: 20.x or higher (optional, for containerized deployment)
- **Kubernetes**: 1.24 or higher (optional, for Kubernetes deployment)

## Installation Methods

### Method 1: Docker Compose (Recommended)

This is the fastest way to get CloudSentinel running locally.

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/cloudsentinel.git
   cd cloudsentinel
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` file with your settings:
   ```env
   # Database Configuration
   POSTGRES_DB=cloudsentinel
   POSTGRES_USER=cloudsentinel
   POSTGRES_PASSWORD=secure_password_here
   
   # Redis Configuration
   REDIS_URL=redis://redis:6379/0
   
   # JWT Configuration
   SECRET_KEY=your_secret_key_here
   JWT_SECRET_KEY=your_jwt_secret_key_here
   
   # API Configuration
   API_HOST=0.0.0.0
   API_PORT=8000
   
   # Frontend Configuration
   VITE_API_URL=http://localhost:8000
   ```

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

4. **Initialize the database**
   ```bash
   docker-compose exec api alembic upgrade head
   ```

5. **Create admin user**
   ```bash
   docker-compose exec api python -c "
   from src.api.database import get_db
   from src.api.services.auth_services import auth_service
   from src.api.models.user import User
   
   db = next(get_db())
   admin_user = User(
       email='admin@cloudsentinel.com',
       username='admin',
       full_name='Administrator',
       hashed_password=auth_service.get_password_hash('admin123'),
       role='admin',
       is_active=True
   )
   db.add(admin_user)
   db.commit()
   print('Admin user created: admin@cloudsentinel.com / admin123')
   "
   ```

6. **Access the application**
   - Web Interface: http://localhost:3000
   - API Documentation: http://localhost:8000/docs
   - Default Login: admin@cloudsentinel.com / admin123

### Method 2: Manual Installation

For development or customized deployments.

#### Backend Setup

1. **Create Python virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up PostgreSQL database**
   ```bash
   sudo -u postgres createdb cloudsentinel
   sudo -u postgres createuser cloudsentinel
   sudo -u postgres psql -c "ALTER USER cloudsentinel PASSWORD 'your_password';"
   sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE cloudsentinel TO cloudsentinel;"
   ```

4. **Configure environment variables**
   ```bash
   export DATABASE_URL="postgresql://cloudsentinel:your_password@localhost/cloudsentinel"
   export REDIS_URL="redis://localhost:6379/0"
   export SECRET_KEY="your-secret-key"
   export JWT_SECRET_KEY="your-jwt-secret"
   ```

5. **Initialize database schema**
   ```bash
   cd src/api
   alembic upgrade head
   ```

6. **Start Redis server**
   ```bash
   redis-server
   ```

7. **Start Celery worker**
   ```bash
   celery -A src.tasks.scan_tasks worker --loglevel=info
   ```

8. **Start Celery scheduler**
   ```bash
   celery -A src.tasks.scan_tasks beat --loglevel=info
   ```

9. **Start FastAPI server**
   ```bash
   uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
   ```

#### Frontend Setup

1. **Navigate to frontend directory**
   ```bash
   cd src/frontend
   ```

2. **Install Node.js dependencies**
   ```bash
   npm install
   ```

3. **Configure environment**
   ```bash
   echo "VITE_API_URL=http://localhost:8000" > .env
   ```

4. **Start development server**
   ```bash
   npm run dev
   ```

### Method 3: Kubernetes Deployment

For production environments with high availability.

#### Prerequisites
- Kubernetes cluster (1.24+)
- kubectl configured
- Helm 3.x (optional)

#### Quick Deployment

1. **Apply Kubernetes manifests**
   ```bash
   kubectl apply -f deployment/k8s/
   ```

2. **Verify deployment**
   ```bash
   kubectl get pods -l app=cloudsentinel
   ```

3. **Get service URL**
   ```bash
   kubectl get ingress cloudsentinel-ingress
   ```

#### Helm Deployment (Alternative)

1. **Add CloudSentinel Helm repository**
   ```bash
   helm repo add cloudsentinel https://charts.cloudsentinel.com
   helm repo update
   ```

2. **Install with custom values**
   ```bash
   helm install cloudsentinel cloudsentinel/cloudsentinel \
     --set database.password=your_db_password \
     --set auth.jwtSecret=your_jwt_secret \
     --set ingress.hostname=cloudsentinel.yourdomain.com
   ```

## Configuration

### Database Configuration

CloudSentinel uses PostgreSQL as the primary database. Key configurations:

```python
# src/utils/config.py
DATABASE_URL = "postgresql://user:password@host:port/database"
DATABASE_POOL_SIZE = 20
DATABASE_MAX_OVERFLOW = 30
DATABASE_POOL_TIMEOUT = 30
```

### Redis Configuration

Redis is used for caching and Celery message brokering:

```python
REDIS_URL = "redis://host:port/db"
REDIS_MAX_CONNECTIONS = 100
CACHE_TTL = 3600  # 1 hour default
```

### Authentication Configuration

JWT-based authentication settings:

```python
JWT_SECRET_KEY = "your-256-bit-secret"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
PASSWORD_MIN_LENGTH = 8
```

### Scanning Configuration

Default scanning parameters:

```python
# Maximum concurrent scans
MAX_CONCURRENT_SCANS = 10

# Scan timeout (minutes)
SCAN_TIMEOUT_MINUTES = 60

# Results retention (days)
RESULTS_RETENTION_DAYS = 365

# Default scan depth
DEFAULT_DEEP_SCAN = False
```

### Logging Configuration

Structured logging setup:

```python
LOG_LEVEL = "INFO"
LOG_FORMAT = "json"
LOG_FILE = "/var/log/cloudsentinel/app.log"
LOG_ROTATION = "daily"
LOG_RETENTION_DAYS = 30
```

## Cloud Provider Setup

### AWS Configuration

1. **Create IAM User for CloudSentinel**
   ```bash
   aws iam create-user --user-name cloudsentinel-scanner
   ```

2. **Attach SecurityAudit policy**
   ```bash
   aws iam attach-user-policy \
     --user-name cloudsentinel-scanner \
     --policy-arn arn:aws:iam::aws:policy/SecurityAudit
   ```

3. **Create access keys**
   ```bash
   aws iam create-access-key --user-name cloudsentinel-scanner
   ```

4. **Test permissions**
   ```bash
   aws sts get-caller-identity
   aws s3 ls
   aws iam list-users
   ```

#### Required AWS Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketLocation",
                "s3:ListAllMyBuckets",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListRoles",
                "iam:GetRole",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeVpcs",
                "ec2:DescribeNetworkAcls",
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters"
            ],
            "Resource": "*"
        }
    ]
}
```

### Azure Configuration

1. **Create Service Principal**
   ```bash
   az ad sp create-for-rbac --name "CloudSentinel" --role "Security Reader"
   ```

2. **Note the output** (save these values):
   ```json
   {
     "appId": "your-client-id",
     "displayName": "CloudSentinel",
     "name": "your-service-principal-name",
     "password": "your-client-secret",
     "tenant": "your-tenant-id"
   }
   ```

3. **Test access**
   ```bash
   az login --service-principal -u your-client-id -p your-client-secret --tenant your-tenant-id
   az account show
   ```

#### Required Azure Roles
- **Security Reader**: Read access to security-related resources
- **Storage Account Contributor**: Read access to storage accounts
- **Network Contributor**: Read access to network resources

### GCP Configuration

1. **Create Service Account**
   ```bash
   gcloud iam service-accounts create cloudsentinel-scanner \
     --description="CloudSentinel Security Scanner" \
     --display-name="CloudSentinel Scanner"
   ```

2. **Grant required roles**
   ```bash
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member="serviceAccount:cloudsentinel-scanner@PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/security.securityReviewer"
   
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member="serviceAccount:cloudsentinel-scanner@PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/storage.objectViewer"
   ```

3. **Create and download key**
   ```bash
   gcloud iam service-accounts keys create cloudsentinel-key.json \
     --iam-account=cloudsentinel-scanner@PROJECT_ID.iam.gserviceaccount.com
   ```

## Security Hardening

### Production Security Checklist

- [ ] Change all default passwords
- [ ] Use strong JWT secrets (256-bit random)
- [ ] Enable TLS/SSL for all connections
- [ ] Configure firewall rules
- [ ] Enable audit logging
- [ ] Set up monitoring and alerting
- [ ] Regular security updates
- [ ] Backup and recovery procedures

### SSL/TLS Configuration

For production deployments, enable HTTPS:

1. **Obtain SSL certificates**
   ```bash
   # Using Let's Encrypt
   certbot certonly --standalone -d cloudsentinel.yourdomain.com
   ```

2. **Configure Nginx**
   ```nginx
   server {
       listen 443 ssl http2;
       server_name cloudsentinel.yourdomain.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/private.key;
       
       location / {
           proxy_pass http://frontend:3000;
       }
       
       location /api {
           proxy_pass http://api:8000;
       }
   }
   ```

### Network Security

1. **Firewall Rules**
   ```bash
   # Allow only necessary ports
   ufw allow 80/tcp
   ufw allow 443/tcp
   ufw deny 8000/tcp  # Block direct API access
   ufw deny 5432/tcp  # Block direct database access
   ```

2. **Database Security**
   ```sql
   -- Create restricted database user
   CREATE USER cloudsentinel_app WITH PASSWORD 'secure_password';
   GRANT CONNECT ON DATABASE cloudsentinel TO cloudsentinel_app;
   GRANT USAGE ON SCHEMA public TO cloudsentinel_app;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cloudsentinel_app;
   ```

## Monitoring and Maintenance

### Health Monitoring

CloudSentinel provides built-in health endpoints:

- **API Health**: `GET /health`
- **Database Health**: `GET /health/database`
- **Redis Health**: `GET /health/redis`
- **Celery Health**: `GET /health/celery`

### Log Monitoring

Key log locations:
```bash
# Application logs
tail -f /var/log/cloudsentinel/app.log

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Database logs
tail -f /var/log/postgresql/postgresql-13-main.log
```

### Performance Monitoring

Monitor these key metrics:
- API response times
- Database query performance
- Scan execution times
- Memory and CPU usage
- Disk space utilization

### Backup Procedures

1. **Database Backup**
   ```bash
   pg_dump cloudsentinel > cloudsentinel_backup_$(date +%Y%m%d).sql
   ```

2. **Configuration Backup**
   ```bash
   tar -czf config_backup_$(date +%Y%m%d).tar.gz /etc/cloudsentinel/
   ```

3. **Automated Backup Script**
   ```bash
   #!/bin/bash
   BACKUP_DIR="/backups"
   DATE=$(date +%Y%m%d_%H%M%S)
   
   # Database backup
   pg_dump cloudsentinel | gzip > $BACKUP_DIR/db_$DATE.sql.gz
   
   # Clean old backups (keep 30 days)
   find $BACKUP_DIR -name "db_*.sql.gz" -mtime +30 -delete
   ```

## Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check PostgreSQL status
systemctl status postgresql

# Test database connection
psql -h localhost -U cloudsentinel -d cloudsentinel -c "SELECT 1;"

# Check database logs
tail -f /var/log/postgresql/postgresql-13-main.log
```

#### Redis Connection Issues
```bash
# Check Redis status
systemctl status redis-server

# Test Redis connection
redis-cli ping

# Monitor Redis logs
tail -f /var/log/redis/redis-server.log
```

#### Celery Worker Issues
```bash
# Check worker status
celery -A src.tasks.scan_tasks status

# Monitor worker logs
tail -f /var/log/cloudsentinel/celery_worker.log

# Restart workers
systemctl restart cloudsentinel-worker
```

#### Cloud API Permission Issues
```bash
# Test AWS permissions
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name cloudsentinel-scanner

# Test Azure permissions
az account show
az role assignment list --assignee your-client-id

# Test GCP permissions
gcloud auth list
gcloud projects get-iam-policy PROJECT_ID
```

### Performance Tuning

1. **Database Optimization**
   ```sql
   -- Add indexes for common queries
   CREATE INDEX idx_scan_results_severity ON scan_results(severity);
   CREATE INDEX idx_scan_results_created_at ON scan_results(created_at);
   CREATE INDEX idx_alerts_status ON alerts(status);
   
   -- Analyze query performance
   EXPLAIN ANALYZE SELECT * FROM scan_results WHERE severity = 'critical';
   ```

2. **Redis Optimization**
   ```redis
   # Increase memory limit
   maxmemory 2gb
   maxmemory-policy allkeys-lru
   
   # Enable persistence
   save 900 1
   save 300 10
   ```

3. **Application Tuning**
   ```python
   # Increase worker processes
   workers = multiprocessing.cpu_count() * 2 + 1
   
   # Optimize database connections
   DATABASE_POOL_SIZE = 20
   DATABASE_MAX_OVERFLOW = 30
   ```

### Getting Help

- **Documentation**: https://docs.cloudsentinel.com
- **GitHub Issues**: https://github.com/your-org/cloudsentinel/issues
- **Community Forum**: https://community.cloudsentinel.com
- **Security Issues**: security@cloudsentinel.com
