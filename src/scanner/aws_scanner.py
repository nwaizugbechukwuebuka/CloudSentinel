"""AWS security scanner for CloudSentinel."""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List, Any
from src.scanner.common import CloudScanner, Finding, VulnerabilityType, get_compliance_frameworks
from src.utils.logger import logger


class AWSScanner(CloudScanner):
    """AWS security scanner implementation."""
    
    def __init__(self, credentials: Dict[str, Any]):
        super().__init__(credentials)
        self.session = None
        self.regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
        self.account_id = None
    
    def authenticate(self) -> bool:
        """Authenticate with AWS using provided credentials."""
        try:
            # Create AWS session
            if self.credentials.get('access_key_id') and self.credentials.get('secret_access_key'):
                self.session = boto3.Session(
                    aws_access_key_id=self.credentials['access_key_id'],
                    aws_secret_access_key=self.credentials['secret_access_key'],
                    region_name=self.credentials.get('region', 'us-east-1')
                )
            else:
                # Use default credentials (IAM role, profile, etc.)
                self.session = boto3.Session()
            
            # Test authentication by getting caller identity
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            
            logger.info("AWS authentication successful", account_id=self.account_id)
            return True
            
        except (ClientError, NoCredentialsError) as e:
            logger.error("AWS authentication failed", error=str(e))
            return False
    
    def scan_storage(self) -> List[Finding]:
        """Scan AWS S3 buckets for security issues."""
        findings = []
        
        try:
            s3 = self.session.client('s3')
            
            # Get all buckets
            response = s3.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket region
                    bucket_region = s3.get_bucket_location(Bucket=bucket_name)
                    region = bucket_region.get('LocationConstraint') or 'us-east-1'
                    
                    # Create regional S3 client
                    s3_regional = self.session.client('s3', region_name=region)
                    
                    # Check public access
                    public_findings = self._check_s3_public_access(s3_regional, bucket_name, region)
                    findings.extend(public_findings)
                    
                    # Check encryption
                    encryption_findings = self._check_s3_encryption(s3_regional, bucket_name, region)
                    findings.extend(encryption_findings)
                    
                    # Check versioning
                    versioning_findings = self._check_s3_versioning(s3_regional, bucket_name, region)
                    findings.extend(versioning_findings)
                    
                except ClientError as e:
                    logger.warning("Error scanning S3 bucket", bucket=bucket_name, error=str(e))
                    
        except ClientError as e:
            logger.error("Error listing S3 buckets", error=str(e))
        
        return findings
    
    def _check_s3_public_access(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check S3 bucket for public access issues."""
        findings = []
        
        try:
            # Check bucket ACL
            acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = acl_response.get('Grants', [])
            
            for grant in grants:
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                    risk_score = self.calculate_risk_score(
                        VulnerabilityType.PUBLIC_BUCKET,
                        {"public_access": True, "production_env": True}
                    )
                    
                    finding = Finding(
                        finding_id=self.generate_finding_id(),
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        resource_type="S3 Bucket",
                        vulnerability_type=VulnerabilityType.PUBLIC_BUCKET,
                        risk_level=self.get_risk_level(risk_score),
                        title=f"S3 Bucket '{bucket_name}' is publicly accessible",
                        description=f"The S3 bucket '{bucket_name}' has public read/write permissions, which could expose sensitive data.",
                        remediation="Remove public access permissions and implement bucket policies with least privilege principles.",
                        region=region,
                        account_id=self.account_id,
                        compliance_frameworks=get_compliance_frameworks(VulnerabilityType.PUBLIC_BUCKET),
                        risk_score=risk_score,
                        tags={"service": "s3", "type": "storage"},
                        configuration={"bucket_name": bucket_name, "public_acl": True}
                    )
                    findings.append(finding)
            
            # Check bucket policy for public access
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = policy_response.get('Policy', '')
                
                if '"Principal":"*"' in policy or '"Principal":{"AWS":"*"}' in policy:
                    risk_score = self.calculate_risk_score(
                        VulnerabilityType.PUBLIC_BUCKET,
                        {"public_access": True, "production_env": True}
                    )
                    
                    finding = Finding(
                        finding_id=self.generate_finding_id(),
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        resource_type="S3 Bucket",
                        vulnerability_type=VulnerabilityType.PUBLIC_BUCKET,
                        risk_level=self.get_risk_level(risk_score),
                        title=f"S3 Bucket '{bucket_name}' has public bucket policy",
                        description=f"The S3 bucket '{bucket_name}' has a bucket policy allowing public access.",
                        remediation="Review and restrict bucket policy to authorized principals only.",
                        region=region,
                        account_id=self.account_id,
                        compliance_frameworks=get_compliance_frameworks(VulnerabilityType.PUBLIC_BUCKET),
                        risk_score=risk_score,
                        tags={"service": "s3", "type": "storage"},
                        configuration={"bucket_name": bucket_name, "public_policy": True}
                    )
                    findings.append(finding)
                    
            except ClientError:
                # No bucket policy exists
                pass
                
        except ClientError as e:
            logger.warning("Error checking S3 bucket public access", bucket=bucket_name, error=str(e))
        
        return findings
    
    def _check_s3_encryption(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check S3 bucket encryption configuration."""
        findings = []
        
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
            # Encryption is configured
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                # No encryption configured
                risk_score = self.calculate_risk_score(
                    VulnerabilityType.UNENCRYPTED_STORAGE,
                    {"sensitive_data": True, "production_env": True}
                )
                
                finding = Finding(
                    finding_id=self.generate_finding_id(),
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    resource_type="S3 Bucket",
                    vulnerability_type=VulnerabilityType.UNENCRYPTED_STORAGE,
                    risk_level=self.get_risk_level(risk_score),
                    title=f"S3 Bucket '{bucket_name}' lacks encryption",
                    description=f"The S3 bucket '{bucket_name}' does not have server-side encryption enabled.",
                    remediation="Enable server-side encryption using AES-256 or KMS keys.",
                    region=region,
                    account_id=self.account_id,
                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.UNENCRYPTED_STORAGE),
                    risk_score=risk_score,
                    tags={"service": "s3", "type": "storage"},
                    configuration={"bucket_name": bucket_name, "encryption": False}
                )
                findings.append(finding)
        
        return findings
    
    def _check_s3_versioning(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check S3 bucket versioning configuration."""
        findings = []
        
        try:
            versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_status = versioning_response.get('Status', 'Disabled')
            
            if versioning_status != 'Enabled':
                risk_score = self.calculate_risk_score(
                    VulnerabilityType.COMPLIANCE_VIOLATION,
                    {"production_env": True}
                )
                
                finding = Finding(
                    finding_id=self.generate_finding_id(),
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    resource_type="S3 Bucket",
                    vulnerability_type=VulnerabilityType.COMPLIANCE_VIOLATION,
                    risk_level=self.get_risk_level(risk_score),
                    title=f"S3 Bucket '{bucket_name}' versioning disabled",
                    description=f"The S3 bucket '{bucket_name}' does not have versioning enabled, which affects data protection and compliance.",
                    remediation="Enable versioning to protect against accidental deletion and meet compliance requirements.",
                    region=region,
                    account_id=self.account_id,
                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.COMPLIANCE_VIOLATION),
                    risk_score=risk_score,
                    tags={"service": "s3", "type": "storage"},
                    configuration={"bucket_name": bucket_name, "versioning": False}
                )
                findings.append(finding)
                
        except ClientError as e:
            logger.warning("Error checking S3 bucket versioning", bucket=bucket_name, error=str(e))
        
        return findings
    
    def scan_iam(self) -> List[Finding]:
        """Scan AWS IAM for security issues."""
        findings = []
        
        try:
            iam = self.session.client('iam')
            
            # Check for overly permissive policies
            findings.extend(self._check_iam_policies(iam))
            
            # Check for users without MFA
            findings.extend(self._check_iam_mfa(iam))
            
            # Check password policy
            findings.extend(self._check_password_policy(iam))
            
        except ClientError as e:
            logger.error("Error scanning IAM", error=str(e))
        
        return findings
    
    def _check_iam_policies(self, iam_client) -> List[Finding]:
        """Check for overly permissive IAM policies."""
        findings = []
        
        try:
            # Get all policies
            paginator = iam_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):
                policies = page.get('Policies', [])
                
                for policy in policies:
                    policy_arn = policy['Arn']
                    policy_name = policy['PolicyName']
                    
                    try:
                        # Get policy document
                        policy_version = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        document = policy_version['PolicyVersion']['Document']
                        statements = document.get('Statement', [])
                        
                        if not isinstance(statements, list):
                            statements = [statements]
                        
                        for statement in statements:
                            effect = statement.get('Effect', '')
                            action = statement.get('Action', [])
                            resource = statement.get('Resource', [])
                            
                            # Check for overly broad permissions
                            if (effect == 'Allow' and 
                                ('*' in action or action == '*') and 
                                ('*' in resource or resource == '*')):
                                
                                risk_score = self.calculate_risk_score(
                                    VulnerabilityType.EXCESSIVE_PERMISSIONS,
                                    {"production_env": True}
                                )
                                
                                finding = Finding(
                                    finding_id=self.generate_finding_id(),
                                    resource_id=policy_arn,
                                    resource_name=policy_name,
                                    resource_type="IAM Policy",
                                    vulnerability_type=VulnerabilityType.EXCESSIVE_PERMISSIONS,
                                    risk_level=self.get_risk_level(risk_score),
                                    title=f"IAM Policy '{policy_name}' has excessive permissions",
                                    description=f"The IAM policy '{policy_name}' allows all actions on all resources.",
                                    remediation="Apply principle of least privilege by restricting actions and resources to minimum required.",
                                    region="global",
                                    account_id=self.account_id,
                                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.EXCESSIVE_PERMISSIONS),
                                    risk_score=risk_score,
                                    tags={"service": "iam", "type": "policy"},
                                    configuration={"policy_name": policy_name, "overly_permissive": True}
                                )
                                findings.append(finding)
                                break
                                
                    except ClientError as e:
                        logger.warning("Error checking IAM policy", policy=policy_name, error=str(e))
                        
        except ClientError as e:
            logger.error("Error listing IAM policies", error=str(e))
        
        return findings
    
    def _check_iam_mfa(self, iam_client) -> List[Finding]:
        """Check for IAM users without MFA."""
        findings = []
        
        try:
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                users = page.get('Users', [])
                
                for user in users:
                    username = user['UserName']
                    
                    try:
                        # Check if user has MFA devices
                        mfa_devices = iam_client.list_mfa_devices(UserName=username)
                        
                        if not mfa_devices.get('MFADevices'):
                            risk_score = self.calculate_risk_score(
                                VulnerabilityType.MISSING_MFA,
                                {"production_env": True}
                            )
                            
                            finding = Finding(
                                finding_id=self.generate_finding_id(),
                                resource_id=username,
                                resource_name=username,
                                resource_type="IAM User",
                                vulnerability_type=VulnerabilityType.MISSING_MFA,
                                risk_level=self.get_risk_level(risk_score),
                                title=f"IAM User '{username}' lacks MFA",
                                description=f"The IAM user '{username}' does not have multi-factor authentication enabled.",
                                remediation="Enable MFA for all IAM users, especially those with console access.",
                                region="global",
                                account_id=self.account_id,
                                compliance_frameworks=get_compliance_frameworks(VulnerabilityType.MISSING_MFA),
                                risk_score=risk_score,
                                tags={"service": "iam", "type": "user"},
                                configuration={"username": username, "mfa_enabled": False}
                            )
                            findings.append(finding)
                            
                    except ClientError as e:
                        logger.warning("Error checking MFA for user", user=username, error=str(e))
                        
        except ClientError as e:
            logger.error("Error listing IAM users", error=str(e))
        
        return findings
    
    def _check_password_policy(self, iam_client) -> List[Finding]:
        """Check IAM password policy."""
        findings = []
        
        try:
            policy = iam_client.get_account_password_policy()
            password_policy = policy['PasswordPolicy']
            
            # Check policy strength
            weak_policy = False
            issues = []
            
            if password_policy.get('MinimumPasswordLength', 0) < 12:
                weak_policy = True
                issues.append("minimum length less than 12 characters")
            
            if not password_policy.get('RequireNumbers', False):
                weak_policy = True
                issues.append("numbers not required")
            
            if not password_policy.get('RequireSymbols', False):
                weak_policy = True
                issues.append("symbols not required")
            
            if not password_policy.get('RequireLowercaseCharacters', False):
                weak_policy = True
                issues.append("lowercase characters not required")
            
            if not password_policy.get('RequireUppercaseCharacters', False):
                weak_policy = True
                issues.append("uppercase characters not required")
            
            if weak_policy:
                risk_score = self.calculate_risk_score(
                    VulnerabilityType.WEAK_PASSWORD_POLICY,
                    {"production_env": True}
                )
                
                finding = Finding(
                    finding_id=self.generate_finding_id(),
                    resource_id="account-password-policy",
                    resource_name="Account Password Policy",
                    resource_type="IAM Password Policy",
                    vulnerability_type=VulnerabilityType.WEAK_PASSWORD_POLICY,
                    risk_level=self.get_risk_level(risk_score),
                    title="Weak IAM password policy detected",
                    description=f"The account password policy has weaknesses: {', '.join(issues)}.",
                    remediation="Strengthen password policy by requiring minimum 12 characters, numbers, symbols, and mixed case letters.",
                    region="global",
                    account_id=self.account_id,
                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.WEAK_PASSWORD_POLICY),
                    risk_score=risk_score,
                    tags={"service": "iam", "type": "policy"},
                    configuration={"password_policy": password_policy, "issues": issues}
                )
                findings.append(finding)
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                # No password policy set
                risk_score = self.calculate_risk_score(
                    VulnerabilityType.WEAK_PASSWORD_POLICY,
                    {"production_env": True}
                )
                
                finding = Finding(
                    finding_id=self.generate_finding_id(),
                    resource_id="account-password-policy",
                    resource_name="Account Password Policy",
                    resource_type="IAM Password Policy",
                    vulnerability_type=VulnerabilityType.WEAK_PASSWORD_POLICY,
                    risk_level=self.get_risk_level(risk_score),
                    title="No IAM password policy configured",
                    description="No account password policy is configured, allowing weak passwords.",
                    remediation="Configure a strong password policy requiring minimum 12 characters, numbers, symbols, and mixed case letters.",
                    region="global",
                    account_id=self.account_id,
                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.WEAK_PASSWORD_POLICY),
                    risk_score=risk_score,
                    tags={"service": "iam", "type": "policy"},
                    configuration={"password_policy": None}
                )
                findings.append(finding)
            else:
                logger.error("Error getting password policy", error=str(e))
        
        return findings
    
    def scan_network(self) -> List[Finding]:
        """Scan AWS network configurations."""
        findings = []
        
        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                
                # Check security groups
                findings.extend(self._check_security_groups(ec2, region))
                
                # Check VPC flow logs
                findings.extend(self._check_vpc_flow_logs(ec2, region))
                
            except ClientError as e:
                logger.warning("Error scanning network in region", region=region, error=str(e))
        
        return findings
    
    def _check_security_groups(self, ec2_client, region: str) -> List[Finding]:
        """Check for overly permissive security groups."""
        findings = []
        
        try:
            response = ec2_client.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        
                        if cidr == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 0)
                            protocol = rule.get('IpProtocol', '')
                            
                            # Check for dangerous open ports
                            dangerous_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
                            
                            if (from_port in dangerous_ports or 
                                (from_port == 0 and to_port == 65535) or
                                protocol == '-1'):  # All protocols
                                
                                risk_score = self.calculate_risk_score(
                                    VulnerabilityType.OPEN_SECURITY_GROUP,
                                    {"public_access": True, "production_env": True}
                                )
                                
                                finding = Finding(
                                    finding_id=self.generate_finding_id(),
                                    resource_id=sg_id,
                                    resource_name=sg_name,
                                    resource_type="Security Group",
                                    vulnerability_type=VulnerabilityType.OPEN_SECURITY_GROUP,
                                    risk_level=self.get_risk_level(risk_score),
                                    title=f"Security Group '{sg_name}' allows unrestricted access",
                                    description=f"Security group '{sg_name}' allows inbound access from 0.0.0.0/0 on port {from_port}.",
                                    remediation="Restrict security group rules to specific IP ranges and remove unnecessary open ports.",
                                    region=region,
                                    account_id=self.account_id,
                                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.OPEN_SECURITY_GROUP),
                                    risk_score=risk_score,
                                    tags={"service": "ec2", "type": "security_group"},
                                    configuration={
                                        "sg_id": sg_id,
                                        "sg_name": sg_name,
                                        "open_to_world": True,
                                        "port": from_port,
                                        "protocol": protocol
                                    }
                                )
                                findings.append(finding)
                                
        except ClientError as e:
            logger.error("Error checking security groups", region=region, error=str(e))
        
        return findings
    
    def _check_vpc_flow_logs(self, ec2_client, region: str) -> List[Finding]:
        """Check for missing VPC flow logs."""
        findings = []
        
        try:
            # Get VPCs
            vpc_response = ec2_client.describe_vpcs()
            vpcs = vpc_response.get('Vpcs', [])
            
            # Get flow logs
            flow_logs_response = ec2_client.describe_flow_logs()
            flow_logs = flow_logs_response.get('FlowLogs', [])
            
            # Create set of VPCs with flow logs
            vpcs_with_logs = {fl['ResourceId'] for fl in flow_logs if fl['ResourceType'] == 'VPC'}
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                
                if vpc_id not in vpcs_with_logs:
                    risk_score = self.calculate_risk_score(
                        VulnerabilityType.MISSING_LOGGING,
                        {"production_env": True}
                    )
                    
                    finding = Finding(
                        finding_id=self.generate_finding_id(),
                        resource_id=vpc_id,
                        resource_name=vpc_id,
                        resource_type="VPC",
                        vulnerability_type=VulnerabilityType.MISSING_LOGGING,
                        risk_level=self.get_risk_level(risk_score),
                        title=f"VPC '{vpc_id}' missing flow logs",
                        description=f"VPC '{vpc_id}' does not have flow logs enabled for network monitoring.",
                        remediation="Enable VPC flow logs to monitor network traffic and detect security issues.",
                        region=region,
                        account_id=self.account_id,
                        compliance_frameworks=get_compliance_frameworks(VulnerabilityType.MISSING_LOGGING),
                        risk_score=risk_score,
                        tags={"service": "vpc", "type": "logging"},
                        configuration={"vpc_id": vpc_id, "flow_logs_enabled": False}
                    )
                    findings.append(finding)
                    
        except ClientError as e:
            logger.error("Error checking VPC flow logs", region=region, error=str(e))
        
        return findings
    
    def scan_compute(self) -> List[Finding]:
        """Scan AWS compute resources."""
        findings = []
        
        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                
                # Check EC2 instances
                findings.extend(self._check_ec2_instances(ec2, region))
                
            except ClientError as e:
                logger.warning("Error scanning compute in region", region=region, error=str(e))
        
        return findings
    
    def _check_ec2_instances(self, ec2_client, region: str) -> List[Finding]:
        """Check EC2 instances for security issues."""
        findings = []
        
        try:
            response = ec2_client.describe_instances()
            reservations = response.get('Reservations', [])
            
            for reservation in reservations:
                instances = reservation.get('Instances', [])
                
                for instance in instances:
                    instance_id = instance['InstanceId']
                    instance_state = instance['State']['Name']
                    
                    # Only check running instances
                    if instance_state != 'running':
                        continue
                    
                    # Check for instances without detailed monitoring
                    monitoring = instance.get('Monitoring', {})
                    if monitoring.get('State') != 'enabled':
                        risk_score = self.calculate_risk_score(
                            VulnerabilityType.MISSING_LOGGING,
                            {"production_env": True}
                        )
                        
                        finding = Finding(
                            finding_id=self.generate_finding_id(),
                            resource_id=instance_id,
                            resource_name=instance_id,
                            resource_type="EC2 Instance",
                            vulnerability_type=VulnerabilityType.MISSING_LOGGING,
                            risk_level=self.get_risk_level(risk_score),
                            title=f"EC2 Instance '{instance_id}' lacks detailed monitoring",
                            description=f"EC2 instance '{instance_id}' does not have detailed monitoring enabled.",
                            remediation="Enable detailed monitoring for better visibility into instance performance and security.",
                            region=region,
                            account_id=self.account_id,
                            compliance_frameworks=get_compliance_frameworks(VulnerabilityType.MISSING_LOGGING),
                            risk_score=risk_score,
                            tags={"service": "ec2", "type": "monitoring"},
                            configuration={"instance_id": instance_id, "detailed_monitoring": False}
                        )
                        findings.append(finding)
                        
        except ClientError as e:
            logger.error("Error checking EC2 instances", region=region, error=str(e))
        
        return findings
