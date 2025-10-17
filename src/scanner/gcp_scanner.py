"""Google Cloud Platform security scanner for CloudSentinel."""

from google.cloud import asset_v1
from google.cloud import storage
from google.cloud import compute_v1
from google.oauth2 import service_account
from google.auth import default
from typing import Dict, List, Any
import json
from src.scanner.common import CloudScanner, Finding, VulnerabilityType, get_compliance_frameworks
from src.utils.logger import logger


class GCPScanner(CloudScanner):
    """GCP security scanner implementation."""
    
    def __init__(self, credentials: Dict[str, Any]):
        super().__init__(credentials)
        self.project_id = credentials.get('project_id')
        self.credentials_obj = None
        self.regions = ['us-central1', 'us-east1', 'europe-west1', 'asia-southeast1']
    
    def authenticate(self) -> bool:
        """Authenticate with GCP using provided credentials."""
        try:
            credentials_path = self.credentials.get('credentials_path')
            
            if credentials_path:
                # Use service account key file
                self.credentials_obj = service_account.Credentials.from_service_account_file(
                    credentials_path
                )
            else:
                # Use default credentials (service account, gcloud, etc.)
                self.credentials_obj, _ = default()
            
            # Test authentication by creating an asset client
            asset_client = asset_v1.AssetServiceClient(credentials=self.credentials_obj)
            parent = f"projects/{self.project_id}"
            
            # This will raise an exception if authentication fails
            list(asset_client.list_assets(request={"parent": parent}))
            
            logger.info("GCP authentication successful", project_id=self.project_id)
            return True
            
        except Exception as e:
            logger.error("GCP authentication failed", error=str(e))
            return False
    
    def scan_storage(self) -> List[Finding]:
        """Scan GCP Cloud Storage for security issues."""
        findings = []
        
        try:
            storage_client = storage.Client(
                project=self.project_id,
                credentials=self.credentials_obj
            )
            
            # Get all buckets
            buckets = storage_client.list_buckets()
            
            for bucket in buckets:
                bucket_name = bucket.name
                location = bucket.location
                
                try:
                    # Check public access
                    public_findings = self._check_bucket_public_access(bucket, location)
                    findings.extend(public_findings)
                    
                    # Check encryption
                    encryption_findings = self._check_bucket_encryption(bucket, location)
                    findings.extend(encryption_findings)
                    
                    # Check uniform bucket-level access
                    uniform_access_findings = self._check_uniform_bucket_access(bucket, location)
                    findings.extend(uniform_access_findings)
                    
                except Exception as e:
                    logger.warning("Error scanning GCS bucket", bucket=bucket_name, error=str(e))
                    
        except Exception as e:
            logger.error("Error listing GCS buckets", error=str(e))
        
        return findings
    
    def _check_bucket_public_access(self, bucket, location: str) -> List[Finding]:
        """Check bucket for public access issues."""
        findings = []
        
        try:
            # Get bucket IAM policy
            policy = bucket.get_iam_policy()
            
            for binding in policy.bindings:
                if 'allUsers' in binding.members or 'allAuthenticatedUsers' in binding.members:
                    risk_score = self.calculate_risk_score(
                        VulnerabilityType.PUBLIC_BUCKET,
                        {"public_access": True, "production_env": True}
                    )
                    
                    finding = Finding(
                        finding_id=self.generate_finding_id(),
                        resource_id=bucket.name,
                        resource_name=bucket.name,
                        resource_type="Cloud Storage Bucket",
                        vulnerability_type=VulnerabilityType.PUBLIC_BUCKET,
                        risk_level=self.get_risk_level(risk_score),
                        title=f"GCS Bucket '{bucket.name}' is publicly accessible",
                        description=f"The Cloud Storage bucket '{bucket.name}' has public access permissions.",
                        remediation="Remove public access and implement proper IAM policies with least privilege.",
                        region=location,
                        account_id=self.project_id,
                        compliance_frameworks=get_compliance_frameworks(VulnerabilityType.PUBLIC_BUCKET),
                        risk_score=risk_score,
                        tags={"service": "storage", "type": "bucket"},
                        configuration={
                            "bucket_name": bucket.name,
                            "public_access": True,
                            "members": binding.members
                        }
                    )
                    findings.append(finding)
                    break
                    
        except Exception as e:
            logger.warning("Error checking bucket public access", bucket=bucket.name, error=str(e))
        
        return findings
    
    def _check_bucket_encryption(self, bucket, location: str) -> List[Finding]:
        """Check bucket encryption configuration."""
        findings = []
        
        # Check if customer-managed encryption key is used
        if not bucket.default_kms_key_name:
            risk_score = self.calculate_risk_score(
                VulnerabilityType.UNENCRYPTED_STORAGE,
                {"sensitive_data": True}
            )
            
            finding = Finding(
                finding_id=self.generate_finding_id(),
                resource_id=bucket.name,
                resource_name=bucket.name,
                resource_type="Cloud Storage Bucket",
                vulnerability_type=VulnerabilityType.UNENCRYPTED_STORAGE,
                risk_level=self.get_risk_level(risk_score),
                title=f"GCS Bucket '{bucket.name}' not using CMEK",
                description=f"The bucket '{bucket.name}' is using Google-managed encryption instead of customer-managed keys.",
                remediation="Consider using customer-managed encryption keys (CMEK) for enhanced security control.",
                region=location,
                account_id=self.project_id,
                compliance_frameworks=get_compliance_frameworks(VulnerabilityType.UNENCRYPTED_STORAGE),
                risk_score=risk_score,
                tags={"service": "storage", "type": "encryption"},
                configuration={"bucket_name": bucket.name, "cmek": False}
            )
            findings.append(finding)
        
        return findings
    
    def _check_uniform_bucket_access(self, bucket, location: str) -> List[Finding]:
        """Check uniform bucket-level access configuration."""
        findings = []
        
        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            risk_score = self.calculate_risk_score(
                VulnerabilityType.WEAK_IAM_POLICY,
                {"production_env": True}
            )
            
            finding = Finding(
                finding_id=self.generate_finding_id(),
                resource_id=bucket.name,
                resource_name=bucket.name,
                resource_type="Cloud Storage Bucket",
                vulnerability_type=VulnerabilityType.WEAK_IAM_POLICY,
                risk_level=self.get_risk_level(risk_score),
                title=f"GCS Bucket '{bucket.name}' uniform access disabled",
                description=f"The bucket '{bucket.name}' does not have uniform bucket-level access enabled.",
                remediation="Enable uniform bucket-level access to simplify access management and improve security.",
                region=location,
                account_id=self.project_id,
                compliance_frameworks=get_compliance_frameworks(VulnerabilityType.WEAK_IAM_POLICY),
                risk_score=risk_score,
                tags={"service": "storage", "type": "access"},
                configuration={"bucket_name": bucket.name, "uniform_access": False}
            )
            findings.append(finding)
        
        return findings
    
    def scan_iam(self) -> List[Finding]:
        """Scan GCP IAM for security issues."""
        findings = []
        
        try:
            # Use Cloud Asset API to get IAM policies
            asset_client = asset_v1.AssetServiceClient(credentials=self.credentials_obj)
            parent = f"projects/{self.project_id}"
            
            # Get IAM policies for the project
            content_type = asset_v1.ContentType.IAM_POLICY
            request = asset_v1.ListAssetsRequest(
                parent=parent,
                content_type=content_type
            )
            
            assets = asset_client.list_assets(request=request)
            
            for asset in assets:
                if asset.iam_policy:
                    findings.extend(self._check_iam_policy(asset))
                    
        except Exception as e:
            logger.error("Error scanning GCP IAM", error=str(e))
        
        return findings
    
    def _check_iam_policy(self, asset) -> List[Finding]:
        """Check IAM policy for security issues."""
        findings = []
        
        policy = asset.iam_policy
        
        for binding in policy.bindings:
            # Check for overly broad permissions
            role = binding.role
            
            # Look for primitive roles (owner, editor, viewer) which are overly broad
            primitive_roles = ['roles/owner', 'roles/editor']
            
            if role in primitive_roles:
                for member in binding.members:
                    # Skip service accounts for primitive roles check
                    if not member.startswith('serviceAccount:'):
                        risk_score = self.calculate_risk_score(
                            VulnerabilityType.EXCESSIVE_PERMISSIONS,
                            {"production_env": True}
                        )
                        
                        finding = Finding(
                            finding_id=self.generate_finding_id(),
                            resource_id=asset.name,
                            resource_name=asset.name.split('/')[-1],
                            resource_type="IAM Policy",
                            vulnerability_type=VulnerabilityType.EXCESSIVE_PERMISSIONS,
                            risk_level=self.get_risk_level(risk_score),
                            title=f"Excessive IAM permissions detected",
                            description=f"Member '{member}' has primitive role '{role}' with broad permissions.",
                            remediation="Replace primitive roles with specific, least-privilege IAM roles.",
                            region="global",
                            account_id=self.project_id,
                            compliance_frameworks=get_compliance_frameworks(VulnerabilityType.EXCESSIVE_PERMISSIONS),
                            risk_score=risk_score,
                            tags={"service": "iam", "type": "policy"},
                            configuration={
                                "resource": asset.name,
                                "member": member,
                                "role": role,
                                "primitive_role": True
                            }
                        )
                        findings.append(finding)
        
        return findings
    
    def scan_network(self) -> List[Finding]:
        """Scan GCP network configurations."""
        findings = []
        
        try:
            compute_client = compute_v1.FirewallsClient(credentials=self.credentials_obj)
            
            # Get all firewall rules
            request = compute_v1.ListFirewallsRequest(project=self.project_id)
            firewall_rules = compute_client.list(request=request)
            
            for rule in firewall_rules:
                findings.extend(self._check_firewall_rule(rule))
                
        except Exception as e:
            logger.error("Error scanning GCP network", error=str(e))
        
        return findings
    
    def _check_firewall_rule(self, rule) -> List[Finding]:
        """Check firewall rule for security issues."""
        findings = []
        
        if rule.direction == 'INGRESS' and '0.0.0.0/0' in rule.source_ranges:
            allowed_ports = []
            
            for allowed in rule.allowed:
                ports = allowed.ports if allowed.ports else ['all']
                allowed_ports.extend(ports)
            
            # Check for dangerous open ports
            dangerous_ports = ['22', '3389', '1433', '3306', '5432']
            
            for port in allowed_ports:
                if port in dangerous_ports or port == 'all':
                    risk_score = self.calculate_risk_score(
                        VulnerabilityType.OPEN_SECURITY_GROUP,
                        {"public_access": True, "production_env": True}
                    )
                    
                    finding = Finding(
                        finding_id=self.generate_finding_id(),
                        resource_id=rule.name,
                        resource_name=rule.name,
                        resource_type="Firewall Rule",
                        vulnerability_type=VulnerabilityType.OPEN_SECURITY_GROUP,
                        risk_level=self.get_risk_level(risk_score),
                        title=f"Firewall rule '{rule.name}' allows unrestricted access",
                        description=f"Firewall rule allows ingress from 0.0.0.0/0 on port {port}.",
                        remediation="Restrict firewall rules to specific IP ranges and remove unnecessary open ports.",
                        region="global",
                        account_id=self.project_id,
                        compliance_frameworks=get_compliance_frameworks(VulnerabilityType.OPEN_SECURITY_GROUP),
                        risk_score=risk_score,
                        tags={"service": "compute", "type": "firewall"},
                        configuration={
                            "rule_name": rule.name,
                            "port": port,
                            "source_ranges": rule.source_ranges
                        }
                    )
                    findings.append(finding)
        
        return findings
    
    def scan_compute(self) -> List[Finding]:
        """Scan GCP Compute Engine resources."""
        findings = []
        
        try:
            compute_client = compute_v1.InstancesClient(credentials=self.credentials_obj)
            
            for region in self.regions:
                # Get zones in the region
                zones_client = compute_v1.ZonesClient(credentials=self.credentials_obj)
                zones_request = compute_v1.ListZonesRequest(
                    project=self.project_id,
                    filter=f"name:{region}*"
                )
                zones = zones_client.list(request=zones_request)
                
                for zone in zones:
                    zone_name = zone.name
                    
                    # Get instances in the zone
                    instances_request = compute_v1.ListInstancesRequest(
                        project=self.project_id,
                        zone=zone_name
                    )
                    instances = compute_client.list(request=instances_request)
                    
                    for instance in instances:
                        findings.extend(self._check_instance_configuration(instance, zone_name))
                        
        except Exception as e:
            logger.error("Error scanning GCP compute", error=str(e))
        
        return findings
    
    def _check_instance_configuration(self, instance, zone: str) -> List[Finding]:
        """Check instance configuration for security issues."""
        findings = []
        
        # Check if instance has external IP
        for network_interface in instance.network_interfaces:
            for access_config in network_interface.access_configs:
                if access_config.type_ == 'ONE_TO_ONE_NAT':
                    # Instance has external IP, check if it's necessary
                    risk_score = self.calculate_risk_score(
                        VulnerabilityType.INSECURE_NETWORK,
                        {"public_access": True}
                    )
                    
                    finding = Finding(
                        finding_id=self.generate_finding_id(),
                        resource_id=instance.name,
                        resource_name=instance.name,
                        resource_type="Compute Instance",
                        vulnerability_type=VulnerabilityType.INSECURE_NETWORK,
                        risk_level=self.get_risk_level(risk_score),
                        title=f"Instance '{instance.name}' has external IP",
                        description=f"The instance '{instance.name}' has an external IP address which increases attack surface.",
                        remediation="Consider removing external IP if not required, use Cloud NAT or load balancers for internet access.",
                        region=zone,
                        account_id=self.project_id,
                        compliance_frameworks=get_compliance_frameworks(VulnerabilityType.INSECURE_NETWORK),
                        risk_score=risk_score,
                        tags={"service": "compute", "type": "network"},
                        configuration={
                            "instance_name": instance.name,
                            "external_ip": access_config.nat_i_p,
                            "zone": zone
                        }
                    )
                    findings.append(finding)
        
        # Check disk encryption
        for disk in instance.disks:
            if disk.boot and not disk.disk_encryption_key:
                risk_score = self.calculate_risk_score(
                    VulnerabilityType.UNENCRYPTED_STORAGE,
                    {"sensitive_data": True, "production_env": True}
                )
                
                finding = Finding(
                    finding_id=self.generate_finding_id(),
                    resource_id=instance.name,
                    resource_name=instance.name,
                    resource_type="Compute Instance",
                    vulnerability_type=VulnerabilityType.UNENCRYPTED_STORAGE,
                    risk_level=self.get_risk_level(risk_score),
                    title=f"Instance '{instance.name}' boot disk not encrypted with CMEK",
                    description=f"The boot disk of instance '{instance.name}' is not encrypted with customer-managed keys.",
                    remediation="Use customer-managed encryption keys (CMEK) for enhanced disk encryption control.",
                    region=zone,
                    account_id=self.project_id,
                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.UNENCRYPTED_STORAGE),
                    risk_score=risk_score,
                    tags={"service": "compute", "type": "encryption"},
                    configuration={
                        "instance_name": instance.name,
                        "cmek_encryption": False,
                        "zone": zone
                    }
                )
                findings.append(finding)
        
        return findings
