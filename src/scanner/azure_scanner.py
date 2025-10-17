"""Azure security scanner for CloudSentinel."""

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError
from typing import Dict, List, Any
from src.scanner.common import CloudScanner, Finding, VulnerabilityType, get_compliance_frameworks
from src.utils.logger import logger


class AzureScanner(CloudScanner):
    """Azure security scanner implementation."""
    
    def __init__(self, credentials: Dict[str, Any]):
        super().__init__(credentials)
        self.credential = None
        self.subscription_id = credentials.get('subscription_id')
        self.locations = ['eastus', 'westus2', 'westeurope', 'southeastasia']
    
    def authenticate(self) -> bool:
        """Authenticate with Azure using provided credentials."""
        try:
            if all(key in self.credentials for key in ['client_id', 'client_secret', 'tenant_id']):
                self.credential = ClientSecretCredential(
                    tenant_id=self.credentials['tenant_id'],
                    client_id=self.credentials['client_id'],
                    client_secret=self.credentials['client_secret']
                )
            else:
                # Use default credentials (managed identity, az cli, etc.)
                self.credential = DefaultAzureCredential()
            
            # Test authentication by listing resource groups
            resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            list(resource_client.resource_groups.list())
            
            logger.info("Azure authentication successful", subscription_id=self.subscription_id)
            return True
            
        except (ClientAuthenticationError, Exception) as e:
            logger.error("Azure authentication failed", error=str(e))
            return False
    
    def scan_storage(self) -> List[Finding]:
        """Scan Azure Storage accounts for security issues."""
        findings = []
        
        try:
            storage_client = StorageManagementClient(self.credential, self.subscription_id)
            
            # Get all storage accounts
            storage_accounts = list(storage_client.storage_accounts.list())
            
            for account in storage_accounts:
                account_name = account.name
                resource_group = account.id.split('/')[4]  # Extract RG from resource ID
                location = account.location
                
                try:
                    # Check public access
                    public_findings = self._check_storage_public_access(storage_client, account_name, resource_group, location)
                    findings.extend(public_findings)
                    
                    # Check encryption
                    encryption_findings = self._check_storage_encryption(account, location)
                    findings.extend(encryption_findings)
                    
                    # Check secure transfer
                    secure_transfer_findings = self._check_secure_transfer(account, location)
                    findings.extend(secure_transfer_findings)
                    
                except Exception as e:
                    logger.warning("Error scanning storage account", account=account_name, error=str(e))
                    
        except Exception as e:
            logger.error("Error listing Azure storage accounts", error=str(e))
        
        return findings
    
    def _check_storage_public_access(self, storage_client, account_name: str, resource_group: str, location: str) -> List[Finding]:
        """Check storage account for public access issues."""
        findings = []
        
        try:
            account = storage_client.storage_accounts.get_properties(resource_group, account_name)
            
            # Check if public blob access is allowed
            if (account.allow_blob_public_access is None or account.allow_blob_public_access):
                risk_score = self.calculate_risk_score(
                    VulnerabilityType.PUBLIC_BUCKET,
                    {"public_access": True, "production_env": True}
                )
                
                finding = Finding(
                    finding_id=self.generate_finding_id(),
                    resource_id=account.id,
                    resource_name=account_name,
                    resource_type="Storage Account",
                    vulnerability_type=VulnerabilityType.PUBLIC_BUCKET,
                    risk_level=self.get_risk_level(risk_score),
                    title=f"Storage Account '{account_name}' allows public blob access",
                    description=f"The storage account '{account_name}' is configured to allow public blob access.",
                    remediation="Disable public blob access unless specifically required for public content.",
                    region=location,
                    account_id=self.subscription_id,
                    compliance_frameworks=get_compliance_frameworks(VulnerabilityType.PUBLIC_BUCKET),
                    risk_score=risk_score,
                    tags={"service": "storage", "type": "access"},
                    configuration={"account_name": account_name, "public_blob_access": True}
                )
                findings.append(finding)
                
        except Exception as e:
            logger.warning("Error checking storage public access", account=account_name, error=str(e))
        
        return findings
    
    def _check_storage_encryption(self, account, location: str) -> List[Finding]:
        """Check storage account encryption configuration."""
        findings = []
        
        # Check if customer-managed keys are used
        encryption = account.encryption
        if not encryption or not encryption.key_source or encryption.key_source != 'Microsoft.Keyvault':
            risk_score = self.calculate_risk_score(
                VulnerabilityType.UNENCRYPTED_STORAGE,
                {"sensitive_data": True}
            )
            
            finding = Finding(
                finding_id=self.generate_finding_id(),
                resource_id=account.id,
                resource_name=account.name,
                resource_type="Storage Account",
                vulnerability_type=VulnerabilityType.UNENCRYPTED_STORAGE,
                risk_level=self.get_risk_level(risk_score),
                title=f"Storage Account '{account.name}' not using customer-managed keys",
                description=f"The storage account '{account.name}' is using Microsoft-managed keys instead of customer-managed keys.",
                remediation="Consider using customer-managed keys stored in Azure Key Vault for enhanced security control.",
                region=location,
                account_id=self.subscription_id,
                compliance_frameworks=get_compliance_frameworks(VulnerabilityType.UNENCRYPTED_STORAGE),
                risk_score=risk_score,
                tags={"service": "storage", "type": "encryption"},
                configuration={"account_name": account.name, "customer_managed_keys": False}
            )
            findings.append(finding)
        
        return findings
    
    def _check_secure_transfer(self, account, location: str) -> List[Finding]:
        """Check storage account secure transfer requirement."""
        findings = []
        
        if not account.enable_https_traffic_only:
            risk_score = self.calculate_risk_score(
                VulnerabilityType.UNENCRYPTED_TRANSIT,
                {"production_env": True}
            )
            
            finding = Finding(
                finding_id=self.generate_finding_id(),
                resource_id=account.id,
                resource_name=account.name,
                resource_type="Storage Account",
                vulnerability_type=VulnerabilityType.UNENCRYPTED_TRANSIT,
                risk_level=self.get_risk_level(risk_score),
                title=f"Storage Account '{account.name}' allows insecure transfer",
                description=f"The storage account '{account.name}' does not enforce HTTPS-only traffic.",
                remediation="Enable 'Secure transfer required' to enforce HTTPS-only access.",
                region=location,
                account_id=self.subscription_id,
                compliance_frameworks=get_compliance_frameworks(VulnerabilityType.UNENCRYPTED_TRANSIT),
                risk_score=risk_score,
                tags={"service": "storage", "type": "transfer"},
                configuration={"account_name": account.name, "https_only": False}
            )
            findings.append(finding)
        
        return findings
    
    def scan_iam(self) -> List[Finding]:
        """Scan Azure IAM (Azure AD) for security issues."""
        findings = []
        
        # Azure AD scanning would require Microsoft Graph API permissions
        # For this implementation, we'll focus on resource-level IAM
        logger.info("Azure IAM scanning requires additional Graph API permissions")
        
        return findings
    
    def scan_network(self) -> List[Finding]:
        """Scan Azure network configurations."""
        findings = []
        
        try:
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            
            # Get all network security groups
            nsgs = list(network_client.network_security_groups.list_all())
            
            for nsg in nsgs:
                nsg_name = nsg.name
                resource_group = nsg.id.split('/')[4]
                location = nsg.location
                
                # Check security rules
                findings.extend(self._check_network_security_rules(nsg, location))
                
        except Exception as e:
            logger.error("Error scanning Azure network", error=str(e))
        
        return findings
    
    def _check_network_security_rules(self, nsg, location: str) -> List[Finding]:
        """Check network security group rules."""
        findings = []
        
        for rule in nsg.security_rules:
            if (rule.access == 'Allow' and 
                rule.direction == 'Inbound' and
                '*' in (rule.source_address_prefix or '')):
                
                # Check for dangerous ports
                dangerous_ports = ['22', '3389', '1433', '3306', '5432']
                
                for port in dangerous_ports:
                    if (rule.destination_port_range == port or 
                        rule.destination_port_range == '*' or
                        (rule.destination_port_ranges and port in rule.destination_port_ranges)):
                        
                        risk_score = self.calculate_risk_score(
                            VulnerabilityType.OPEN_SECURITY_GROUP,
                            {"public_access": True, "production_env": True}
                        )
                        
                        finding = Finding(
                            finding_id=self.generate_finding_id(),
                            resource_id=nsg.id,
                            resource_name=nsg.name,
                            resource_type="Network Security Group",
                            vulnerability_type=VulnerabilityType.OPEN_SECURITY_GROUP,
                            risk_level=self.get_risk_level(risk_score),
                            title=f"NSG '{nsg.name}' allows unrestricted access to port {port}",
                            description=f"Network security group rule allows inbound access from any source to port {port}.",
                            remediation="Restrict NSG rules to specific IP ranges and remove unnecessary open ports.",
                            region=location,
                            account_id=self.subscription_id,
                            compliance_frameworks=get_compliance_frameworks(VulnerabilityType.OPEN_SECURITY_GROUP),
                            risk_score=risk_score,
                            tags={"service": "network", "type": "security_group"},
                            configuration={
                                "nsg_name": nsg.name,
                                "rule_name": rule.name,
                                "port": port,
                                "source": rule.source_address_prefix
                            }
                        )
                        findings.append(finding)
        
        return findings
    
    def scan_compute(self) -> List[Finding]:
        """Scan Azure compute resources."""
        findings = []
        
        try:
            compute_client = ComputeManagementClient(self.credential, self.subscription_id)
            
            # Get all virtual machines
            vms = list(compute_client.virtual_machines.list_all())
            
            for vm in vms:
                vm_name = vm.name
                resource_group = vm.id.split('/')[4]
                location = vm.location
                
                # Check OS disk encryption
                findings.extend(self._check_vm_disk_encryption(vm, location))
                
        except Exception as e:
            logger.error("Error scanning Azure compute", error=str(e))
        
        return findings
    
    def _check_vm_disk_encryption(self, vm, location: str) -> List[Finding]:
        """Check VM disk encryption."""
        findings = []
        
        os_disk = vm.storage_profile.os_disk
        
        # Check if disk encryption is enabled
        if not os_disk.encryption_settings or not os_disk.encryption_settings.enabled:
            risk_score = self.calculate_risk_score(
                VulnerabilityType.UNENCRYPTED_STORAGE,
                {"sensitive_data": True, "production_env": True}
            )
            
            finding = Finding(
                finding_id=self.generate_finding_id(),
                resource_id=vm.id,
                resource_name=vm.name,
                resource_type="Virtual Machine",
                vulnerability_type=VulnerabilityType.UNENCRYPTED_STORAGE,
                risk_level=self.get_risk_level(risk_score),
                title=f"VM '{vm.name}' disk not encrypted",
                description=f"The virtual machine '{vm.name}' does not have disk encryption enabled.",
                remediation="Enable Azure Disk Encryption to protect data at rest.",
                region=location,
                account_id=self.subscription_id,
                compliance_frameworks=get_compliance_frameworks(VulnerabilityType.UNENCRYPTED_STORAGE),
                risk_score=risk_score,
                tags={"service": "compute", "type": "encryption"},
                configuration={"vm_name": vm.name, "disk_encryption": False}
            )
            findings.append(finding)
        
        return findings
