"""Common utilities and base classes for cloud scanners."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import uuid
from datetime import datetime

from src.utils.logger import logger


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities that can be detected."""
    PUBLIC_BUCKET = "public_bucket"
    WEAK_IAM_POLICY = "weak_iam_policy"
    UNENCRYPTED_STORAGE = "unencrypted_storage"
    OPEN_SECURITY_GROUP = "open_security_group"
    MISSING_MFA = "missing_mfa"
    EXPOSED_DATABASE = "exposed_database"
    UNENCRYPTED_TRANSIT = "unencrypted_transit"
    WEAK_PASSWORD_POLICY = "weak_password_policy"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    MISSING_LOGGING = "missing_logging"
    INSECURE_NETWORK = "insecure_network"
    COMPLIANCE_VIOLATION = "compliance_violation"


@dataclass
class Finding:
    """Represents a security finding."""
    finding_id: str
    resource_id: str
    resource_name: str
    resource_type: str
    vulnerability_type: VulnerabilityType
    risk_level: str
    title: str
    description: str
    remediation: str
    region: str
    account_id: str
    compliance_frameworks: List[str]
    risk_score: float
    tags: Dict[str, Any]
    configuration: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_id": self.finding_id,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "vulnerability_type": self.vulnerability_type.value,
            "risk_level": self.risk_level,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "region": self.region,
            "account_id": self.account_id,
            "compliance_frameworks": self.compliance_frameworks,
            "risk_score": self.risk_score,
            "tags": self.tags,
            "configuration": self.configuration
        }


class CloudScanner(ABC):
    """Abstract base class for cloud security scanners."""
    
    def __init__(self, credentials: Dict[str, Any]):
        self.credentials = credentials
        self.findings: List[Finding] = []
    
    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with cloud provider."""
        pass
    
    @abstractmethod
    def scan_storage(self) -> List[Finding]:
        """Scan storage services for security issues."""
        pass
    
    @abstractmethod
    def scan_iam(self) -> List[Finding]:
        """Scan IAM policies and permissions."""
        pass
    
    @abstractmethod
    def scan_network(self) -> List[Finding]:
        """Scan network configurations."""
        pass
    
    @abstractmethod
    def scan_compute(self) -> List[Finding]:
        """Scan compute instances and configurations."""
        pass
    
    def generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        return str(uuid.uuid4())
    
    def calculate_risk_score(self, vulnerability_type: VulnerabilityType, 
                           severity_factors: Dict[str, Any]) -> float:
        """Calculate risk score based on vulnerability type and factors."""
        base_scores = {
            VulnerabilityType.PUBLIC_BUCKET: 8.0,
            VulnerabilityType.WEAK_IAM_POLICY: 7.5,
            VulnerabilityType.UNENCRYPTED_STORAGE: 6.0,
            VulnerabilityType.OPEN_SECURITY_GROUP: 8.5,
            VulnerabilityType.MISSING_MFA: 7.0,
            VulnerabilityType.EXPOSED_DATABASE: 9.0,
            VulnerabilityType.UNENCRYPTED_TRANSIT: 5.5,
            VulnerabilityType.WEAK_PASSWORD_POLICY: 6.5,
            VulnerabilityType.EXCESSIVE_PERMISSIONS: 7.0,
            VulnerabilityType.MISSING_LOGGING: 4.0,
            VulnerabilityType.INSECURE_NETWORK: 7.5,
            VulnerabilityType.COMPLIANCE_VIOLATION: 5.0
        }
        
        score = base_scores.get(vulnerability_type, 5.0)
        
        # Adjust based on factors
        if severity_factors.get("public_access", False):
            score += 1.0
        if severity_factors.get("sensitive_data", False):
            score += 0.5
        if severity_factors.get("production_env", False):
            score += 0.5
        
        return min(score, 10.0)
    
    def get_risk_level(self, risk_score: float) -> str:
        """Get risk level based on score."""
        if risk_score >= 8.0:
            return "critical"
        elif risk_score >= 6.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        elif risk_score >= 2.0:
            return "low"
        else:
            return "info"
    
    def scan_all(self) -> List[Finding]:
        """Perform comprehensive security scan."""
        logger.info("Starting comprehensive security scan", scanner=self.__class__.__name__)
        
        if not self.authenticate():
            logger.error("Authentication failed", scanner=self.__class__.__name__)
            return []
        
        all_findings = []
        
        # Run all scan types
        scan_methods = [
            ("Storage", self.scan_storage),
            ("IAM", self.scan_iam),
            ("Network", self.scan_network),
            ("Compute", self.scan_compute)
        ]
        
        for scan_name, scan_method in scan_methods:
            try:
                logger.info(f"Running {scan_name} scan", scanner=self.__class__.__name__)
                findings = scan_method()
                all_findings.extend(findings)
                logger.info(f"{scan_name} scan completed", 
                           scanner=self.__class__.__name__, 
                           findings_count=len(findings))
            except Exception as e:
                logger.error(f"{scan_name} scan failed", 
                           scanner=self.__class__.__name__, 
                           error=str(e))
        
        logger.info("Comprehensive scan completed", 
                   scanner=self.__class__.__name__, 
                   total_findings=len(all_findings))
        
        return all_findings


def get_compliance_frameworks(vulnerability_type: VulnerabilityType) -> List[str]:
    """Get applicable compliance frameworks for a vulnerability type."""
    frameworks_map = {
        VulnerabilityType.PUBLIC_BUCKET: ["CIS", "SOC2", "ISO27001", "GDPR"],
        VulnerabilityType.WEAK_IAM_POLICY: ["CIS", "SOC2", "ISO27001"],
        VulnerabilityType.UNENCRYPTED_STORAGE: ["PCI-DSS", "HIPAA", "SOC2", "GDPR"],
        VulnerabilityType.OPEN_SECURITY_GROUP: ["CIS", "SOC2", "ISO27001"],
        VulnerabilityType.MISSING_MFA: ["CIS", "SOC2", "ISO27001"],
        VulnerabilityType.EXPOSED_DATABASE: ["PCI-DSS", "HIPAA", "SOC2", "GDPR"],
        VulnerabilityType.UNENCRYPTED_TRANSIT: ["PCI-DSS", "HIPAA", "SOC2"],
        VulnerabilityType.WEAK_PASSWORD_POLICY: ["CIS", "SOC2", "ISO27001"],
        VulnerabilityType.EXCESSIVE_PERMISSIONS: ["CIS", "SOC2", "ISO27001"],
        VulnerabilityType.MISSING_LOGGING: ["SOC2", "ISO27001", "PCI-DSS"],
        VulnerabilityType.INSECURE_NETWORK: ["CIS", "SOC2", "ISO27001"],
        VulnerabilityType.COMPLIANCE_VIOLATION: ["SOC2", "ISO27001"]
    }
    
    return frameworks_map.get(vulnerability_type, ["CIS"])
