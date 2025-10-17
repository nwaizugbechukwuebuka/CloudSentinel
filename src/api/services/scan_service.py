"""Scanning service for CloudSentinel."""

from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor

from src.api.models.scan_result import ScanResult, CloudProvider, ScanStatus, RiskLevel
from src.api.models.alert import Alert, AlertStatus, AlertSeverity
from src.scanner.aws_scanner import AWSScanner
from src.scanner.azure_scanner import AzureScanner
from src.scanner.gcp_scanner import GCPScanner
from src.utils.config import settings
from src.utils.logger import logger


class ScanService:
    """Service for managing cloud security scans."""
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=settings.MAX_CONCURRENT_SCANS)
    
    async def initiate_scan(
        self,
        db: Session,
        provider: CloudProvider,
        credentials: Dict[str, Any],
        user_id: int,
        scan_types: List[str] = None
    ) -> str:
        """Initiate a new security scan."""
        scan_id = str(uuid.uuid4())
        
        logger.info(
            "Initiating security scan",
            scan_id=scan_id,
            provider=provider.value,
            user_id=user_id
        )
        
        # Create initial scan record
        initial_scan = ScanResult(
            scan_id=scan_id,
            provider=provider,
            status=ScanStatus.PENDING,
            user_id=user_id,
            resource_type="scan_job",
            resource_id=scan_id,
            resource_name=f"{provider.value}_scan_{scan_id[:8]}",
            finding_type="scan_job",
            risk_level=RiskLevel.INFO,
            title=f"Security scan initiated for {provider.value}",
            description=f"Comprehensive security scan for {provider.value} cloud resources",
            remediation="N/A - Scan in progress"
        )
        
        db.add(initial_scan)
        db.commit()
        db.refresh(initial_scan)
        
        # Schedule background scan
        asyncio.create_task(
            self._execute_scan_async(db, scan_id, provider, credentials, user_id, scan_types)
        )
        
        return scan_id
    
    async def _execute_scan_async(
        self,
        db: Session,
        scan_id: str,
        provider: CloudProvider,
        credentials: Dict[str, Any],
        user_id: int,
        scan_types: List[str] = None
    ):
        """Execute security scan asynchronously."""
        try:
            # Update scan status to running
            scan_record = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
            if scan_record:
                scan_record.status = ScanStatus.RUNNING
                db.commit()
            
            # Execute scan in thread pool
            loop = asyncio.get_event_loop()
            findings = await loop.run_in_executor(
                self.executor,
                self._execute_scan_sync,
                provider,
                credentials,
                scan_types
            )
            
            # Process findings
            await self._process_findings(db, scan_id, findings, user_id)
            
            # Update scan status to completed
            if scan_record:
                scan_record.status = ScanStatus.COMPLETED
                db.commit()
            
            logger.info(
                "Security scan completed",
                scan_id=scan_id,
                findings_count=len(findings)
            )
            
        except Exception as e:
            logger.error(
                "Security scan failed",
                scan_id=scan_id,
                error=str(e)
            )
            
            # Update scan status to failed
            scan_record = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
            if scan_record:
                scan_record.status = ScanStatus.FAILED
                scan_record.description = f"Scan failed: {str(e)}"
                db.commit()
    
    def _execute_scan_sync(
        self,
        provider: CloudProvider,
        credentials: Dict[str, Any],
        scan_types: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Execute security scan synchronously."""
        
        # Get appropriate scanner
        scanner = self._get_scanner(provider, credentials)
        if not scanner:
            raise Exception(f"Failed to initialize scanner for {provider.value}")
        
        # Execute scan
        if scan_types:
            findings = []
            if "storage" in scan_types:
                findings.extend(scanner.scan_storage())
            if "iam" in scan_types:
                findings.extend(scanner.scan_iam())
            if "network" in scan_types:
                findings.extend(scanner.scan_network())
            if "compute" in scan_types:
                findings.extend(scanner.scan_compute())
        else:
            findings = scanner.scan_all()
        
        # Convert findings to dictionaries
        return [finding.to_dict() for finding in findings]
    
    def _get_scanner(self, provider: CloudProvider, credentials: Dict[str, Any]):
        """Get appropriate scanner instance for provider."""
        
        if provider == CloudProvider.AWS:
            return AWSScanner(credentials)
        elif provider == CloudProvider.AZURE:
            return AzureScanner(credentials)
        elif provider == CloudProvider.GCP:
            return GCPScanner(credentials)
        else:
            raise ValueError(f"Unsupported cloud provider: {provider.value}")
    
    async def _process_findings(
        self,
        db: Session,
        scan_id: str,
        findings: List[Dict[str, Any]],
        user_id: int
    ):
        """Process scan findings and create database records."""
        
        for finding_data in findings:
            try:
                # Create scan result record
                scan_result = ScanResult(
                    scan_id=scan_id,
                    provider=CloudProvider(finding_data["vulnerability_type"].split("_")[0] if "_" in finding_data["vulnerability_type"] else "aws"),
                    region=finding_data.get("region", "unknown"),
                    account_id=finding_data.get("account_id", "unknown"),
                    status=ScanStatus.COMPLETED,
                    resource_type=finding_data["resource_type"],
                    resource_id=finding_data["resource_id"],
                    resource_name=finding_data["resource_name"],
                    finding_type=finding_data["vulnerability_type"],
                    risk_level=RiskLevel(finding_data["risk_level"]),
                    title=finding_data["title"],
                    description=finding_data["description"],
                    remediation=finding_data["remediation"],
                    compliance_frameworks=finding_data["compliance_frameworks"],
                    risk_score=finding_data["risk_score"],
                    tags=finding_data["tags"],
                    configuration=finding_data["configuration"],
                    user_id=user_id
                )
                
                db.add(scan_result)
                db.flush()  # Get the ID
                
                # Create alert for high/critical findings
                if scan_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    alert = Alert(
                        alert_id=str(uuid.uuid4()),
                        title=f"Security Alert: {scan_result.title}",
                        description=scan_result.description,
                        severity=AlertSeverity.CRITICAL if scan_result.risk_level == RiskLevel.CRITICAL else AlertSeverity.HIGH,
                        risk_level=scan_result.risk_level,
                        category="security_finding",
                        status=AlertStatus.OPEN,
                        scan_result_id=scan_result.id,
                        remediation_steps=scan_result.remediation,
                        remediation_priority=5 if scan_result.risk_level == RiskLevel.CRITICAL else 3
                    )
                    db.add(alert)
                
            except Exception as e:
                logger.error(
                    "Error processing finding",
                    finding_id=finding_data.get("finding_id"),
                    error=str(e)
                )
        
        db.commit()
    
    def get_scan_results(
        self,
        db: Session,
        scan_id: Optional[str] = None,
        user_id: Optional[int] = None,
        provider: Optional[CloudProvider] = None,
        risk_level: Optional[RiskLevel] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[ScanResult]:
        """Get scan results with optional filtering."""
        
        query = db.query(ScanResult)
        
        if scan_id:
            query = query.filter(ScanResult.scan_id == scan_id)
        if user_id:
            query = query.filter(ScanResult.user_id == user_id)
        if provider:
            query = query.filter(ScanResult.provider == provider)
        if risk_level:
            query = query.filter(ScanResult.risk_level == risk_level)
        
        # Exclude scan job records
        query = query.filter(ScanResult.resource_type != "scan_job")
        
        return query.offset(offset).limit(limit).all()
    
    def get_scan_summary(
        self,
        db: Session,
        scan_id: str
    ) -> Dict[str, Any]:
        """Get summary statistics for a scan."""
        
        results = db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id,
            ScanResult.resource_type != "scan_job"
        ).all()
        
        if not results:
            return {"error": "Scan not found or no results"}
        
        # Calculate statistics
        total_findings = len(results)
        risk_distribution = {}
        provider_distribution = {}
        resource_type_distribution = {}
        
        for result in results:
            # Risk level distribution
            risk_level = result.risk_level.value
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
            
            # Provider distribution
            provider = result.provider.value
            provider_distribution[provider] = provider_distribution.get(provider, 0) + 1
            
            # Resource type distribution
            resource_type = result.resource_type
            resource_type_distribution[resource_type] = resource_type_distribution.get(resource_type, 0) + 1
        
        # Get scan metadata
        scan_job = db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id,
            ScanResult.resource_type == "scan_job"
        ).first()
        
        return {
            "scan_id": scan_id,
            "status": scan_job.status.value if scan_job else "unknown",
            "total_findings": total_findings,
            "risk_distribution": risk_distribution,
            "provider_distribution": provider_distribution,
            "resource_type_distribution": resource_type_distribution,
            "scan_date": scan_job.created_at.isoformat() if scan_job else None,
            "completed_date": scan_job.updated_at.isoformat() if scan_job and scan_job.status == ScanStatus.COMPLETED else None
        }


# Global scan service instance
scan_service = ScanService()
