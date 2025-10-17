"""Scan API routes for CloudSentinel."""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

from src.api.database import get_db
from src.api.models.user import User, UserRole
from src.api.models.scan_result import CloudProvider, RiskLevel
from src.api.services.auth_services import get_current_active_user, require_role
from src.api.services.scan_service import scan_service
from src.utils.logger import logger

router = APIRouter()


# Pydantic models
class ScanRequest(BaseModel):
    provider: CloudProvider
    credentials: Dict[str, Any]
    scan_types: Optional[List[str]] = None  # ["storage", "iam", "network", "compute"]
    
    class Config:
        schema_extra = {
            "example": {
                "provider": "aws",
                "credentials": {
                    "access_key_id": "AKIA...",
                    "secret_access_key": "your-secret-key",
                    "region": "us-east-1"
                },
                "scan_types": ["storage", "iam", "network"]
            }
        }


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    estimated_duration: str


class ScanResultResponse(BaseModel):
    id: int
    scan_id: str
    provider: str
    region: str
    resource_type: str
    resource_name: str
    finding_type: str
    risk_level: str
    title: str
    description: str
    remediation: str
    risk_score: float
    created_at: str
    
    class Config:
        from_attributes = True


class ScanSummaryResponse(BaseModel):
    scan_id: str
    status: str
    total_findings: int
    risk_distribution: Dict[str, int]
    provider_distribution: Dict[str, int]
    resource_type_distribution: Dict[str, int]
    scan_date: Optional[str]
    completed_date: Optional[str]


@router.post("/start", response_model=ScanResponse)
async def start_scan(
    scan_request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ANALYST))
):
    """Start a new security scan."""
    try:
        scan_id = await scan_service.initiate_scan(
            db=db,
            provider=scan_request.provider,
            credentials=scan_request.credentials,
            user_id=current_user.id,
            scan_types=scan_request.scan_types
        )
        
        logger.info(
            "Scan initiated via API",
            scan_id=scan_id,
            user_id=current_user.id,
            provider=scan_request.provider.value
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status="initiated",
            message="Security scan has been started successfully",
            estimated_duration="5-15 minutes depending on resource count"
        )
        
    except Exception as e:
        logger.error("Failed to start scan", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start scan: {str(e)}"
        )


@router.get("/results/{scan_id}", response_model=List[ScanResultResponse])
async def get_scan_results(
    scan_id: str,
    risk_level: Optional[RiskLevel] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get results for a specific scan."""
    try:
        results = scan_service.get_scan_results(
            db=db,
            scan_id=scan_id,
            user_id=current_user.id,
            risk_level=risk_level,
            limit=limit,
            offset=offset
        )
        
        response_data = []
        for result in results:
            response_data.append(ScanResultResponse(
                id=result.id,
                scan_id=result.scan_id,
                provider=result.provider.value,
                region=result.region or "unknown",
                resource_type=result.resource_type,
                resource_name=result.resource_name,
                finding_type=result.finding_type,
                risk_level=result.risk_level.value,
                title=result.title,
                description=result.description,
                remediation=result.remediation,
                risk_score=result.risk_score or 0.0,
                created_at=result.created_at.isoformat()
            ))
        
        return response_data
        
    except Exception as e:
        logger.error("Failed to get scan results", error=str(e), scan_id=scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan results: {str(e)}"
        )


@router.get("/summary/{scan_id}", response_model=ScanSummaryResponse)
async def get_scan_summary(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get summary statistics for a scan."""
    try:
        summary = scan_service.get_scan_summary(db=db, scan_id=scan_id)
        
        if "error" in summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=summary["error"]
            )
        
        return ScanSummaryResponse(**summary)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan summary", error=str(e), scan_id=scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan summary: {str(e)}"
        )


@router.get("/history", response_model=List[ScanSummaryResponse])
async def get_scan_history(
    provider: Optional[CloudProvider] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get user's scan history."""
    try:
        # Get unique scan IDs for the user
        from src.api.models.scan_result import ScanResult
        
        query = db.query(ScanResult.scan_id).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type == "scan_job"
        ).distinct()
        
        if provider:
            query = query.filter(ScanResult.provider == provider)
        
        scan_ids = [row.scan_id for row in query.offset(offset).limit(limit).all()]
        
        # Get summaries for each scan
        summaries = []
        for scan_id in scan_ids:
            summary = scan_service.get_scan_summary(db=db, scan_id=scan_id)
            if "error" not in summary:
                summaries.append(ScanSummaryResponse(**summary))
        
        return summaries
        
    except Exception as e:
        logger.error("Failed to get scan history", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan history: {str(e)}"
        )


@router.get("/providers")
async def get_supported_providers():
    """Get list of supported cloud providers."""
    return {
        "providers": [
            {
                "name": "aws",
                "display_name": "Amazon Web Services",
                "required_credentials": [
                    "access_key_id",
                    "secret_access_key",
                    "region"
                ],
                "supported_scan_types": ["storage", "iam", "network", "compute"]
            },
            {
                "name": "azure",
                "display_name": "Microsoft Azure",
                "required_credentials": [
                    "client_id",
                    "client_secret",
                    "tenant_id",
                    "subscription_id"
                ],
                "supported_scan_types": ["storage", "network", "compute"]
            },
            {
                "name": "gcp",
                "display_name": "Google Cloud Platform",
                "required_credentials": [
                    "project_id",
                    "credentials_path"
                ],
                "supported_scan_types": ["storage", "iam", "network", "compute"]
            }
        ]
    }


@router.get("/stats")
async def get_scan_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get overall scan statistics for the user."""
    try:
        from src.api.models.scan_result import ScanResult
        from sqlalchemy import func, distinct
        
        # Total scans
        total_scans = db.query(func.count(distinct(ScanResult.scan_id))).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type == "scan_job"
        ).scalar()
        
        # Total findings
        total_findings = db.query(func.count(ScanResult.id)).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type != "scan_job"
        ).scalar()
        
        # Risk level distribution
        risk_stats = db.query(
            ScanResult.risk_level,
            func.count(ScanResult.id)
        ).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type != "scan_job"
        ).group_by(ScanResult.risk_level).all()
        
        risk_distribution = {risk.value: count for risk, count in risk_stats}
        
        # Provider distribution
        provider_stats = db.query(
            ScanResult.provider,
            func.count(ScanResult.id)
        ).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type != "scan_job"
        ).group_by(ScanResult.provider).all()
        
        provider_distribution = {provider.value: count for provider, count in provider_stats}
        
        return {
            "total_scans": total_scans or 0,
            "total_findings": total_findings or 0,
            "risk_distribution": risk_distribution,
            "provider_distribution": provider_distribution
        }
        
    except Exception as e:
        logger.error("Failed to get scan statistics", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan statistics: {str(e)}"
        )
