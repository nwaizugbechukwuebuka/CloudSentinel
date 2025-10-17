"""Risk assessment and scoring engine for security findings."""

import math
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RiskWeights:
    """Risk calculation weights for different factors."""
    severity: float = 0.35
    confidence: float = 0.15
    exploitability: float = 0.20
    impact: float = 0.20
    exposure: float = 0.10


class RiskEngine:
    """Advanced risk assessment engine for cloud security findings."""

    def __init__(self):
        self.weights = RiskWeights()
        self.compliance_frameworks = {
            "cis": {
                "name": "CIS Benchmarks",
                "total_controls": 200,
                "weight": 1.0
            },
            "nist": {
                "name": "NIST Cybersecurity Framework",
                "total_controls": 98,
                "weight": 0.9
            },
            "iso27001": {
                "name": "ISO 27001",
                "total_controls": 114,
                "weight": 0.8
            },
            "soc2": {
                "name": "SOC 2",
                "total_controls": 64,
                "weight": 0.7
            }
        }

    def calculate_finding_risk(self, finding: Dict[str, Any]) -> float:
        """Calculate risk score for a security finding (0-10 scale)."""
        try:
            # Base severity scoring
            severity_scores = {
                "critical": 10.0,
                "high": 8.0,
                "medium": 5.0,
                "low": 2.0,
                "info": 1.0
            }
            
            severity_score = severity_scores.get(
                finding.get("severity", "medium").lower(), 5.0
            )
            
            # Confidence scoring
            confidence_scores = {
                "high": 1.0,
                "medium": 0.8,
                "low": 0.6
            }
            
            confidence_score = confidence_scores.get(
                finding.get("confidence", "medium").lower(), 0.8
            )
            
            # Exploitability scoring
            exploitability_scores = {
                "high": 1.0,
                "medium": 0.7,
                "low": 0.4,
                "none": 0.1
            }
            
            exploitability_score = exploitability_scores.get(
                finding.get("exploitability", "medium").lower(), 0.7
            )
            
            # Impact scoring
            impact_scores = {
                "high": 1.0,
                "medium": 0.7,
                "low": 0.4,
                "none": 0.1
            }
            
            impact_score = impact_scores.get(
                finding.get("impact", "medium").lower(), 0.7
            )
            
            # Exposure scoring (public vs private)
            exposure_score = 1.0 if finding.get("public_exposure", False) else 0.3
            
            # Calculate weighted risk score
            risk_score = (
                (severity_score * self.weights.severity) +
                (severity_score * confidence_score * self.weights.confidence) +
                (severity_score * exploitability_score * self.weights.exploitability) +
                (severity_score * impact_score * self.weights.impact) +
                (severity_score * exposure_score * self.weights.exposure)
            )
            
            # Apply compliance violation multiplier
            if finding.get("compliance_violation", False):
                risk_score *= 1.2
            
            # Ensure score is within bounds
            return min(max(risk_score, 0.0), 10.0)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 5.0  # Default medium risk

    def calculate_overall_risk(self, scan_results: List[Any]) -> Dict[str, Any]:
        """Calculate overall risk assessment for scan results."""
        try:
            if not scan_results:
                return {
                    "risk_score": 0.0,
                    "risk_level": "minimal",
                    "total_findings": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "recommendations": []
                }
            
            # Count findings by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
            
            total_risk_score = 0.0
            
            for result in scan_results:
                severity = getattr(result, 'severity', 'medium').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                risk_score = getattr(result, 'risk_score', 5.0)
                total_risk_score += risk_score
            
            # Calculate weighted average risk score
            if len(scan_results) > 0:
                # Weight critical and high findings more heavily
                weighted_score = (
                    (severity_counts["critical"] * 9.0) +
                    (severity_counts["high"] * 7.0) +
                    (severity_counts["medium"] * 4.0) +
                    (severity_counts["low"] * 2.0) +
                    (severity_counts["info"] * 1.0)
                ) / max(len(scan_results), 1)
                
                overall_risk = min(weighted_score, 10.0)
            else:
                overall_risk = 0.0
            
            risk_level = self._get_risk_level(overall_risk)
            
            return {
                "risk_score": round(overall_risk, 2),
                "risk_level": risk_level,
                "total_findings": len(scan_results),
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"],
                "recommendations": self._generate_recommendations(severity_counts, overall_risk)
            }
            
        except Exception as e:
            logger.error(f"Error calculating overall risk: {str(e)}")
            return {"risk_score": 0.0, "risk_level": "unknown", "total_findings": 0}

    def _get_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score."""
        if risk_score >= 9.0:
            return "critical"
        elif risk_score >= 7.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        elif risk_score >= 2.0:
            return "low"
        else:
            return "minimal"

    def calculate_compliance_score(
        self, 
        findings: List[Dict[str, Any]], 
        framework: str = "cis"
    ) -> Dict[str, Any]:
        """Calculate compliance score for a specific framework."""
        try:
            framework_info = self.compliance_frameworks.get(framework.lower())
            if not framework_info:
                raise ValueError(f"Unsupported compliance framework: {framework}")
            
            total_controls = framework_info["total_controls"]
            
            # Collect all compliance violations
            violations = set()
            for finding in findings:
                finding_violations = finding.get("compliance_violations", [])
                if isinstance(finding_violations, list):
                    violations.update(finding_violations)
            
            # Filter violations for this framework
            framework_violations = {
                v for v in violations 
                if v.upper().startswith(framework.upper())
            }
            
            # Calculate compliance percentage
            failed_controls = len(framework_violations)
            passed_controls = total_controls - failed_controls
            compliance_percentage = (passed_controls / total_controls) * 100
            
            return {
                "framework": framework_info["name"],
                "compliance_percentage": round(compliance_percentage, 2),
                "total_controls": total_controls,
                "passed_controls": passed_controls,
                "failed_controls": failed_controls,
                "failed_control_ids": list(framework_violations)
            }
            
        except Exception as e:
            logger.error(f"Error calculating compliance score: {str(e)}")
            return {
                "framework": framework,
                "compliance_percentage": 0.0,
                "total_controls": 0,
                "passed_controls": 0,
                "failed_controls": 0,
                "failed_control_ids": []
            }

    def generate_risk_trends(
        self, 
        historical_scans: List[Any], 
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """Generate risk trend data over time."""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Initialize daily risk scores
            trends = []
            current_date = start_date
            
            while current_date <= end_date:
                day_scans = [
                    scan for scan in historical_scans
                    if (hasattr(scan, 'created_at') and 
                        scan.created_at.date() == current_date.date())
                ]
                
                if day_scans:
                    # Calculate average risk score for the day
                    daily_risk = sum(
                        getattr(scan, 'risk_score', 0) for scan in day_scans
                    ) / len(day_scans)
                else:
                    daily_risk = 0.0
                
                trends.append({
                    "date": current_date.strftime("%Y-%m-%d"),
                    "risk_score": round(daily_risk, 2),
                    "scan_count": len(day_scans)
                })
                
                current_date += timedelta(days=1)
            
            return trends
            
        except Exception as e:
            logger.error(f"Error generating risk trends: {str(e)}")
            return []

    def calculate_security_posture(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall security posture assessment."""
        try:
            if not findings:
                return {
                    "posture_level": "unknown",
                    "improvement_score": 0.0,
                    "strengths": [],
                    "weaknesses": [],
                    "recommendations": []
                }
            
            # Calculate average risk score
            total_risk = sum(finding.get("risk_score", 5.0) for finding in findings)
            avg_risk = total_risk / len(findings)
            
            # Determine posture level
            if avg_risk <= 3.0:
                posture_level = "strong"
                improvement_score = 9.0
            elif avg_risk <= 5.0:
                posture_level = "good"
                improvement_score = 7.0
            elif avg_risk <= 7.0:
                posture_level = "fair"
                improvement_score = 5.0
            elif avg_risk <= 8.5:
                posture_level = "weak"
                improvement_score = 3.0
            else:
                posture_level = "poor"
                improvement_score = 1.0
            
            # Analyze findings by service
            service_risks = {}
            for finding in findings:
                service = finding.get("service", "unknown")
                if service not in service_risks:
                    service_risks[service] = []
                service_risks[service].append(finding.get("risk_score", 5.0))
            
            # Identify strengths and weaknesses
            strengths = []
            weaknesses = []
            
            for service, risks in service_risks.items():
                avg_service_risk = sum(risks) / len(risks)
                if avg_service_risk <= 4.0:
                    strengths.append(f"{service.upper()} security configuration")
                elif avg_service_risk >= 7.0:
                    weaknesses.append(f"{service.upper()} security issues")
            
            # Generate recommendations
            recommendations = self._generate_posture_recommendations(
                avg_risk, service_risks, findings
            )
            
            return {
                "posture_level": posture_level,
                "improvement_score": improvement_score,
                "average_risk": round(avg_risk, 2),
                "strengths": strengths,
                "weaknesses": weaknesses,
                "recommendations": recommendations
            }
            
        except Exception as e:
            logger.error(f"Error calculating security posture: {str(e)}")
            return {"posture_level": "unknown", "improvement_score": 0.0}

    def get_remediation_priority(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Determine remediation priority and SLA for a finding."""
        try:
            risk_score = finding.get("risk_score", 5.0)
            severity = finding.get("severity", "medium").lower()
            public_exposure = finding.get("public_exposure", False)
            exploitability = finding.get("exploitability", "medium").lower()
            
            # Determine priority level
            if (severity == "critical" or 
                (severity == "high" and public_exposure) or
                risk_score >= 9.0):
                priority_level = "immediate"
                sla_hours = 4
            elif severity == "high" or risk_score >= 7.0:
                priority_level = "high"
                sla_hours = 24
            elif severity == "medium" or risk_score >= 4.0:
                priority_level = "medium"
                sla_hours = 72
            else:
                priority_level = "low"
                sla_hours = 168  # 1 week
            
            # Generate reasoning
            factors = []
            if severity in ["critical", "high"]:
                factors.append(f"{severity} severity")
            if public_exposure:
                factors.append("public exposure")
            if exploitability == "high":
                factors.append("high exploitability")
            if risk_score >= 8.0:
                factors.append("high risk score")
            
            reasoning = "Priority based on: " + ", ".join(factors) if factors else "Standard priority assessment"
            
            return {
                "priority_level": priority_level,
                "sla_hours": sla_hours,
                "reasoning": reasoning,
                "estimated_effort": self._estimate_remediation_effort(finding)
            }
            
        except Exception as e:
            logger.error(f"Error determining remediation priority: {str(e)}")
            return {"priority_level": "medium", "sla_hours": 72}

    def calculate_risk_by_service(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Calculate risk breakdown by cloud service."""
        try:
            service_risks = {}
            
            for finding in findings:
                service = finding.get("service", "unknown")
                risk_score = finding.get("risk_score", 5.0)
                severity = finding.get("severity", "medium")
                
                if service not in service_risks:
                    service_risks[service] = {
                        "total_findings": 0,
                        "risk_scores": [],
                        "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    }
                
                service_risks[service]["total_findings"] += 1
                service_risks[service]["risk_scores"].append(risk_score)
                service_risks[service]["severities"][severity.lower()] += 1
            
            # Calculate averages and risk levels
            result = {}
            for service, data in service_risks.items():
                avg_risk = sum(data["risk_scores"]) / len(data["risk_scores"])
                max_risk = max(data["risk_scores"])
                
                result[service] = {
                    "finding_count": data["total_findings"],
                    "average_risk": round(avg_risk, 2),
                    "maximum_risk": round(max_risk, 2),
                    "risk_level": self._get_risk_level(avg_risk),
                    "severity_breakdown": data["severities"]
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Error calculating risk by service: {str(e)}")
            return {}

    def generate_executive_summary(self, scan_results: List[Any]) -> Dict[str, Any]:
        """Generate executive-level risk summary."""
        try:
            overall_risk = self.calculate_overall_risk(scan_results)
            
            # Get top findings (highest risk)
            top_findings = sorted(
                scan_results,
                key=lambda x: getattr(x, 'risk_score', 0),
                reverse=True
            )[:5]
            
            # Generate key findings summary
            key_findings = []
            for finding in top_findings:
                key_findings.append({
                    "title": getattr(finding, 'finding_type', 'Security Issue'),
                    "risk_score": getattr(finding, 'risk_score', 0),
                    "severity": getattr(finding, 'severity', 'medium'),
                    "service": getattr(finding, 'service', 'unknown'),
                    "description": f"{getattr(finding, 'finding_type', 'Issue')} detected in {getattr(finding, 'service', 'service')}"
                })
            
            # Generate recommendations
            recommendations = []
            if overall_risk["critical_count"] > 0:
                recommendations.append("Immediately address critical security findings")
            if overall_risk["high_count"] > 5:
                recommendations.append("Prioritize high-severity vulnerabilities")
            if overall_risk["risk_score"] > 7.0:
                recommendations.append("Implement comprehensive security review process")
            
            recommendations.append("Establish regular security scanning schedule")
            recommendations.append("Implement automated remediation for common issues")
            
            return {
                "overall_risk_level": overall_risk["risk_level"],
                "risk_score": overall_risk["risk_score"],
                "total_findings": overall_risk["total_findings"],
                "key_findings": key_findings,
                "recommendations": recommendations,
                "compliance_status": "Requires attention" if overall_risk["risk_score"] > 6.0 else "Acceptable",
                "summary": f"Security scan identified {overall_risk['total_findings']} findings with {overall_risk['critical_count']} critical issues requiring immediate attention."
            }
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            return {"overall_risk_level": "unknown", "risk_score": 0.0}

    def calculate_mttr_metrics(self, alerts: List[Any]) -> Dict[str, Any]:
        """Calculate Mean Time To Remediation metrics."""
        try:
            resolved_alerts = [
                alert for alert in alerts
                if (hasattr(alert, 'status') and alert.status == 'resolved' and
                    hasattr(alert, 'resolved_at') and alert.resolved_at and
                    hasattr(alert, 'created_at') and alert.created_at)
            ]
            
            if not resolved_alerts:
                return {
                    "overall_mttr_hours": 0,
                    "by_severity": {},
                    "resolution_rate": 0
                }
            
            # Calculate resolution times by severity
            by_severity = {}
            all_times = []
            
            for alert in resolved_alerts:
                resolution_time = (alert.resolved_at - alert.created_at).total_seconds() / 3600
                all_times.append(resolution_time)
                
                severity = getattr(alert, 'severity', 'medium')
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(resolution_time)
            
            # Calculate averages
            overall_mttr = sum(all_times) / len(all_times)
            severity_mttr = {
                severity: sum(times) / len(times)
                for severity, times in by_severity.items()
            }
            
            # Calculate resolution rate
            total_alerts = len(alerts)
            resolution_rate = (len(resolved_alerts) / total_alerts * 100) if total_alerts > 0 else 0
            
            return {
                "overall_mttr_hours": round(overall_mttr, 2),
                "by_severity": {k: round(v, 2) for k, v in severity_mttr.items()},
                "resolution_rate": round(resolution_rate, 2)
            }
            
        except Exception as e:
            logger.error(f"Error calculating MTTR metrics: {str(e)}")
            return {"overall_mttr_hours": 0, "by_severity": {}, "resolution_rate": 0}

    def _generate_recommendations(
        self, 
        severity_counts: Dict[str, int], 
        overall_risk: float
    ) -> List[str]:
        """Generate risk-based recommendations."""
        recommendations = []
        
        if severity_counts["critical"] > 0:
            recommendations.append(f"Address {severity_counts['critical']} critical findings immediately")
        
        if severity_counts["high"] > 3:
            recommendations.append("Implement systematic approach for high-severity issues")
        
        if overall_risk > 7.0:
            recommendations.append("Conduct comprehensive security architecture review")
        elif overall_risk > 5.0:
            recommendations.append("Enhance security monitoring and alerting")
        
        if sum(severity_counts.values()) > 50:
            recommendations.append("Consider automated remediation for common issues")
        
        recommendations.append("Establish regular security scanning schedule")
        
        return recommendations

    def _generate_posture_recommendations(
        self,
        avg_risk: float,
        service_risks: Dict[str, List[float]],
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate security posture improvement recommendations."""
        recommendations = []
        
        # Risk-based recommendations
        if avg_risk > 7.0:
            recommendations.append("Implement immediate security hardening measures")
        elif avg_risk > 5.0:
            recommendations.append("Enhance security configuration management")
        
        # Service-specific recommendations
        for service, risks in service_risks.items():
            avg_service_risk = sum(risks) / len(risks)
            if avg_service_risk > 7.0:
                recommendations.append(f"Review and strengthen {service.upper()} security controls")
        
        # Pattern-based recommendations
        public_exposures = sum(1 for f in findings if f.get("public_exposure", False))
        if public_exposures > 0:
            recommendations.append("Review and minimize public resource exposure")
        
        iam_issues = sum(1 for f in findings if "iam" in f.get("service", "").lower())
        if iam_issues > 5:
            recommendations.append("Implement least-privilege access controls")
        
        return recommendations

    def _estimate_remediation_effort(self, finding: Dict[str, Any]) -> str:
        """Estimate effort required for remediation."""
        finding_type = finding.get("finding_type", "").lower()
        severity = finding.get("severity", "medium").lower()
        
        if "bucket" in finding_type and "public" in finding_type:
            return "15 minutes"
        elif "iam" in finding_type and "policy" in finding_type:
            return "30 minutes"
        elif "security_group" in finding_type:
            return "20 minutes"
        elif severity == "critical":
            return "1-2 hours"
        elif severity == "high":
            return "2-4 hours"
        else:
            return "4-8 hours"
