"""
Report Builder for CloudSentinel
Generates comprehensive security reports from scan results and findings.
"""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
import logging

# Import reporting libraries
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ReportMetadata:
    """Metadata for report generation"""
    title: str
    subtitle: str
    generated_at: str
    scan_period_start: str
    scan_period_end: str
    cloud_providers: List[str]
    total_scans: int
    total_findings: int
    report_type: str
    organization: str = "CloudSentinel Security"
    logo_path: Optional[str] = None

@dataclass
class FindingSummary:
    """Summary of security findings"""
    severity: str
    count: int
    percentage: float
    top_categories: List[Dict[str, Any]]
    trend: str  # 'increasing', 'decreasing', 'stable'

@dataclass
class ComplianceScore:
    """Compliance framework scoring"""
    framework: str
    score: float
    passed_controls: int
    total_controls: int
    critical_failures: List[str]

class ReportBuilder:
    """
    Generates comprehensive security reports from CloudSentinel scan data.
    Supports multiple output formats: PDF, JSON, CSV, Excel.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.styles = self._initialize_styles()
        
    def _initialize_styles(self) -> Dict:
        """Initialize report styling"""
        if not REPORTLAB_AVAILABLE:
            return {}
            
        styles = getSampleStyleSheet()
        custom_styles = {
            'title': ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.HexColor('#1f2937'),
                alignment=1  # Center
            ),
            'heading1': ParagraphStyle(
                'CustomH1',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=12,
                textColor=colors.HexColor('#374151')
            ),
            'heading2': ParagraphStyle(
                'CustomH2',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=8,
                textColor=colors.HexColor('#4b5563')
            ),
            'body': ParagraphStyle(
                'CustomBody',
                parent=styles['Normal'],
                fontSize=10,
                spaceAfter=6
            ),
            'critical': ParagraphStyle(
                'Critical',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.red,
                backColor=colors.HexColor('#fef2f2')
            ),
            'high': ParagraphStyle(
                'High',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#dc2626'),
                backColor=colors.HexColor('#fef2f2')
            ),
            'medium': ParagraphStyle(
                'Medium',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#d97706'),
                backColor=colors.HexColor('#fffbeb')
            ),
            'low': ParagraphStyle(
                'Low',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#2563eb'),
                backColor=colors.HexColor('#eff6ff')
            )
        }
        
        return {**styles, **custom_styles}
    
    def generate_executive_summary_report(
        self,
        scan_data: List[Dict],
        findings_data: List[Dict],
        metadata: ReportMetadata,
        output_format: str = 'pdf'
    ) -> str:
        """Generate executive summary report"""
        
        logger.info(f"Generating executive summary report in {output_format} format")
        
        # Analyze data
        summary_data = self._analyze_executive_data(scan_data, findings_data)
        
        if output_format.lower() == 'pdf':
            return self._generate_executive_pdf(summary_data, metadata)
        elif output_format.lower() == 'json':
            return self._generate_executive_json(summary_data, metadata)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def generate_detailed_technical_report(
        self,
        scan_data: List[Dict],
        findings_data: List[Dict],
        metadata: ReportMetadata,
        include_remediation: bool = True,
        output_format: str = 'pdf'
    ) -> str:
        """Generate detailed technical report"""
        
        logger.info(f"Generating detailed technical report in {output_format} format")
        
        # Analyze data
        detailed_data = self._analyze_detailed_data(scan_data, findings_data, include_remediation)
        
        if output_format.lower() == 'pdf':
            return self._generate_detailed_pdf(detailed_data, metadata)
        elif output_format.lower() == 'json':
            return self._generate_detailed_json(detailed_data, metadata)
        elif output_format.lower() == 'excel' and PANDAS_AVAILABLE:
            return self._generate_detailed_excel(detailed_data, metadata)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def generate_compliance_report(
        self,
        scan_data: List[Dict],
        findings_data: List[Dict],
        framework: str,
        metadata: ReportMetadata,
        output_format: str = 'pdf'
    ) -> str:
        """Generate compliance framework report"""
        
        logger.info(f"Generating {framework} compliance report in {output_format} format")
        
        # Analyze compliance data
        compliance_data = self._analyze_compliance_data(scan_data, findings_data, framework)
        
        if output_format.lower() == 'pdf':
            return self._generate_compliance_pdf(compliance_data, metadata, framework)
        elif output_format.lower() == 'json':
            return self._generate_compliance_json(compliance_data, metadata, framework)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def generate_trend_analysis_report(
        self,
        historical_scan_data: List[Dict],
        historical_findings_data: List[Dict],
        metadata: ReportMetadata,
        period_days: int = 30,
        output_format: str = 'pdf'
    ) -> str:
        """Generate trend analysis report"""
        
        logger.info(f"Generating trend analysis report for {period_days} days in {output_format} format")
        
        # Analyze trends
        trend_data = self._analyze_trend_data(historical_scan_data, historical_findings_data, period_days)
        
        if output_format.lower() == 'pdf':
            return self._generate_trend_pdf(trend_data, metadata)
        elif output_format.lower() == 'json':
            return self._generate_trend_json(trend_data, metadata)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _analyze_executive_data(self, scan_data: List[Dict], findings_data: List[Dict]) -> Dict:
        """Analyze data for executive summary"""
        
        # Calculate key metrics
        total_scans = len(scan_data)
        total_findings = len(findings_data)
        
        # Severity breakdown
        severity_counts = {}
        for finding in findings_data:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Risk score calculation
        risk_scores = [scan.get('risk_score', 0) for scan in scan_data if scan.get('risk_score')]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Cloud provider breakdown
        provider_counts = {}
        for scan in scan_data:
            provider = scan.get('cloud_provider', 'unknown')
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        # Top finding categories
        category_counts = {}
        for finding in findings_data:
            category = finding.get('category', 'uncategorized')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Critical findings requiring immediate attention
        critical_findings = [
            finding for finding in findings_data 
            if finding.get('severity') == 'critical'
        ][:10]
        
        return {
            'summary': {
                'total_scans': total_scans,
                'total_findings': total_findings,
                'avg_risk_score': round(avg_risk_score, 2),
                'critical_findings_count': len([f for f in findings_data if f.get('severity') == 'critical']),
                'high_findings_count': len([f for f in findings_data if f.get('severity') == 'high'])
            },
            'severity_breakdown': severity_counts,
            'provider_breakdown': provider_counts,
            'top_categories': top_categories,
            'critical_findings': critical_findings,
            'recommendations': self._generate_executive_recommendations(severity_counts, avg_risk_score)
        }
    
    def _analyze_detailed_data(self, scan_data: List[Dict], findings_data: List[Dict], include_remediation: bool) -> Dict:
        """Analyze data for detailed technical report"""
        
        # Group findings by various criteria
        findings_by_provider = {}
        findings_by_service = {}
        findings_by_resource = {}
        
        for finding in findings_data:
            provider = finding.get('cloud_provider', 'unknown')
            service = finding.get('service_name', 'unknown')
            resource = finding.get('resource_id', 'unknown')
            
            if provider not in findings_by_provider:
                findings_by_provider[provider] = []
            findings_by_provider[provider].append(finding)
            
            if service not in findings_by_service:
                findings_by_service[service] = []
            findings_by_service[service].append(finding)
            
            if resource not in findings_by_resource:
                findings_by_resource[resource] = []
            findings_by_resource[resource].append(finding)
        
        # Remediation analysis if requested
        remediation_analysis = {}
        if include_remediation:
            remediation_analysis = self._analyze_remediation_efforts(findings_data)
        
        return {
            'findings_by_provider': findings_by_provider,
            'findings_by_service': findings_by_service,
            'findings_by_resource': findings_by_resource,
            'remediation_analysis': remediation_analysis,
            'detailed_scan_results': scan_data,
            'vulnerability_details': self._extract_vulnerability_details(findings_data)
        }
    
    def _analyze_compliance_data(self, scan_data: List[Dict], findings_data: List[Dict], framework: str) -> Dict:
        """Analyze data for compliance reporting"""
        
        # Compliance framework mappings
        compliance_mappings = {
            'CIS': {
                'controls': [
                    '1.1 - Maintain Inventory of Authorized Devices',
                    '1.2 - Maintain Inventory of Authorized Software',
                    '2.1 - Maintain Inventory and Control of Hardware Assets',
                    '3.1 - Run Automated Vulnerability Scanning Tools',
                    '4.1 - Maintain Secure Configurations',
                    '5.1 - Establish Secure Configurations',
                    '6.1 - Maintain Inventory of Authorized Software',
                    '7.1 - Implement Email and Web Browser Protections',
                    '8.1 - Implement Malware Defenses',
                    '9.1 - Limitation and Control of Network Ports'
                ]
            },
            'NIST': {
                'controls': [
                    'AC-1 - Access Control Policy and Procedures',
                    'AC-2 - Account Management',
                    'AU-1 - Audit and Accountability Policy and Procedures',
                    'CA-1 - Security Assessment and Authorization',
                    'CM-1 - Configuration Management Policy and Procedures',
                    'CP-1 - Contingency Planning Policy and Procedures',
                    'IA-1 - Identification and Authentication Policy',
                    'IR-1 - Incident Response Policy and Procedures',
                    'MA-1 - System Maintenance Policy and Procedures',
                    'MP-1 - Media Protection Policy and Procedures'
                ]
            },
            'SOC2': {
                'controls': [
                    'CC1.1 - Control Environment',
                    'CC2.1 - Communication and Information',
                    'CC3.1 - Risk Assessment',
                    'CC4.1 - Monitoring Activities',
                    'CC5.1 - Control Activities',
                    'A1.1 - Availability',
                    'C1.1 - Confidentiality',
                    'P1.1 - Processing Integrity',
                    'PI1.1 - Privacy'
                ]
            }
        }
        
        controls = compliance_mappings.get(framework, {}).get('controls', [])
        
        # Map findings to compliance controls
        compliance_results = {}
        for control in controls:
            compliance_results[control] = {
                'status': 'pass',  # Default to pass
                'findings': [],
                'risk_score': 0
            }
        
        # Process findings against controls
        for finding in findings_data:
            # Simple mapping logic - in production, this would be more sophisticated
            finding_type = finding.get('finding_type', '').lower()
            
            # Map to relevant controls based on finding type
            relevant_controls = self._map_finding_to_controls(finding_type, framework)
            
            for control in relevant_controls:
                if control in compliance_results:
                    compliance_results[control]['findings'].append(finding)
                    compliance_results[control]['status'] = 'fail'
                    compliance_results[control]['risk_score'] += finding.get('risk_score', 1)
        
        # Calculate overall compliance score
        passed_controls = len([c for c in compliance_results.values() if c['status'] == 'pass'])
        total_controls = len(controls)
        compliance_score = (passed_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            'framework': framework,
            'overall_score': round(compliance_score, 2),
            'passed_controls': passed_controls,
            'total_controls': total_controls,
            'control_results': compliance_results,
            'critical_failures': [
                control for control, result in compliance_results.items() 
                if result['status'] == 'fail' and result['risk_score'] > 5
            ]
        }
    
    def _analyze_trend_data(self, historical_scan_data: List[Dict], historical_findings_data: List[Dict], period_days: int) -> Dict:
        """Analyze historical data for trends"""
        
        # Group data by time periods
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        # Create time buckets
        time_buckets = []
        bucket_size = timedelta(days=period_days // 10)  # 10 data points
        current_date = start_date
        
        while current_date < end_date:
            time_buckets.append({
                'start': current_date,
                'end': current_date + bucket_size,
                'scans': [],
                'findings': []
            })
            current_date += bucket_size
        
        # Distribute data into buckets
        for scan in historical_scan_data:
            scan_date = datetime.fromisoformat(scan.get('created_at', '').replace('Z', '+00:00'))
            for bucket in time_buckets:
                if bucket['start'] <= scan_date < bucket['end']:
                    bucket['scans'].append(scan)
                    break
        
        for finding in historical_findings_data:
            finding_date = datetime.fromisoformat(finding.get('created_at', '').replace('Z', '+00:00'))
            for bucket in time_buckets:
                if bucket['start'] <= finding_date < bucket['end']:
                    bucket['findings'].append(finding)
                    break
        
        # Calculate trends
        trend_metrics = []
        for bucket in time_buckets:
            metrics = {
                'date': bucket['start'].strftime('%Y-%m-%d'),
                'scan_count': len(bucket['scans']),
                'finding_count': len(bucket['findings']),
                'critical_count': len([f for f in bucket['findings'] if f.get('severity') == 'critical']),
                'high_count': len([f for f in bucket['findings'] if f.get('severity') == 'high']),
                'avg_risk_score': sum([s.get('risk_score', 0) for s in bucket['scans']]) / max(len(bucket['scans']), 1)
            }
            trend_metrics.append(metrics)
        
        return {
            'period_start': start_date.strftime('%Y-%m-%d'),
            'period_end': end_date.strftime('%Y-%m-%d'),
            'trend_data': trend_metrics,
            'summary': self._calculate_trend_summary(trend_metrics)
        }
    
    def _generate_executive_pdf(self, data: Dict, metadata: ReportMetadata) -> str:
        """Generate executive summary PDF report"""
        
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        
        # Create PDF document
        doc = SimpleDocTemplate(temp_file.name, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph(metadata.title, self.styles['title']))
        story.append(Paragraph(metadata.subtitle, self.styles['heading1']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['heading1']))
        
        summary_text = f"""
        This report provides a comprehensive overview of the security posture across 
        {len(metadata.cloud_providers)} cloud provider(s) based on {metadata.total_scans} 
        security scans conducted between {metadata.scan_period_start} and {metadata.scan_period_end}.
        
        Key findings:
        • Total security findings identified: {data['summary']['total_findings']:,}
        • Critical security issues requiring immediate attention: {data['summary']['critical_findings_count']:,}
        • High-priority security issues: {data['summary']['high_findings_count']:,}
        • Overall risk score: {data['summary']['avg_risk_score']}/10
        """
        
        story.append(Paragraph(summary_text, self.styles['body']))
        story.append(Spacer(1, 20))
        
        # Severity Breakdown Table
        story.append(Paragraph("Security Findings by Severity", self.styles['heading2']))
        
        severity_data = [['Severity', 'Count', 'Percentage']]
        total_findings = sum(data['severity_breakdown'].values())
        
        for severity, count in sorted(data['severity_breakdown'].items(), 
                                    key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x[0], 0), 
                                    reverse=True):
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            severity_data.append([severity.title(), str(count), f"{percentage:.1f}%"])
        
        severity_table = Table(severity_data)
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(severity_table)
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Immediate Recommendations", self.styles['heading2']))
        for i, recommendation in enumerate(data['recommendations'], 1):
            story.append(Paragraph(f"{i}. {recommendation}", self.styles['body']))
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"Executive summary PDF report generated: {temp_file.name}")
        return temp_file.name
    
    def _generate_executive_json(self, data: Dict, metadata: ReportMetadata) -> str:
        """Generate executive summary JSON report"""
        
        report_data = {
            'metadata': asdict(metadata),
            'executive_summary': data,
            'generated_at': datetime.now().isoformat()
        }
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(report_data, temp_file, indent=2, default=str)
        temp_file.close()
        
        logger.info(f"Executive summary JSON report generated: {temp_file.name}")
        return temp_file.name
    
    def _generate_executive_recommendations(self, severity_counts: Dict, avg_risk_score: float) -> List[str]:
        """Generate executive recommendations based on findings"""
        
        recommendations = []
        
        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)
        
        if critical_count > 0:
            recommendations.append(
                f"Address {critical_count} critical security findings immediately to prevent potential security breaches."
            )
        
        if high_count > 0:
            recommendations.append(
                f"Prioritize remediation of {high_count} high-severity security issues within the next 30 days."
            )
        
        if avg_risk_score > 7:
            recommendations.append(
                "Implement comprehensive security controls to reduce overall risk exposure."
            )
        
        recommendations.extend([
            "Establish regular security scanning schedules for all cloud environments.",
            "Implement automated alerting for critical security findings.",
            "Conduct security training for development and operations teams.",
            "Review and update security policies and procedures quarterly."
        ])
        
        return recommendations
    
    def _map_finding_to_controls(self, finding_type: str, framework: str) -> List[str]:
        """Map finding types to compliance controls"""
        
        # Simplified mapping logic
        control_mappings = {
            'iam': ['AC-1', 'AC-2', 'IA-1'],
            'encryption': ['SC-8', 'SC-13'],
            'logging': ['AU-1', 'AU-2'],
            'network': ['SC-7', 'SC-20'],
            'access': ['AC-1', 'AC-3'],
            'configuration': ['CM-1', 'CM-2']
        }
        
        relevant_controls = []
        for keyword, controls in control_mappings.items():
            if keyword in finding_type:
                relevant_controls.extend(controls)
        
        return relevant_controls
    
    def _analyze_remediation_efforts(self, findings_data: List[Dict]) -> Dict:
        """Analyze remediation efforts and timelines"""
        
        remediation_stats = {
            'total_findings': len(findings_data),
            'remediated_findings': 0,
            'avg_remediation_time': 0,
            'findings_by_age': {'0-7_days': 0, '8-30_days': 0, '31-90_days': 0, '90+_days': 0}
        }
        
        now = datetime.now()
        remediation_times = []
        
        for finding in findings_data:
            created_at = datetime.fromisoformat(finding.get('created_at', '').replace('Z', '+00:00'))
            status = finding.get('status', 'open')
            
            if status in ['resolved', 'fixed', 'closed']:
                remediation_stats['remediated_findings'] += 1
                if finding.get('resolved_at'):
                    resolved_at = datetime.fromisoformat(finding.get('resolved_at', '').replace('Z', '+00:00'))
                    remediation_time = (resolved_at - created_at).days
                    remediation_times.append(remediation_time)
            else:
                # Calculate age of open findings
                age_days = (now - created_at).days
                if age_days <= 7:
                    remediation_stats['findings_by_age']['0-7_days'] += 1
                elif age_days <= 30:
                    remediation_stats['findings_by_age']['8-30_days'] += 1
                elif age_days <= 90:
                    remediation_stats['findings_by_age']['31-90_days'] += 1
                else:
                    remediation_stats['findings_by_age']['90+_days'] += 1
        
        if remediation_times:
            remediation_stats['avg_remediation_time'] = sum(remediation_times) / len(remediation_times)
        
        return remediation_stats
    
    def _extract_vulnerability_details(self, findings_data: List[Dict]) -> List[Dict]:
        """Extract detailed vulnerability information"""
        
        vulnerability_details = []
        
        for finding in findings_data:
            if finding.get('severity') in ['critical', 'high']:
                detail = {
                    'id': finding.get('id'),
                    'title': finding.get('title', 'Unknown Vulnerability'),
                    'severity': finding.get('severity'),
                    'description': finding.get('description', 'No description available'),
                    'resource': finding.get('resource_id'),
                    'service': finding.get('service_name'),
                    'provider': finding.get('cloud_provider'),
                    'remediation': finding.get('remediation_guidance', 'No remediation guidance available'),
                    'risk_score': finding.get('risk_score', 0),
                    'created_at': finding.get('created_at')
                }
                vulnerability_details.append(detail)
        
        # Sort by risk score descending
        vulnerability_details.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return vulnerability_details[:50]  # Top 50 most critical
    
    def _calculate_trend_summary(self, trend_data: List[Dict]) -> Dict:
        """Calculate trend analysis summary"""
        
        if len(trend_data) < 2:
            return {'trend': 'insufficient_data'}
        
        first_period = trend_data[0]
        last_period = trend_data[-1]
        
        # Calculate percentage changes
        findings_change = self._calculate_percentage_change(
            first_period['finding_count'], 
            last_period['finding_count']
        )
        
        critical_change = self._calculate_percentage_change(
            first_period['critical_count'], 
            last_period['critical_count']
        )
        
        risk_score_change = self._calculate_percentage_change(
            first_period['avg_risk_score'], 
            last_period['avg_risk_score']
        )
        
        return {
            'findings_trend': findings_change,
            'critical_trend': critical_change,
            'risk_score_trend': risk_score_change,
            'overall_trend': 'improving' if findings_change < 0 else 'deteriorating' if findings_change > 0 else 'stable'
        }
    
    def _calculate_percentage_change(self, old_value: float, new_value: float) -> float:
        """Calculate percentage change between two values"""
        if old_value == 0:
            return 100.0 if new_value > 0 else 0.0
        return ((new_value - old_value) / old_value) * 100

    # Additional generation methods for other report types would follow similar patterns...
    # (truncated for brevity but would include _generate_detailed_pdf, _generate_compliance_pdf, etc.)
