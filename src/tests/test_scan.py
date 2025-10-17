"""Test cloud scanning functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from src.scanner.aws_scanner import AWSScanner
from src.scanner.azure_scanner import AzureScanner  
from src.scanner.gcp_scanner import GCPScanner
from src.scanner.common import BaseFinding


class TestAWSScanner:
    """Test AWS cloud scanner functionality."""

    @patch('boto3.Session')
    def test_aws_scanner_initialization(self, mock_session):
        """Test AWS scanner initialization."""
        credentials = {
            "access_key_id": "test_key",
            "secret_access_key": "test_secret",
            "region": "us-east-1"
        }
        
        scanner = AWSScanner(credentials)
        assert scanner.region == "us-east-1"
        mock_session.assert_called_once()

    @patch('boto3.Session')
    def test_aws_scanner_invalid_credentials(self, mock_session):
        """Test AWS scanner with invalid credentials."""
        mock_session.side_effect = NoCredentialsError()
        
        credentials = {
            "access_key_id": "invalid",
            "secret_access_key": "invalid",
            "region": "us-east-1"
        }
        
        with pytest.raises(Exception):
            AWSScanner(credentials)

    @patch('boto3.Session')
    def test_scan_s3_buckets_public_read(self, mock_session):
        """Test S3 bucket scanning for public read access."""
        # Mock S3 client
        mock_s3 = Mock()
        mock_session.return_value.client.return_value = mock_s3
        
        # Mock bucket list
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'test-bucket-public', 'CreationDate': '2023-01-01'},
                {'Name': 'test-bucket-private', 'CreationDate': '2023-01-01'}
            ]
        }
        
        # Mock bucket ACL (public read)
        mock_s3.get_bucket_acl.side_effect = [
            {
                'Grants': [
                    {
                        'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                        'Permission': 'READ'
                    }
                ]
            },
            {
                'Grants': [
                    {
                        'Grantee': {'ID': 'owner-id'},
                        'Permission': 'FULL_CONTROL'
                    }
                ]
            }
        ]
        
        # Mock bucket policy (no policy)
        mock_s3.get_bucket_policy.side_effect = [
            ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy'),
            ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
        ]
        
        scanner = AWSScanner({
            "access_key_id": "test",
            "secret_access_key": "test",
            "region": "us-east-1"
        })
        
        findings = scanner.scan_s3_buckets()
        
        # Should find one public bucket
        public_findings = [f for f in findings if f.severity == "critical"]
        assert len(public_findings) >= 1
        assert any("public" in f.description.lower() for f in public_findings)

    @patch('boto3.Session')
    def test_scan_iam_policies_overprivileged(self, mock_session):
        """Test IAM policy scanning for overprivileged policies."""
        # Mock IAM client
        mock_iam = Mock()
        mock_session.return_value.client.return_value = mock_iam
        
        # Mock list policies
        mock_iam.list_policies.return_value = {
            'Policies': [
                {
                    'PolicyName': 'OverprivilegedPolicy',
                    'Arn': 'arn:aws:iam::123456789012:policy/OverprivilegedPolicy',
                    'DefaultVersionId': 'v1'
                }
            ]
        }
        
        # Mock policy version with wildcard permissions
        mock_iam.get_policy_version.return_value = {
            'PolicyVersion': {
                'Document': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }
                    ]
                }
            }
        }
        
        scanner = AWSScanner({
            "access_key_id": "test",
            "secret_access_key": "test", 
            "region": "us-east-1"
        })
        
        findings = scanner.scan_iam_policies()
        
        # Should find overprivileged policy
        overprivileged_findings = [
            f for f in findings 
            if "wildcard" in f.description.lower() or "overprivileged" in f.description.lower()
        ]
        assert len(overprivileged_findings) >= 1

    @patch('boto3.Session')
    def test_scan_security_groups_open(self, mock_session):
        """Test security group scanning for open access."""
        # Mock EC2 client
        mock_ec2 = Mock()
        mock_session.return_value.client.return_value = mock_ec2
        
        # Mock security groups
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-12345678',
                    'GroupName': 'open-ssh-group',
                    'Description': 'Security group with open SSH',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ]
                }
            ]
        }
        
        scanner = AWSScanner({
            "access_key_id": "test",
            "secret_access_key": "test",
            "region": "us-east-1"
        })
        
        findings = scanner.scan_security_groups()
        
        # Should find open SSH access
        ssh_findings = [
            f for f in findings 
            if "ssh" in f.description.lower() and "0.0.0.0/0" in f.description
        ]
        assert len(ssh_findings) >= 1


class TestAzureScanner:
    """Test Azure cloud scanner functionality."""

    @patch('src.scanner.azure_scanner.DefaultAzureCredential')
    @patch('src.scanner.azure_scanner.ResourceManagementClient')
    def test_azure_scanner_initialization(self, mock_resource_client, mock_credential):
        """Test Azure scanner initialization."""
        credentials = {
            "subscription_id": "test-sub-id",
            "tenant_id": "test-tenant-id",
            "client_id": "test-client-id",
            "client_secret": "test-secret"
        }
        
        scanner = AzureScanner(credentials)
        assert scanner.subscription_id == "test-sub-id"
        mock_credential.assert_called_once()

    @patch('src.scanner.azure_scanner.DefaultAzureCredential')
    @patch('src.scanner.azure_scanner.StorageManagementClient')
    def test_scan_storage_accounts_public(self, mock_storage_client, mock_credential):
        """Test Azure storage account scanning."""
        # Mock storage accounts
        mock_client_instance = Mock()
        mock_storage_client.return_value = mock_client_instance
        
        mock_client_instance.storage_accounts.list.return_value = [
            Mock(
                name='publicstorageaccount',
                id='/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/publicstorageaccount',
                location='eastus',
                allow_blob_public_access=True,
                network_rule_set=Mock(default_action='Allow')
            )
        ]
        
        scanner = AzureScanner({
            "subscription_id": "test-sub-id",
            "tenant_id": "test-tenant-id"
        })
        
        findings = scanner.scan_storage_accounts()
        
        # Should find public storage account
        public_findings = [
            f for f in findings 
            if "public" in f.description.lower()
        ]
        assert len(public_findings) >= 1


class TestGCPScanner:
    """Test GCP cloud scanner functionality."""

    @patch('src.scanner.gcp_scanner.service_account.Credentials.from_service_account_info')
    @patch('src.scanner.gcp_scanner.discovery.build')
    def test_gcp_scanner_initialization(self, mock_discovery, mock_credentials):
        """Test GCP scanner initialization."""
        credentials = {
            "project_id": "test-project",
            "service_account_key": {
                "type": "service_account",
                "project_id": "test-project"
            }
        }
        
        scanner = GCPScanner(credentials)
        assert scanner.project_id == "test-project"
        mock_credentials.assert_called_once()

    @patch('src.scanner.gcp_scanner.service_account.Credentials.from_service_account_info')
    @patch('src.scanner.gcp_scanner.discovery.build')
    def test_scan_cloud_storage_buckets(self, mock_discovery, mock_credentials):
        """Test GCP Cloud Storage bucket scanning."""
        # Mock storage service
        mock_service = Mock()
        mock_discovery.return_value = mock_service
        
        # Mock bucket list
        mock_service.buckets.return_value.list.return_value.execute.return_value = {
            'items': [
                {
                    'name': 'public-bucket',
                    'location': 'US',
                    'timeCreated': '2023-01-01T00:00:00Z'
                }
            ]
        }
        
        # Mock bucket IAM policy with public access
        mock_service.buckets.return_value.getIamPolicy.return_value.execute.return_value = {
            'bindings': [
                {
                    'role': 'roles/storage.objectViewer',
                    'members': ['allUsers']
                }
            ]
        }
        
        scanner = GCPScanner({
            "project_id": "test-project",
            "service_account_key": {"type": "service_account"}
        })
        
        findings = scanner.scan_cloud_storage()
        
        # Should find public bucket
        public_findings = [
            f for f in findings 
            if "public" in f.description.lower() and "allUsers" in f.description
        ]
        assert len(public_findings) >= 1


class TestBaseFinding:
    """Test BaseFinding utility class."""

    def test_base_finding_creation(self):
        """Test creating a base finding."""
        finding = BaseFinding(
            finding_id="test-finding-1",
            finding_type="test_vulnerability",
            severity="high",
            title="Test Vulnerability",
            description="A test vulnerability was found",
            resource_id="resource-123",
            resource_type="test_resource",
            region="us-east-1",
            service="test_service",
            compliance_violations=["TEST-1.1"],
            remediation_steps=["Fix the issue"],
            risk_factors={
                "public_exposure": True,
                "exploitability": "high"
            }
        )
        
        assert finding.finding_id == "test-finding-1"
        assert finding.severity == "high"
        assert finding.compliance_violations == ["TEST-1.1"]
        assert finding.risk_factors["public_exposure"] is True

    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = BaseFinding(
            finding_id="test-finding-2",
            finding_type="configuration_issue",
            severity="medium",
            title="Configuration Issue",
            description="Configuration needs attention",
            resource_id="config-456"
        )
        
        finding_dict = finding.to_dict()
        
        assert finding_dict["finding_id"] == "test-finding-2"
        assert finding_dict["severity"] == "medium"
        assert finding_dict["title"] == "Configuration Issue"
        assert "timestamp" in finding_dict

    def test_finding_severity_validation(self):
        """Test finding severity validation."""
        valid_severities = ["critical", "high", "medium", "low", "info"]
        
        for severity in valid_severities:
            finding = BaseFinding(
                finding_id=f"test-{severity}",
                finding_type="test",
                severity=severity,
                title="Test",
                description="Test",
                resource_id="test"
            )
            assert finding.severity == severity

    def test_finding_compliance_mapping(self):
        """Test compliance framework mapping."""
        finding = BaseFinding(
            finding_id="compliance-test",
            finding_type="access_control",
            severity="high",
            title="Access Control Issue",
            description="Improper access controls",
            resource_id="access-resource",
            compliance_violations=["CIS-1.1", "NIST-AC-3", "ISO27001-A.9.1.1"]
        )
        
        assert "CIS-1.1" in finding.compliance_violations
        assert "NIST-AC-3" in finding.compliance_violations
        assert "ISO27001-A.9.1.1" in finding.compliance_violations
