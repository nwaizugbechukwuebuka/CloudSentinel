import React from 'react';
import { 
  CloudIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  MinusIcon
} from '@heroicons/react/24/outline';

const CloudCard = ({ 
  provider, 
  data = {}, 
  onStartScan, 
  onViewDetails,
  loading = false 
}) => {
  const providerConfig = {
    aws: {
      name: 'Amazon Web Services',
      color: 'bg-orange-500',
      lightColor: 'bg-orange-50',
      textColor: 'text-orange-700',
      borderColor: 'border-orange-200',
      icon: '🟠'
    },
    azure: {
      name: 'Microsoft Azure',
      color: 'bg-blue-500',
      lightColor: 'bg-blue-50',
      textColor: 'text-blue-700',
      borderColor: 'border-blue-200',
      icon: '🔵'
    },
    gcp: {
      name: 'Google Cloud Platform',
      color: 'bg-green-500',
      lightColor: 'bg-green-50',
      textColor: 'text-green-700',
      borderColor: 'border-green-200',
      icon: '🟢'
    }
  };

  const config = providerConfig[provider] || providerConfig.aws;
  
  const {
    lastScan = null,
    riskScore = 0,
    totalFindings = 0,
    criticalFindings = 0,
    highFindings = 0,
    mediumFindings = 0,
    lowFindings = 0,
    resourcesScanned = 0,
    scanStatus = 'idle',
    trend = 'stable',
    complianceScore = 0
  } = data;

  const getRiskLevel = (score) => {
    if (score >= 8) return { level: 'Critical', color: 'text-red-600', bgColor: 'bg-red-100' };
    if (score >= 6) return { level: 'High', color: 'text-orange-600', bgColor: 'bg-orange-100' };
    if (score >= 4) return { level: 'Medium', color: 'text-yellow-600', bgColor: 'bg-yellow-100' };
    return { level: 'Low', color: 'text-green-600', bgColor: 'bg-green-100' };
  };

  const getTrendIcon = (trend) => {
    switch (trend) {
      case 'improving':
        return <ArrowTrendingUpIcon className="w-4 h-4 text-green-500" />;
      case 'declining':
        return <ArrowTrendingDownIcon className="w-4 h-4 text-red-500" />;
      default:
        return <MinusIcon className="w-4 h-4 text-gray-400" />;
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    return date.toLocaleDateString();
  };

  const getStatusBadge = (status) => {
    const statusConfig = {
      running: { color: 'bg-blue-100 text-blue-800', label: 'Scanning...' },
      completed: { color: 'bg-green-100 text-green-800', label: 'Complete' },
      failed: { color: 'bg-red-100 text-red-800', label: 'Failed' },
      idle: { color: 'bg-gray-100 text-gray-800', label: 'Idle' }
    };
    
    const config = statusConfig[status] || statusConfig.idle;
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.color}`}>
        {config.label}
      </span>
    );
  };

  if (loading) {
    return (
      <div className={`bg-white rounded-xl shadow-sm border-2 ${config.borderColor} p-6 animate-pulse`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-gray-200 rounded-lg"></div>
            <div className="h-6 bg-gray-200 rounded w-32"></div>
          </div>
          <div className="h-6 bg-gray-200 rounded w-16"></div>
        </div>
        <div className="space-y-3">
          <div className="h-4 bg-gray-200 rounded"></div>
          <div className="h-4 bg-gray-200 rounded w-3/4"></div>
          <div className="h-4 bg-gray-200 rounded w-1/2"></div>
        </div>
      </div>
    );
  }

  const riskLevel = getRiskLevel(riskScore);

  return (
    <div className={`bg-white rounded-xl shadow-sm border-2 ${config.borderColor} hover:shadow-md transition-shadow duration-200`}>
      {/* Header */}
      <div className={`${config.lightColor} px-6 py-4 rounded-t-xl border-b ${config.borderColor}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`w-10 h-10 ${config.color} rounded-lg flex items-center justify-center text-white text-xl`}>
              <CloudIcon className="w-6 h-6" />
            </div>
            <div>
              <h3 className={`text-lg font-semibold ${config.textColor}`}>
                {config.name}
              </h3>
              <p className="text-sm text-gray-600">
                Last scan: {formatDate(lastScan)}
              </p>
            </div>
          </div>
          <div className="text-right">
            {getStatusBadge(scanStatus)}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {/* Risk Score Section */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className={`w-12 h-12 ${riskLevel.bgColor} rounded-lg flex items-center justify-center`}>
              <ShieldCheckIcon className={`w-6 h-6 ${riskLevel.color}`} />
            </div>
            <div>
              <p className="text-sm text-gray-600">Risk Score</p>
              <div className="flex items-center space-x-2">
                <span className={`text-2xl font-bold ${riskLevel.color}`}>
                  {riskScore.toFixed(1)}
                </span>
                <span className={`text-sm font-medium px-2 py-1 rounded ${riskLevel.bgColor} ${riskLevel.color}`}>
                  {riskLevel.level}
                </span>
                {getTrendIcon(trend)}
              </div>
            </div>
          </div>
          
          <div className="text-right">
            <p className="text-sm text-gray-600">Compliance</p>
            <p className="text-2xl font-bold text-gray-900">
              {complianceScore}%
            </p>
          </div>
        </div>

        {/* Findings Summary */}
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Security Findings</h4>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-red-50 rounded-lg p-3 border border-red-100">
              <div className="flex items-center justify-between">
                <span className="text-sm text-red-600">Critical</span>
                <span className="text-lg font-bold text-red-700">{criticalFindings}</span>
              </div>
            </div>
            <div className="bg-orange-50 rounded-lg p-3 border border-orange-100">
              <div className="flex items-center justify-between">
                <span className="text-sm text-orange-600">High</span>
                <span className="text-lg font-bold text-orange-700">{highFindings}</span>
              </div>
            </div>
            <div className="bg-yellow-50 rounded-lg p-3 border border-yellow-100">
              <div className="flex items-center justify-between">
                <span className="text-sm text-yellow-600">Medium</span>
                <span className="text-lg font-bold text-yellow-700">{mediumFindings}</span>
              </div>
            </div>
            <div className="bg-blue-50 rounded-lg p-3 border border-blue-100">
              <div className="flex items-center justify-between">
                <span className="text-sm text-blue-600">Low</span>
                <span className="text-lg font-bold text-blue-700">{lowFindings}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="mb-6 bg-gray-50 rounded-lg p-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-gray-600">Total Findings</p>
              <p className="text-xl font-semibold text-gray-900">{totalFindings}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Resources Scanned</p>
              <p className="text-xl font-semibold text-gray-900">{resourcesScanned.toLocaleString()}</p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex space-x-3">
          <button
            onClick={() => onStartScan && onStartScan(provider)}
            disabled={scanStatus === 'running'}
            className={`flex-1 flex items-center justify-center px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              scanStatus === 'running'
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                : `${config.color} text-white hover:opacity-90`
            }`}
          >
            {scanStatus === 'running' ? (
              <>
                <ClockIcon className="w-4 h-4 mr-2 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <ShieldCheckIcon className="w-4 h-4 mr-2" />
                Start Scan
              </>
            )}
          </button>
          
          <button
            onClick={() => onViewDetails && onViewDetails(provider)}
            className="px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 transition-colors"
          >
            View Details
          </button>
        </div>

        {/* Quick Insights */}
        {totalFindings > 0 && (
          <div className="mt-4 p-4 bg-blue-50 rounded-lg border border-blue-100">
            <div className="flex items-start space-x-3">
              <ExclamationTriangleIcon className="w-5 h-5 text-blue-600 mt-0.5" />
              <div>
                <h5 className="text-sm font-medium text-blue-900">Security Insights</h5>
                <p className="text-sm text-blue-700 mt-1">
                  {criticalFindings > 0 && `${criticalFindings} critical issues need immediate attention. `}
                  {highFindings > 0 && `${highFindings} high-priority vulnerabilities detected. `}
                  {criticalFindings === 0 && highFindings === 0 && "Good security posture with no critical issues."}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CloudCard;
