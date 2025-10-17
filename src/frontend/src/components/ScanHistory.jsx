import React, { useState } from 'react';
import {
  ClockIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  XCircleIcon,
  ChevronRightIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  CloudIcon,
  ShieldCheckIcon,
  DocumentArrowDownIcon,
  PlayIcon
} from '@heroicons/react/24/outline';

const ScanHistory = ({ 
  scans = [], 
  loading = false, 
  onViewResults, 
  onDownloadReport,
  onRestartScan 
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterProvider, setFilterProvider] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('desc');

  const providerConfig = {
    aws: { name: 'AWS', color: 'text-orange-600', bgColor: 'bg-orange-100' },
    azure: { name: 'Azure', color: 'text-blue-600', bgColor: 'bg-blue-100' },
    gcp: { name: 'GCP', color: 'text-green-600', bgColor: 'bg-green-100' }
  };

  const statusConfig = {
    running: {
      icon: ClockIcon,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100',
      label: 'Running',
      animate: 'animate-spin'
    },
    completed: {
      icon: CheckCircleIcon,
      color: 'text-green-600',
      bgColor: 'bg-green-100',
      label: 'Completed'
    },
    failed: {
      icon: XCircleIcon,
      color: 'text-red-600',
      bgColor: 'bg-red-100',
      label: 'Failed'
    },
    cancelled: {
      icon: ExclamationCircleIcon,
      color: 'text-gray-600',
      bgColor: 'bg-gray-100',
      label: 'Cancelled'
    }
  };

  // Filter and sort scans
  const filteredAndSortedScans = React.useMemo(() => {
    let filtered = scans.filter(scan => {
      const matchesSearch = searchTerm === '' || 
        scan.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        scan.cloud_provider.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesProvider = filterProvider === 'all' || scan.cloud_provider === filterProvider;
      const matchesStatus = filterStatus === 'all' || scan.status === filterStatus;
      
      return matchesSearch && matchesProvider && matchesStatus;
    });

    return filtered.sort((a, b) => {
      let aValue = a[sortBy];
      let bValue = b[sortBy];

      if (sortBy === 'created_at' || sortBy === 'completed_at') {
        aValue = new Date(aValue);
        bValue = new Date(bValue);
      }

      if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  }, [scans, searchTerm, filterProvider, filterStatus, sortBy, sortOrder]);

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatDuration = (startTime, endTime) => {
    if (!startTime || !endTime) return 'N/A';
    const start = new Date(startTime);
    const end = new Date(endTime);
    const durationMs = end - start;
    const minutes = Math.floor(durationMs / 60000);
    const seconds = Math.floor((durationMs % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  const getSeverityColor = (severity, count) => {
    if (count === 0) return 'text-gray-400';
    switch (severity) {
      case 'critical': return 'text-red-600 font-bold';
      case 'high': return 'text-orange-600 font-semibold';
      case 'medium': return 'text-yellow-600';
      case 'low': return 'text-blue-600';
      default: return 'text-gray-600';
    }
  };

  const StatusBadge = ({ status }) => {
    const config = statusConfig[status] || statusConfig.completed;
    const Icon = config.icon;
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.color}`}>
        <Icon className={`w-3 h-3 mr-1 ${config.animate || ''}`} />
        {config.label}
      </span>
    );
  };

  const ProviderBadge = ({ provider }) => {
    const config = providerConfig[provider] || { name: provider.toUpperCase(), color: 'text-gray-600', bgColor: 'bg-gray-100' };
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.color}`}>
        <CloudIcon className="w-3 h-3 mr-1" />
        {config.name}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="animate-pulse">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="h-6 bg-gray-200 rounded w-1/3"></div>
          </div>
          {[...Array(5)].map((_, i) => (
            <div key={i} className="px-6 py-4 border-b border-gray-200">
              <div className="flex space-x-4">
                <div className="h-4 bg-gray-200 rounded w-1/4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/6"></div>
                <div className="h-4 bg-gray-200 rounded w-1/4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/6"></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0">
          <div className="flex items-center space-x-3">
            <ShieldCheckIcon className="w-6 h-6 text-gray-500" />
            <h3 className="text-lg font-medium text-gray-900">Scan History</h3>
            <span className="text-sm text-gray-500">
              {filteredAndSortedScans.length} of {scans.length} scans
            </span>
          </div>
        </div>

        {/* Filters and Search */}
        <div className="mt-4 flex flex-col sm:flex-row sm:items-center space-y-3 sm:space-y-0 sm:space-x-4">
          {/* Search */}
          <div className="relative flex-1 max-w-xs">
            <MagnifyingGlassIcon className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search scans..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {/* Filters */}
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              <FunnelIcon className="w-4 h-4 text-gray-400" />
              <select
                value={filterProvider}
                onChange={(e) => setFilterProvider(e.target.value)}
                className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="all">All Providers</option>
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
              </select>
            </div>

            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Statuses</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>

            <select
              value={`${sortBy}-${sortOrder}`}
              onChange={(e) => {
                const [field, order] = e.target.value.split('-');
                setSortBy(field);
                setSortOrder(order);
              }}
              className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="created_at-desc">Newest First</option>
              <option value="created_at-asc">Oldest First</option>
              <option value="cloud_provider-asc">Provider A-Z</option>
              <option value="status-asc">Status</option>
            </select>
          </div>
        </div>
      </div>

      {/* Scan List */}
      <div className="divide-y divide-gray-200">
        {filteredAndSortedScans.length === 0 ? (
          <div className="text-center py-12">
            <ShieldCheckIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No scans found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {scans.length === 0 
                ? "No security scans have been executed yet."
                : "No scans match the current filters."
              }
            </p>
          </div>
        ) : (
          filteredAndSortedScans.map((scan) => (
            <div key={scan.id} className="px-6 py-4 hover:bg-gray-50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-3 mb-2">
                    <h4 className="text-sm font-medium text-gray-900 truncate">
                      Scan #{scan.id}
                    </h4>
                    <ProviderBadge provider={scan.cloud_provider} />
                    <StatusBadge status={scan.status} />
                  </div>

                  <div className="flex flex-wrap items-center gap-4 text-sm text-gray-500">
                    <div className="flex items-center space-x-1">
                      <ClockIcon className="w-4 h-4" />
                      <span>Started: {formatDate(scan.created_at)}</span>
                    </div>
                    
                    {scan.completed_at && (
                      <div className="flex items-center space-x-1">
                        <CheckCircleIcon className="w-4 h-4" />
                        <span>Duration: {formatDuration(scan.created_at, scan.completed_at)}</span>
                      </div>
                    )}

                    {scan.region && (
                      <div>
                        <span>Region: {scan.region}</span>
                      </div>
                    )}

                    {scan.total_resources && (
                      <div>
                        <span>Resources: {scan.total_resources.toLocaleString()}</span>
                      </div>
                    )}
                  </div>

                  {/* Findings Summary */}
                  {scan.findings_count !== undefined && (
                    <div className="mt-3 flex items-center space-x-4">
                      <span className="text-sm text-gray-600">Findings:</span>
                      <div className="flex items-center space-x-3">
                        {scan.critical_findings !== undefined && (
                          <span className={`text-sm ${getSeverityColor('critical', scan.critical_findings)}`}>
                            Critical: {scan.critical_findings}
                          </span>
                        )}
                        {scan.high_findings !== undefined && (
                          <span className={`text-sm ${getSeverityColor('high', scan.high_findings)}`}>
                            High: {scan.high_findings}
                          </span>
                        )}
                        {scan.medium_findings !== undefined && (
                          <span className={`text-sm ${getSeverityColor('medium', scan.medium_findings)}`}>
                            Medium: {scan.medium_findings}
                          </span>
                        )}
                        {scan.low_findings !== undefined && (
                          <span className={`text-sm ${getSeverityColor('low', scan.low_findings)}`}>
                            Low: {scan.low_findings}
                          </span>
                        )}
                        <span className="text-sm font-medium text-gray-900">
                          Total: {scan.findings_count}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Risk Score */}
                  {scan.risk_score !== undefined && (
                    <div className="mt-2">
                      <span className="text-sm text-gray-600">Risk Score: </span>
                      <span className={`text-sm font-medium ${
                        scan.risk_score >= 8 ? 'text-red-600' :
                        scan.risk_score >= 6 ? 'text-orange-600' :
                        scan.risk_score >= 4 ? 'text-yellow-600' : 'text-green-600'
                      }`}>
                        {scan.risk_score.toFixed(1)}/10
                      </span>
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center space-x-2 ml-4">
                  {scan.status === 'completed' && (
                    <>
                      <button
                        onClick={() => onViewResults && onViewResults(scan)}
                        className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                      >
                        <MagnifyingGlassIcon className="w-4 h-4 mr-1" />
                        View Results
                      </button>
                      
                      <button
                        onClick={() => onDownloadReport && onDownloadReport(scan)}
                        className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                      >
                        <DocumentArrowDownIcon className="w-4 h-4 mr-1" />
                        Download
                      </button>
                    </>
                  )}

                  {(scan.status === 'failed' || scan.status === 'completed') && (
                    <button
                      onClick={() => onRestartScan && onRestartScan(scan)}
                      className="inline-flex items-center px-3 py-1.5 border border-blue-300 shadow-sm text-xs font-medium rounded text-blue-700 bg-blue-50 hover:bg-blue-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    >
                      <PlayIcon className="w-4 h-4 mr-1" />
                      Restart
                    </button>
                  )}

                  <ChevronRightIcon className="w-5 h-5 text-gray-400" />
                </div>
              </div>

              {/* Progress Bar for Running Scans */}
              {scan.status === 'running' && scan.progress !== undefined && (
                <div className="mt-3">
                  <div className="flex items-center justify-between text-sm text-gray-600 mb-1">
                    <span>Scanning progress</span>
                    <span>{scan.progress}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-blue-600 h-2 rounded-full transition-all duration-300" 
                      style={{ width: `${scan.progress}%` }}
                    ></div>
                  </div>
                  {scan.current_service && (
                    <p className="text-xs text-gray-500 mt-1">
                      Currently scanning: {scan.current_service.toUpperCase()}
                    </p>
                  )}
                </div>
              )}

              {/* Error Message for Failed Scans */}
              {scan.status === 'failed' && scan.error_message && (
                <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md">
                  <div className="flex items-start space-x-2">
                    <XCircleIcon className="w-5 h-5 text-red-600 mt-0.5" />
                    <div>
                      <h5 className="text-sm font-medium text-red-900">Scan Failed</h5>
                      <p className="text-sm text-red-700 mt-1">{scan.error_message}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Pagination could be added here if needed */}
    </div>
  );
};

export default ScanHistory;
