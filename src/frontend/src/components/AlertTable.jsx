import React, { useState, useEffect } from 'react';
import { 
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  InformationCircleIcon,
  ChevronUpDownIcon,
  FunnelIcon,
  EyeIcon,
  CheckCircleIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';

const AlertTable = ({ 
  alerts = [], 
  loading = false, 
  onUpdateStatus, 
  onViewDetails,
  onBulkUpdate
}) => {
  const [selectedAlerts, setSelectedAlerts] = useState(new Set());
  const [sortField, setSortField] = useState('created_at');
  const [sortDirection, setSortDirection] = useState('desc');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  const severityConfig = {
    critical: {
      icon: ExclamationTriangleIcon,
      bgColor: 'bg-red-100',
      textColor: 'text-red-800',
      borderColor: 'border-red-200',
      label: 'Critical'
    },
    high: {
      icon: ShieldExclamationIcon,
      bgColor: 'bg-orange-100',
      textColor: 'text-orange-800',
      borderColor: 'border-orange-200',
      label: 'High'
    },
    medium: {
      icon: ExclamationTriangleIcon,
      bgColor: 'bg-yellow-100',
      textColor: 'text-yellow-800',
      borderColor: 'border-yellow-200',
      label: 'Medium'
    },
    low: {
      icon: InformationCircleIcon,
      bgColor: 'bg-blue-100',
      textColor: 'text-blue-800',
      borderColor: 'border-blue-200',
      label: 'Low'
    }
  };

  const statusConfig = {
    open: {
      bgColor: 'bg-red-100',
      textColor: 'text-red-800',
      label: 'Open'
    },
    acknowledged: {
      bgColor: 'bg-yellow-100',
      textColor: 'text-yellow-800',
      label: 'Acknowledged'
    },
    resolved: {
      bgColor: 'bg-green-100',
      textColor: 'text-green-800',
      label: 'Resolved'
    },
    suppressed: {
      bgColor: 'bg-gray-100',
      textColor: 'text-gray-800',
      label: 'Suppressed'
    }
  };

  // Filter and sort alerts
  const filteredAndSortedAlerts = React.useMemo(() => {
    let filtered = alerts.filter(alert => {
      const severityMatch = filterSeverity === 'all' || alert.severity === filterSeverity;
      const statusMatch = filterStatus === 'all' || alert.status === filterStatus;
      return severityMatch && statusMatch;
    });

    return filtered.sort((a, b) => {
      let aValue = a[sortField];
      let bValue = b[sortField];

      if (sortField === 'created_at' || sortField === 'updated_at') {
        aValue = new Date(aValue);
        bValue = new Date(bValue);
      }

      if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [alerts, filterSeverity, filterStatus, sortField, sortDirection]);

  const handleSort = (field) => {
    if (field === sortField) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const handleSelectAlert = (alertId) => {
    const newSelected = new Set(selectedAlerts);
    if (newSelected.has(alertId)) {
      newSelected.delete(alertId);
    } else {
      newSelected.add(alertId);
    }
    setSelectedAlerts(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedAlerts.size === filteredAndSortedAlerts.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(filteredAndSortedAlerts.map(alert => alert.id)));
    }
  };

  const handleBulkStatusUpdate = (status) => {
    if (selectedAlerts.size > 0 && onBulkUpdate) {
      onBulkUpdate(Array.from(selectedAlerts), { status });
      setSelectedAlerts(new Set());
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const getRiskScoreColor = (score) => {
    if (score >= 8) return 'text-red-600 font-bold';
    if (score >= 6) return 'text-orange-600 font-semibold';
    if (score >= 4) return 'text-yellow-600';
    return 'text-green-600';
  };

  const SeverityBadge = ({ severity }) => {
    const config = severityConfig[severity] || severityConfig.medium;
    const Icon = config.icon;
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.textColor} border ${config.borderColor}`}>
        <Icon className="w-3 h-3 mr-1" />
        {config.label}
      </span>
    );
  };

  const StatusBadge = ({ status }) => {
    const config = statusConfig[status] || statusConfig.open;
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.textColor}`}>
        {config.label}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="animate-pulse">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          </div>
          {[...Array(5)].map((_, i) => (
            <div key={i} className="px-6 py-4 border-b border-gray-200">
              <div className="flex space-x-4">
                <div className="h-4 bg-gray-200 rounded w-1/4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/6"></div>
                <div className="h-4 bg-gray-200 rounded w-1/6"></div>
                <div className="h-4 bg-gray-200 rounded w-1/4"></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      {/* Header with filters and bulk actions */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0">
          <div className="flex items-center space-x-4">
            <h3 className="text-lg font-medium text-gray-900">Security Alerts</h3>
            <span className="text-sm text-gray-500">
              {filteredAndSortedAlerts.length} of {alerts.length} alerts
            </span>
          </div>
          
          <div className="flex items-center space-x-3">
            {/* Severity Filter */}
            <div className="flex items-center space-x-2">
              <FunnelIcon className="w-4 h-4 text-gray-400" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            
            {/* Status Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>

        {/* Bulk Actions */}
        {selectedAlerts.size > 0 && (
          <div className="mt-3 flex items-center justify-between bg-blue-50 rounded-lg px-4 py-3 border border-blue-200">
            <span className="text-sm text-blue-700">
              {selectedAlerts.size} alert(s) selected
            </span>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleBulkStatusUpdate('acknowledged')}
                className="px-3 py-1 text-sm bg-yellow-100 text-yellow-800 rounded-md hover:bg-yellow-200"
              >
                Acknowledge
              </button>
              <button
                onClick={() => handleBulkStatusUpdate('resolved')}
                className="px-3 py-1 text-sm bg-green-100 text-green-800 rounded-md hover:bg-green-200"
              >
                Resolve
              </button>
              <button
                onClick={() => setSelectedAlerts(new Set())}
                className="px-3 py-1 text-sm bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200"
              >
                Clear Selection
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left">
                <input
                  type="checkbox"
                  checked={selectedAlerts.size === filteredAndSortedAlerts.length && filteredAndSortedAlerts.length > 0}
                  onChange={handleSelectAll}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('severity')}
              >
                <div className="flex items-center space-x-1">
                  <span>Severity</span>
                  <ChevronUpDownIcon className="w-4 h-4" />
                </div>
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('title')}
              >
                <div className="flex items-center space-x-1">
                  <span>Alert</span>
                  <ChevronUpDownIcon className="w-4 h-4" />
                </div>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Resource
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Service
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('risk_score')}
              >
                <div className="flex items-center space-x-1">
                  <span>Risk Score</span>
                  <ChevronUpDownIcon className="w-4 h-4" />
                </div>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('created_at')}
              >
                <div className="flex items-center space-x-1">
                  <span>Created</span>
                  <ChevronUpDownIcon className="w-4 h-4" />
                </div>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredAndSortedAlerts.map((alert) => (
              <tr 
                key={alert.id}
                className={`hover:bg-gray-50 ${selectedAlerts.has(alert.id) ? 'bg-blue-50' : ''}`}
              >
                <td className="px-6 py-4">
                  <input
                    type="checkbox"
                    checked={selectedAlerts.has(alert.id)}
                    onChange={() => handleSelectAlert(alert.id)}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </td>
                <td className="px-6 py-4">
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="px-6 py-4">
                  <div className="max-w-xs">
                    <div className="text-sm font-medium text-gray-900 truncate">
                      {alert.title}
                    </div>
                    <div className="text-sm text-gray-500 truncate">
                      {alert.description}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm text-gray-900">{alert.resource_id || 'N/A'}</div>
                  <div className="text-sm text-gray-500">{alert.resource_type || ''}</div>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm text-gray-900">{alert.service?.toUpperCase() || 'N/A'}</div>
                  <div className="text-sm text-gray-500">{alert.cloud_provider?.toUpperCase() || ''}</div>
                </td>
                <td className="px-6 py-4">
                  <span className={`text-sm font-medium ${getRiskScoreColor(alert.risk_score || 0)}`}>
                    {(alert.risk_score || 0).toFixed(1)}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <StatusBadge status={alert.status} />
                </td>
                <td className="px-6 py-4 text-sm text-gray-500">
                  {alert.created_at ? formatDate(alert.created_at) : 'N/A'}
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => onViewDetails && onViewDetails(alert)}
                      className="text-blue-600 hover:text-blue-800"
                      title="View Details"
                    >
                      <EyeIcon className="w-4 h-4" />
                    </button>
                    
                    {alert.status === 'open' && (
                      <button
                        onClick={() => onUpdateStatus && onUpdateStatus(alert.id, 'acknowledged')}
                        className="text-yellow-600 hover:text-yellow-800"
                        title="Acknowledge"
                      >
                        <CheckCircleIcon className="w-4 h-4" />
                      </button>
                    )}
                    
                    {(alert.status === 'open' || alert.status === 'acknowledged') && (
                      <button
                        onClick={() => onUpdateStatus && onUpdateStatus(alert.id, 'resolved')}
                        className="text-green-600 hover:text-green-800"
                        title="Resolve"
                      >
                        <CheckCircleIcon className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredAndSortedAlerts.length === 0 && (
          <div className="text-center py-12">
            <ShieldExclamationIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {alerts.length === 0 
                ? "No security alerts have been generated yet."
                : "No alerts match the current filters."
              }
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertTable;
