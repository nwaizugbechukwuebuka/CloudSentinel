import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { alertAPI } from '../services/api'
import {
  ExclamationTriangleIcon,
  CheckIcon,
  XMarkIcon,
  EyeIcon
} from '@heroicons/react/24/outline'

export default function Alerts() {
  const [filters, setFilters] = useState({})
  const [selectedAlert, setSelectedAlert] = useState(null)
  const queryClient = useQueryClient()

  const { data: alerts, isLoading } = useQuery(
    ['alerts', filters],
    () => alertAPI.getAlerts(filters),
    {
      select: (response) => response.data
    }
  )

  const { data: alertStats } = useQuery(
    'alert-stats',
    alertAPI.getAlertStats,
    {
      select: (response) => response.data
    }
  )

  const acknowledgeMutation = useMutation(alertAPI.acknowledgeAlert, {
    onSuccess: () => {
      queryClient.invalidateQueries('alerts')
      queryClient.invalidateQueries('alert-stats')
    }
  })

  const resolveMutation = useMutation(alertAPI.resolveAlert, {
    onSuccess: () => {
      queryClient.invalidateQueries('alerts')
      queryClient.invalidateQueries('alert-stats')
    }
  })

  const getSeverityBadge = (severity) => {
    const badges = {
      critical: 'badge badge-critical',
      high: 'badge badge-high',
      medium: 'badge badge-medium',
      low: 'badge badge-low'
    }
    return badges[severity] || badges.low
  }

  const getStatusBadge = (status) => {
    const badges = {
      open: 'badge status-open',
      investigating: 'badge status-investigating',
      resolved: 'badge status-resolved',
      closed: 'badge status-closed'
    }
    return badges[status] || badges.open
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Alerts</h1>
        <p className="mt-2 text-sm text-gray-600">
          Monitor and manage security alerts from your scans
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-4">
        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
              </div>
              <div className="ml-5">
                <p className="text-sm font-medium text-gray-500">Total Alerts</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {alertStats?.total_alerts || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-8 w-8 text-yellow-600" />
              </div>
              <div className="ml-5">
                <p className="text-sm font-medium text-gray-500">Open Alerts</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {alertStats?.open_alerts || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
              </div>
              <div className="ml-5">
                <p className="text-sm font-medium text-gray-500">Critical</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {alertStats?.severity_distribution?.critical || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-8 w-8 text-orange-600" />
              </div>
              <div className="ml-5">
                <p className="text-sm font-medium text-gray-500">High</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {alertStats?.severity_distribution?.high || 0}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="card-body">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
            <select
              onChange={(e) => setFilters({...filters, severity: e.target.value || undefined})}
              className="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              onChange={(e) => setFilters({...filters, status: e.target.value || undefined})}
              className="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>

            <select
              onChange={(e) => setFilters({...filters, risk_level: e.target.value || undefined})}
              className="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <button
              onClick={() => setFilters({})}
              className="btn-secondary"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="card">
        <div className="card-body p-0">
          {alerts && alerts.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="table">
                <thead className="table-header">
                  <tr>
                    <th className="table-header-cell">Title</th>
                    <th className="table-header-cell">Severity</th>
                    <th className="table-header-cell">Status</th>
                    <th className="table-header-cell">Risk Level</th>
                    <th className="table-header-cell">Created</th>
                    <th className="table-header-cell">Actions</th>
                  </tr>
                </thead>
                <tbody className="table-body">
                  {alerts.map((alert) => (
                    <tr key={alert.id}>
                      <td className="table-cell">
                        <div>
                          <p className="font-medium text-gray-900">{alert.title}</p>
                          <p className="text-sm text-gray-500 truncate max-w-md">
                            {alert.description}
                          </p>
                        </div>
                      </td>
                      <td className="table-cell">
                        <span className={getSeverityBadge(alert.severity)}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="table-cell">
                        <span className={getStatusBadge(alert.status)}>
                          {alert.status}
                        </span>
                      </td>
                      <td className="table-cell">
                        <span className={`badge badge-${alert.risk_level}`}>
                          {alert.risk_level}
                        </span>
                      </td>
                      <td className="table-cell text-gray-500">
                        {new Date(alert.created_at).toLocaleDateString()}
                      </td>
                      <td className="table-cell">
                        <div className="flex space-x-2">
                          <button
                            onClick={() => setSelectedAlert(alert)}
                            className="text-indigo-600 hover:text-indigo-900"
                            title="View Details"
                          >
                            <EyeIcon className="h-4 w-4" />
                          </button>
                          {alert.status === 'open' && !alert.is_acknowledged && (
                            <button
                              onClick={() => acknowledgeMutation.mutate(alert.alert_id)}
                              className="text-yellow-600 hover:text-yellow-900"
                              title="Acknowledge"
                              disabled={acknowledgeMutation.isLoading}
                            >
                              <CheckIcon className="h-4 w-4" />
                            </button>
                          )}
                          {alert.status !== 'resolved' && (
                            <button
                              onClick={() => resolveMutation.mutate(alert.alert_id)}
                              className="text-green-600 hover:text-green-900"
                              title="Resolve"
                              disabled={resolveMutation.isLoading}
                            >
                              <XMarkIcon className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12">
              <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts</h3>
              <p className="mt-1 text-sm text-gray-500">
                No security alerts found with the current filters.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  )
}

function AlertDetailModal({ alert, onClose }) {
  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-2/3 max-w-2xl shadow-lg rounded-md bg-white">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-medium text-gray-900">Alert Details</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            ×
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <h4 className="font-medium text-gray-900">{alert.title}</h4>
            <div className="mt-2 flex space-x-2">
              <span className={`badge badge-${alert.severity}`}>
                {alert.severity}
              </span>
              <span className={`badge badge-${alert.risk_level}`}>
                {alert.risk_level}
              </span>
              <span className={`badge status-${alert.status}`}>
                {alert.status}
              </span>
            </div>
          </div>

          <div>
            <h5 className="font-medium text-gray-700">Description</h5>
            <p className="mt-1 text-sm text-gray-600">{alert.description}</p>
          </div>

          {alert.remediation_steps && (
            <div>
              <h5 className="font-medium text-gray-700">Remediation Steps</h5>
              <p className="mt-1 text-sm text-gray-600">{alert.remediation_steps}</p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h5 className="font-medium text-gray-700">Created</h5>
              <p className="text-sm text-gray-600">
                {new Date(alert.created_at).toLocaleString()}
              </p>
            </div>
            {alert.acknowledged_at && (
              <div>
                <h5 className="font-medium text-gray-700">Acknowledged</h5>
                <p className="text-sm text-gray-600">
                  {new Date(alert.acknowledged_at).toLocaleString()}
                </p>
              </div>
            )}
          </div>

          <div className="flex justify-end pt-4">
            <button onClick={onClose} className="btn-secondary">
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
