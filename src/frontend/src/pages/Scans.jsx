import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { useForm } from 'react-hook-form'
import { scanAPI } from '../services/api'
import {
  PlusIcon,
  CloudIcon,
  PlayIcon,
  EyeIcon,
  DocumentArrowDownIcon
} from '@heroicons/react/24/outline'

export default function Scans() {
  const [showNewScanModal, setShowNewScanModal] = useState(false)
  const queryClient = useQueryClient()

  const { data: scanHistory, isLoading } = useQuery(
    'scan-history',
    () => scanAPI.getScanHistory(),
    {
      select: (response) => response.data
    }
  )

  const { data: providers } = useQuery(
    'supported-providers',
    () => scanAPI.getSupportedProviders(),
    {
      select: (response) => response.data.providers
    }
  )

  const startScanMutation = useMutation(scanAPI.startScan, {
    onSuccess: () => {
      queryClient.invalidateQueries('scan-history')
      setShowNewScanModal(false)
    }
  })

  const getRiskLevelBadge = (riskLevel) => {
    const badges = {
      critical: 'badge badge-critical',
      high: 'badge badge-high',
      medium: 'badge badge-medium',
      low: 'badge badge-low',
      info: 'badge badge-info'
    }
    return badges[riskLevel] || badges.info
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
      <div className="sm:flex sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Scans</h1>
          <p className="mt-2 text-sm text-gray-600">
            Manage and monitor cloud security scans
          </p>
        </div>
        <div className="mt-4 sm:mt-0">
          <button
            onClick={() => setShowNewScanModal(true)}
            className="btn-primary"
          >
            <PlusIcon className="h-4 w-4 mr-2" />
            New Scan
          </button>
        </div>
      </div>

      {/* Scan History */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900">Scan History</h3>
        </div>
        <div className="card-body p-0">
          {scanHistory && scanHistory.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="table">
                <thead className="table-header">
                  <tr>
                    <th className="table-header-cell">Scan ID</th>
                    <th className="table-header-cell">Status</th>
                    <th className="table-header-cell">Provider</th>
                    <th className="table-header-cell">Findings</th>
                    <th className="table-header-cell">Date</th>
                    <th className="table-header-cell">Actions</th>
                  </tr>
                </thead>
                <tbody className="table-body">
                  {scanHistory.map((scan) => (
                    <tr key={scan.scan_id}>
                      <td className="table-cell font-mono text-sm">
                        {scan.scan_id.slice(0, 8)}...
                      </td>
                      <td className="table-cell">
                        <span className={`badge ${
                          scan.status === 'completed' ? 'bg-green-100 text-green-800' :
                          scan.status === 'running' ? 'bg-yellow-100 text-yellow-800' :
                          scan.status === 'failed' ? 'bg-red-100 text-red-800' :
                          'bg-gray-100 text-gray-800'
                        }`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="table-cell">
                        <div className="flex items-center">
                          <CloudIcon className="h-4 w-4 mr-2 text-gray-400" />
                          {Object.keys(scan.provider_distribution || {})[0] || 'N/A'}
                        </div>
                      </td>
                      <td className="table-cell">
                        <div className="flex space-x-2">
                          {Object.entries(scan.risk_distribution || {}).map(([level, count]) => (
                            <span key={level} className={getRiskLevelBadge(level)}>
                              {count}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="table-cell text-gray-500">
                        {new Date(scan.scan_date).toLocaleDateString()}
                      </td>
                      <td className="table-cell">
                        <div className="flex space-x-2">
                          <button
                            className="text-indigo-600 hover:text-indigo-900"
                            title="View Results"
                          >
                            <EyeIcon className="h-4 w-4" />
                          </button>
                          <button
                            className="text-gray-600 hover:text-gray-900"
                            title="Export"
                          >
                            <DocumentArrowDownIcon className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12">
              <CloudIcon className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">No scans yet</h3>
              <p className="mt-1 text-sm text-gray-500">
                Get started by creating your first security scan.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* New Scan Modal */}
      {showNewScanModal && (
        <NewScanModal
          providers={providers}
          onClose={() => setShowNewScanModal(false)}
          onSubmit={(data) => startScanMutation.mutate(data)}
          isLoading={startScanMutation.isLoading}
        />
      )}
    </div>
  )
}

function NewScanModal({ providers, onClose, onSubmit, isLoading }) {
  const { register, handleSubmit, watch, formState: { errors } } = useForm()
  const selectedProvider = watch('provider')

  const onSubmitForm = (data) => {
    // Convert credentials to object
    const credentials = {}
    const provider = providers?.find(p => p.name === data.provider)
    
    if (provider) {
      provider.required_credentials.forEach(field => {
        credentials[field] = data[field]
      })
    }

    onSubmit({
      provider: data.provider,
      credentials,
      scan_types: data.scan_types || ['storage', 'iam', 'network', 'compute']
    })
  }

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
        <form onSubmit={handleSubmit(onSubmitForm)} className="space-y-4">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-medium text-gray-900">New Security Scan</h3>
            <button
              type="button"
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
            >
              ×
            </button>
          </div>

          {/* Provider Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Cloud Provider
            </label>
            <select
              {...register('provider', { required: 'Provider is required' })}
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="">Select a provider</option>
              {providers?.map(provider => (
                <option key={provider.name} value={provider.name}>
                  {provider.display_name}
                </option>
              ))}
            </select>
            {errors.provider && (
              <p className="mt-1 text-sm text-red-600">{errors.provider.message}</p>
            )}
          </div>

          {/* Credentials */}
          {selectedProvider && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-gray-700">Credentials</h4>
              {providers?.find(p => p.name === selectedProvider)?.required_credentials.map(field => (
                <div key={field}>
                  <label className="block text-sm font-medium text-gray-700">
                    {field.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </label>
                  <input
                    {...register(field, { required: `${field} is required` })}
                    type={field.includes('secret') || field.includes('password') ? 'password' : 'text'}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  {errors[field] && (
                    <p className="mt-1 text-sm text-red-600">{errors[field].message}</p>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="btn-primary"
            >
              {isLoading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Starting...
                </>
              ) : (
                <>
                  <PlayIcon className="h-4 w-4 mr-2" />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
