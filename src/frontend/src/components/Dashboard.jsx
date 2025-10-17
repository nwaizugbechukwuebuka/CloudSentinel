import React from 'react'
import { useQuery } from 'react-query'
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar
} from 'recharts'
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  ClockIcon
} from '@heroicons/react/24/outline'
import { reportAPI } from '../services/api'

export default function Dashboard() {
  const { data: summary, isLoading } = useQuery(
    'dashboard-summary',
    reportAPI.getDashboardSummary,
    {
      select: (response) => response.data
    }
  )

  const getRiskColor = (riskLevel) => {
    const colors = {
      critical: '#DC2626',
      high: '#EA580C',
      medium: '#D97706',
      low: '#2563EB',
      info: '#6B7280'
    }
    return colors[riskLevel] || colors.info
  }

  const riskData = summary?.risk_distribution ? 
    Object.entries(summary.risk_distribution).map(([level, count]) => ({
      name: level.charAt(0).toUpperCase() + level.slice(1),
      value: count,
      color: getRiskColor(level)
    })) : []

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
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-2 text-sm text-gray-600">
          Monitor your cloud infrastructure security posture
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Total Scans"
          value={summary?.total_scans || 0}
          icon={ChartBarIcon}
          color="text-blue-600"
          bgColor="bg-blue-100"
        />
        <StatsCard
          title="Total Findings"
          value={summary?.total_findings || 0}
          icon={ShieldExclamationIcon}
          color="text-yellow-600"
          bgColor="bg-yellow-100"
        />
        <StatsCard
          title="Open Alerts"
          value={summary?.open_alerts || 0}
          icon={ExclamationTriangleIcon}
          color="text-red-600"
          bgColor="bg-red-100"
        />
        <StatsCard
          title="Recent Scans"
          value={summary?.recent_scans || 0}
          subtitle="Last 7 days"
          icon={ClockIcon}
          color="text-green-600"
          bgColor="bg-green-100"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Risk Distribution */}
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900">Risk Distribution</h3>
          </div>
          <div className="card-body">
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {riskData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900">Recent Activity</h3>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              {summary?.recent_scans > 0 ? (
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <ShieldExclamationIcon className="h-5 w-5 text-green-500" />
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-gray-900">
                      {summary.recent_scans} scans completed in the last 7 days
                    </p>
                    <p className="text-sm text-gray-500">
                      {summary.total_findings} total findings discovered
                    </p>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <ShieldExclamationIcon className="mx-auto h-12 w-12 text-gray-400" />
                  <h3 className="mt-2 text-sm font-medium text-gray-900">No recent scans</h3>
                  <p className="mt-1 text-sm text-gray-500">
                    Get started by running your first security scan.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900">Quick Actions</h3>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <button className="btn-primary">
              Start New Scan
            </button>
            <button className="btn-secondary">
              View All Alerts
            </button>
            <button className="btn-secondary">
              Generate Report
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function StatsCard({ title, value, subtitle, icon: Icon, color, bgColor }) {
  return (
    <div className="card">
      <div className="card-body">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <div className={`${bgColor} rounded-md p-3`}>
              <Icon className={`h-6 w-6 ${color}`} />
            </div>
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 truncate">
                {title}
              </dt>
              <dd className="flex items-baseline">
                <div className="text-2xl font-semibold text-gray-900">
                  {value.toLocaleString()}
                </div>
                {subtitle && (
                  <div className="ml-2 flex items-baseline text-sm text-gray-600">
                    {subtitle}
                  </div>
                )}
              </dd>
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}
