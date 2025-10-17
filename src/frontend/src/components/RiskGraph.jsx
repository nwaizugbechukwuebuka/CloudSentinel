import React, { useState } from 'react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  RadialBarChart,
  RadialBar
} from 'recharts';
import {
  ChartBarIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  MinusIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

const RiskGraph = ({ 
  data = [], 
  type = 'line',
  title = 'Risk Trends',
  showControls = true,
  height = 300,
  loading = false 
}) => {
  const [chartType, setChartType] = useState(type);
  const [timeRange, setTimeRange] = useState('30d');

  // Color palette for charts
  const colors = {
    primary: '#3B82F6',
    secondary: '#EF4444',
    success: '#10B981',
    warning: '#F59E0B',
    info: '#6366F1',
    critical: '#DC2626',
    high: '#EA580C',
    medium: '#D97706',
    low: '#059669'
  };

  const severityColors = ['#DC2626', '#EA580C', '#D97706', '#059669'];

  // Mock data for different chart types if no data provided
  const getDefaultData = () => {
    const now = new Date();
    const defaultData = [];
    for (let i = 29; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      defaultData.push({
        date: date.toISOString().split('T')[0],
        riskScore: Math.random() * 10,
        critical: Math.floor(Math.random() * 5),
        high: Math.floor(Math.random() * 10),
        medium: Math.floor(Math.random() * 15),
        low: Math.floor(Math.random() * 20),
        totalFindings: Math.floor(Math.random() * 50) + 10,
        complianceScore: Math.random() * 100
      });
    }
    return defaultData;
  };

  const chartData = data.length > 0 ? data : getDefaultData();
  
  // Calculate trend
  const calculateTrend = () => {
    if (chartData.length < 2) return { trend: 'stable', change: 0 };
    
    const recent = chartData.slice(-7).reduce((sum, item) => sum + (item.riskScore || 0), 0) / 7;
    const previous = chartData.slice(-14, -7).reduce((sum, item) => sum + (item.riskScore || 0), 0) / 7;
    
    const change = ((recent - previous) / previous * 100) || 0;
    
    let trend = 'stable';
    if (change > 5) trend = 'declining'; // Higher risk score is worse
    else if (change < -5) trend = 'improving';
    
    return { trend, change: Math.abs(change) };
  };

  const { trend, change } = calculateTrend();

  const getTrendIcon = () => {
    switch (trend) {
      case 'improving':
        return <ArrowTrendingUpIcon className="w-5 h-5 text-green-500" />;
      case 'declining':
        return <ArrowTrendingDownIcon className="w-5 h-5 text-red-500" />;
      default:
        return <MinusIcon className="w-5 h-5 text-gray-400" />;
    }
  };

  const getTrendText = () => {
    switch (trend) {
      case 'improving':
        return `Risk decreased by ${change.toFixed(1)}%`;
      case 'declining':
        return `Risk increased by ${change.toFixed(1)}%`;
      default:
        return 'Risk level stable';
    }
  };

  // Custom tooltip component
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="text-sm font-medium text-gray-900 mb-2">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name}: ${typeof entry.value === 'number' ? entry.value.toFixed(1) : entry.value}`}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  // Prepare pie chart data for severity distribution
  const severityData = [
    { name: 'Critical', value: chartData.reduce((sum, item) => sum + (item.critical || 0), 0), color: colors.critical },
    { name: 'High', value: chartData.reduce((sum, item) => sum + (item.high || 0), 0), color: colors.high },
    { name: 'Medium', value: chartData.reduce((sum, item) => sum + (item.medium || 0), 0), color: colors.medium },
    { name: 'Low', value: chartData.reduce((sum, item) => sum + (item.low || 0), 0), color: colors.low }
  ];

  // Risk score gauge data
  const currentRiskScore = chartData.length > 0 ? chartData[chartData.length - 1].riskScore || 0 : 0;
  const gaugeData = [
    { name: 'Risk Score', value: currentRiskScore, fill: currentRiskScore > 7 ? colors.critical : currentRiskScore > 4 ? colors.warning : colors.success }
  ];

  const renderChart = () => {
    switch (chartType) {
      case 'area':
        return (
          <ResponsiveContainer width="100%" height={height}>
            <AreaChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis 
                dataKey="date" 
                stroke="#6b7280"
                fontSize={12}
                tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
              />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip content={<CustomTooltip />} />
              <Area 
                type="monotone" 
                dataKey="riskScore" 
                stroke={colors.primary} 
                fill={colors.primary}
                fillOpacity={0.3}
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        );

      case 'bar':
        return (
          <ResponsiveContainer width="100%" height={height}>
            <BarChart data={chartData.slice(-10)}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis 
                dataKey="date" 
                stroke="#6b7280"
                fontSize={12}
                tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
              />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="critical" stackId="a" fill={colors.critical} />
              <Bar dataKey="high" stackId="a" fill={colors.high} />
              <Bar dataKey="medium" stackId="a" fill={colors.medium} />
              <Bar dataKey="low" stackId="a" fill={colors.low} />
            </BarChart>
          </ResponsiveContainer>
        );

      case 'pie':
        return (
          <div className="flex justify-center">
            <ResponsiveContainer width="100%" height={height}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        );

      case 'gauge':
        return (
          <div className="flex justify-center">
            <ResponsiveContainer width="100%" height={height}>
              <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="90%" data={gaugeData}>
                <RadialBar
                  minAngle={15}
                  label={{ position: 'insideStart', fill: '#fff' }}
                  background
                  clockWise
                  dataKey="value"
                />
                <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle" className="text-2xl font-bold">
                  {currentRiskScore.toFixed(1)}
                </text>
              </RadialBarChart>
            </ResponsiveContainer>
          </div>
        );

      default: // line chart
        return (
          <ResponsiveContainer width="100%" height={height}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis 
                dataKey="date" 
                stroke="#6b7280"
                fontSize={12}
                tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
              />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip content={<CustomTooltip />} />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="riskScore" 
                stroke={colors.primary} 
                strokeWidth={3}
                dot={{ fill: colors.primary, strokeWidth: 2, r: 4 }}
                name="Risk Score"
              />
              <Line 
                type="monotone" 
                dataKey="complianceScore" 
                stroke={colors.success} 
                strokeWidth={2}
                dot={{ fill: colors.success, strokeWidth: 2, r: 3 }}
                name="Compliance %"
              />
            </LineChart>
          </ResponsiveContainer>
        );
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 rounded w-1/3 mb-4"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <ChartBarIcon className="w-6 h-6 text-gray-500" />
            <h3 className="text-lg font-medium text-gray-900">{title}</h3>
          </div>
          
          {/* Trend Indicator */}
          <div className="flex items-center space-x-2">
            {getTrendIcon()}
            <span className={`text-sm font-medium ${
              trend === 'improving' ? 'text-green-600' :
              trend === 'declining' ? 'text-red-600' : 'text-gray-600'
            }`}>
              {getTrendText()}
            </span>
          </div>
        </div>

        {/* Controls */}
        {showControls && (
          <div className="mt-4 flex flex-wrap items-center gap-4">
            <div className="flex items-center space-x-2">
              <label className="text-sm text-gray-600">Chart Type:</label>
              <select
                value={chartType}
                onChange={(e) => setChartType(e.target.value)}
                className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="line">Line Chart</option>
                <option value="area">Area Chart</option>
                <option value="bar">Bar Chart</option>
                <option value="pie">Pie Chart</option>
                <option value="gauge">Risk Gauge</option>
              </select>
            </div>
            
            <div className="flex items-center space-x-2">
              <label className="text-sm text-gray-600">Time Range:</label>
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="90d">Last 90 days</option>
                <option value="1y">Last year</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Chart Content */}
      <div className="p-6">
        {chartData.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-gray-500">
            <ChartBarIcon className="w-12 h-12 mb-3" />
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Start a security scan to see risk trends</p>
          </div>
        ) : (
          renderChart()
        )}
      </div>

      {/* Summary Stats */}
      {chartData.length > 0 && (
        <div className="px-6 py-4 bg-gray-50 rounded-b-lg border-t border-gray-200">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-sm text-gray-600">Current Risk</p>
              <p className={`text-lg font-bold ${
                currentRiskScore > 7 ? 'text-red-600' :
                currentRiskScore > 4 ? 'text-yellow-600' : 'text-green-600'
              }`}>
                {currentRiskScore.toFixed(1)}
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-600">Avg Risk</p>
              <p className="text-lg font-bold text-gray-900">
                {(chartData.reduce((sum, item) => sum + (item.riskScore || 0), 0) / chartData.length).toFixed(1)}
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-600">Total Findings</p>
              <p className="text-lg font-bold text-gray-900">
                {chartData.reduce((sum, item) => sum + (item.totalFindings || 0), 0)}
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-600">Compliance</p>
              <p className="text-lg font-bold text-blue-600">
                {chartData.length > 0 ? (chartData[chartData.length - 1].complianceScore || 0).toFixed(0) : 0}%
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Risk Level Warning */}
      {currentRiskScore > 7 && (
        <div className="mx-6 mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-start space-x-3">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-600 mt-0.5" />
            <div>
              <h4 className="text-sm font-medium text-red-900">High Risk Detected</h4>
              <p className="text-sm text-red-700 mt-1">
                Current risk score of {currentRiskScore.toFixed(1)} indicates critical security issues that require immediate attention.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RiskGraph;
