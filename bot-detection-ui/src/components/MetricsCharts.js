import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const MetricsCharts = ({ data }) => {
  // Ensure data is always an array and has at least one element
  const safeData = Array.isArray(data) && data.length > 0 ? data : [
    { bots: 0, humans: 0, blocked: 0 }
  ];
  
  const currentData = safeData[safeData.length - 1] || { bots: 0, humans: 0, blocked: 0 };
  
  const pieData = [
    { name: 'Human Traffic', value: currentData.humans || 0, color: '#22c55e' },
    { name: 'Advanced Attack Traffic', value: currentData.bots || 0, color: '#ef4444' },
    { name: 'Blocked Traffic', value: currentData.blocked || 0, color: '#fb923c' }
  ].filter(item => typeof item.value === 'number' && item.value >= 0);

  const totalTraffic = (currentData.humans || 0) + (currentData.bots || 0) + (currentData.blocked || 0);
  const botDetectionRate = totalTraffic > 0 ? (((currentData.bots || 0) + (currentData.blocked || 0)) / totalTraffic * 100) : 0;
  const blockingEffectiveness = ((currentData.bots || 0) + (currentData.blocked || 0)) > 0 ? ((currentData.blocked || 0) / ((currentData.bots || 0) + (currentData.blocked || 0)) * 100) : 0;

  // Calculate recent trends
  const recentData = safeData.slice(-5);
  const avgBots = recentData.length > 0 ? recentData.reduce((sum, d) => sum + (d.bots || 0), 0) / recentData.length : 0;
  const avgBlocked = recentData.length > 0 ? recentData.reduce((sum, d) => sum + (d.blocked || 0), 0) / recentData.length : 0;

  return (
    <div className="metrics-charts">
      <div className="component-header">
        <span className="icon">📈</span>
        <h2>Analytics Dashboard</h2>
      </div>

      <div className="chart-container">
        <h3>Traffic Distribution</h3>
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie
              data={pieData.length > 0 ? pieData : [{ name: 'No Data', value: 1, color: '#64748b' }]}
              cx="50%"
              cy="50%"
              outerRadius={70}
              fill="#8884d8"
              dataKey="value"
              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
              labelLine={false}
            >
              {pieData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip 
              contentStyle={{
                backgroundColor: 'rgba(30, 41, 59, 0.95)',
                border: '1px solid #475569',
                borderRadius: '8px',
                color: '#f1f5f9'
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="effectiveness-metrics">
        <h3>Effectiveness Metrics</h3>
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-value">{botDetectionRate.toFixed(1)}%</div>
            <div className="metric-label">Bot Detection Rate</div>
          </div>
          <div className="metric-card">
            <div className="metric-value">{blockingEffectiveness.toFixed(1)}%</div>
            <div className="metric-label">Blocking Effectiveness</div>
          </div>
        </div>
      </div>

      <div className="trend-analysis">
        <h4>Recent Trends (Last 5 intervals):</h4>
        <div className="trend-items">
          <div className="trend-item">
            <span className="trend-label">Avg Advanced Attack Traffic:</span>
            <span className="trend-value">{avgBots.toFixed(1)}</span>
          </div>
          <div className="trend-item">
            <span className="trend-label">Avg Blocked:</span>
            <span className="trend-value">{avgBlocked.toFixed(1)}</span>
          </div>
          <div className="trend-item">
            <span className="trend-label">Security Status:</span>
            <span className={`trend-value status ${blockingEffectiveness > 70 ? 'good' : blockingEffectiveness > 40 ? 'warning' : 'alert'}`}>
              {blockingEffectiveness > 70 ? '🟢 Secure' : blockingEffectiveness > 40 ? '🟡 Moderate' : '🔴 Alert'}
            </span>
          </div>
        </div>
      </div>

      <div className="demo-explanation">
        <h4>💡 Demo Highlights:</h4>
        <div className="highlight-items">
          <div className="highlight-item">
            <span className="highlight-icon">🎯</span>
            <span>Behavioral detection catches disguised bots</span>
          </div>
          <div className="highlight-item">
            <span className="highlight-icon">⚡</span>
            <span>Real-time ML model decisions</span>
          </div>
          <div className="highlight-item">
            <span className="highlight-icon">🛡️</span>
            <span>Automated WAF rule deployment</span>
          </div>
          <div className="highlight-item">
            <span className="highlight-icon">☕</span>
            <span>HTTP 418 responses for blocked bots</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MetricsCharts;
