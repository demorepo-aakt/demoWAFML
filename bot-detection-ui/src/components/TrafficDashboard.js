import React from 'react';
import { XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area } from 'recharts';

const TrafficDashboard = ({ data }) => {
  // Ensure data is always an array and has at least one element
  const safeData = Array.isArray(data) && data.length > 0 ? data : [
    { 
      time: new Date().toLocaleTimeString(), 
      bots: 0, 
      humans: 0, 
      blocked: 0, 
      wafRuleTriggers: {},
      timestamp: new Date().toISOString()
    }
  ];
  
  const currentData = safeData[safeData.length - 1] || { bots: 0, humans: 0, blocked: 0, wafRuleTriggers: {} };
  const totalRequests = currentData.bots + currentData.humans + currentData.blocked;
  const wafRules = currentData.wafRuleTriggers || {};
  
  // Calculate total WAF rule triggers for current data
  const totalWafTriggers = Object.values(wafRules).reduce((sum, count) => sum + (count || 0), 0);
  
  // Enhance data with WAF rule triggers for the chart
  const enhancedData = safeData.map(point => ({
    time: point.time || new Date().toLocaleTimeString(),
    humans: point.humans || 0,
    bots: point.bots || 0,
    blocked: point.blocked || 0,
    wafTriggers: point.wafRuleTriggers ? 
      Object.values(point.wafRuleTriggers).reduce((sum, count) => sum + (count || 0), 0) : 0,
    timestamp: point.timestamp || new Date().toISOString()
  }));

  // Ensure we have at least one valid data point for the chart
  const chartData = enhancedData.filter(item => 
    typeof item.humans === 'number' && 
    typeof item.bots === 'number' && 
    typeof item.blocked === 'number' && 
    typeof item.wafTriggers === 'number'
  );
  
  if (chartData.length === 0) {
    chartData.push({
      time: new Date().toLocaleTimeString(),
      humans: 0,
      bots: 0,
      blocked: 0,
      wafTriggers: 0,
      timestamp: new Date().toISOString()
    });
  }

  return (
    <div className="traffic-dashboard">
      <div className="component-header">
        <span className="icon">📊</span>
        <h2>Real-Time Traffic Flow</h2>
      </div>
      
      <div className="traffic-indicators">
        <div className="traffic-indicator human">
          <div className="indicator-dot"></div>
          <span>Human Traffic: {currentData.humans}</span>
        </div>
        <div className="traffic-indicator bot">
          <div className="indicator-dot"></div>
          <span>Advanced Attack Traffic: {currentData.bots}</span>
        </div>
        <div className="traffic-indicator blocked">
          <div className="indicator-dot"></div>
          <span>Blocked: {currentData.blocked}</span>
        </div>
        <div className="traffic-indicator waf-rules">
          <div className="indicator-dot"></div>
          <span>WAF Rules: {totalWafTriggers}</span>
        </div>
      </div>



      <div className="chart-container">
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
            <XAxis 
              dataKey="time" 
              stroke="#94a3b8"
              fontSize={12}
            />
            <YAxis 
              stroke="#94a3b8"
              fontSize={12}
            />
            <Tooltip 
              contentStyle={{
                backgroundColor: 'rgba(30, 41, 59, 0.95)',
                border: '1px solid #475569',
                borderRadius: '8px',
                color: '#f1f5f9'
              }}
            />
            <Legend />
            <Area 
              type="monotone" 
              dataKey="humans" 
              stackId="1"
              stroke="#22c55e" 
              fill="rgba(34, 197, 94, 0.3)"
              name="Human Traffic"
            />
            <Area 
              type="monotone" 
              dataKey="bots" 
              stackId="1"
              stroke="#ef4444" 
              fill="rgba(239, 68, 68, 0.3)"
              name="Advanced Attack Traffic"
            />
            <Area 
              type="monotone" 
              dataKey="blocked" 
              stackId="1"
              stroke="#fb923c" 
              fill="rgba(251, 146, 60, 0.3)"
              name="Blocked Traffic"
            />
            <Area 
              type="monotone" 
              dataKey="wafTriggers" 
              stackId="1"
              stroke="#8b5cf6" 
              fill="rgba(139, 92, 246, 0.4)"
              name="WAF Rules Triggered"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="traffic-summary">
        <div className="summary-item">
          <span className="summary-label">Total Requests</span>
          <span className="summary-value">{totalRequests}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Block Rate</span>
          <span className="summary-value">
            {totalRequests > 0 ? Math.round((currentData.blocked / totalRequests) * 100) : 0}%
          </span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Bot Detection Rate</span>
          <span className="summary-value">
            {totalRequests > 0 ? Math.round(((currentData.bots + currentData.blocked) / totalRequests) * 100) : 0}%
          </span>
        </div>
      </div>
    </div>
  );
};

export default TrafficDashboard;
