import React, { useState } from 'react';

const LiveLogStream = ({ logs }) => {
  const [filterType, setFilterType] = useState('ALL');
  const [showDetails, setShowDetails] = useState(false);

  const filteredLogs = filterType === 'ALL' 
    ? logs 
    : logs.filter(log => log.type === filterType);

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getConfidenceColor = (confidence) => {
    if (confidence > 0.8) return '#ef4444'; // High confidence - red
    if (confidence > 0.6) return '#fb923c'; // Medium confidence - orange
    return '#22c55e'; // Low confidence - green
  };

  const getFeatureAlert = (features) => {
    const alerts = [];
    if (features.headerEntropy < 1.5) alerts.push('Low Header Entropy');
    if (features.burstiness > 3.0) alerts.push('High Burstiness');
    if (features.nightActivity > 0.8) alerts.push('Night Activity');
    return alerts;
  };

  return (
    <div className="live-log-stream">
      <div className="component-header">
        <span className="icon">📡</span>
        <h2>Live WAF Logs Stream</h2>
        <div className="stream-controls">
          <select 
            value={filterType} 
            onChange={(e) => setFilterType(e.target.value)}
            className="filter-select"
          >
            <option value="ALL">All Traffic</option>
            <option value="HUMAN">Human Only</option>
            <option value="BOT">Bot Only</option>
            <option value="BLOCKED">Blocked Only</option>
          </select>
          <button 
            onClick={() => setShowDetails(!showDetails)}
            className={`details-toggle ${showDetails ? 'active' : ''}`}
          >
            {showDetails ? 'Hide Details' : 'Show Details'}
          </button>
        </div>
      </div>

      <div className="log-stats">
        <div className="stat-item">
          <span className="stat-label">Total Logs:</span>
          <span className="stat-value">{logs.length}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Filtered:</span>
          <span className="stat-value">{filteredLogs.length}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Update Rate:</span>
          <span className="stat-value">2s</span>
        </div>
      </div>

      <div className="log-stream">
        {filteredLogs.slice(0, 20).map(log => (
          <div key={log.id} className={`log-entry ${log.type}`}>
            <div className="log-basic-info">
              <span className="log-timestamp">{formatTimestamp(log.timestamp)}</span>
              <span className={`log-type ${log.type}`}>{log.type}</span>
              <span className="log-ip">{log.ip}</span>
              <span className="log-path">{log.path}</span>
              {log.type !== 'HUMAN' && (
                <span 
                  className="log-confidence"
                  style={{ color: getConfidenceColor(log.confidence) }}
                >
                  {(log.confidence * 100).toFixed(0)}%
                </span>
              )}
            </div>
            
            {showDetails && (
              <div className="log-details">
                <div className="log-detail-row">
                  <span className="detail-label">User-Agent:</span>
                  <span className="detail-value">{log.userAgent}</span>
                </div>
                
                {log.type !== 'HUMAN' && (
                  <>
                    <div className="log-detail-row">
                      <span className="detail-label">ML Features:</span>
                      <div className="feature-values">
                        <span className="feature-value">
                          Entropy: {log.features.headerEntropy.toFixed(2)}
                        </span>
                        <span className="feature-value">
                          Burstiness: {log.features.burstiness.toFixed(2)}
                        </span>
                        <span className="feature-value">
                          Night Activity: {(log.features.nightActivity * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                    
                    {getFeatureAlert(log.features).length > 0 && (
                      <div className="log-detail-row">
                        <span className="detail-label">Alerts:</span>
                        <div className="feature-alerts">
                          {getFeatureAlert(log.features).map((alert, index) => (
                            <span key={index} className="feature-alert">{alert}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="log-explanation">
        <h4>📋 What You're Seeing:</h4>
        <div className="explanation-grid">
          <div className="explanation-item">
            <span className="explanation-icon">🟢</span>
            <span><strong>HUMAN:</strong> Normal behavioral patterns detected</span>
          </div>
          <div className="explanation-item">
            <span className="explanation-icon">🔴</span>
            <span><strong>BOT:</strong> Automated patterns identified by ML</span>
          </div>
          <div className="explanation-item">
            <span className="explanation-icon">🟠</span>
            <span><strong>BLOCKED:</strong> Advanced Attack Traffic blocked by WAF rules</span>
          </div>
          <div className="explanation-item">
            <span className="explanation-icon">🎯</span>
            <span><strong>Confidence:</strong> ML model certainty (higher = more confident)</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LiveLogStream;
