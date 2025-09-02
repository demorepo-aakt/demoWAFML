import React, { useState, useEffect } from 'react';

const WAFRuleActivity = () => {
  const [timelineData, setTimelineData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchWAFTimeline = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('http://localhost:5000/api/waf/rule-timeline');
      const data = await response.json();
      
      if (data.status === 'success') {
        setTimelineData(data);
      } else if (data.status === 'no_bot_traffic') {
        setTimelineData(null);
        setError('Start Advanced Attack Traffic to see WAF rule activity');
      } else {
        setError(data.message || 'Failed to load WAF timeline');
      }
    } catch (err) {
      setError('Failed to connect to backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Initial fetch
    fetchWAFTimeline();
    
    // Poll every 10 seconds for updates
    const interval = setInterval(fetchWAFTimeline, 10000);
    
    return () => clearInterval(interval);
  }, []);

  const getIntensityColor = (intensity) => {
    switch (intensity) {
      case 'high': return '#ef4444'; // Red
      case 'medium': return '#f59e0b'; // Orange
      case 'low': return '#10b981'; // Green
      default: return '#6b7280'; // Gray
    }
  };

  const getIntensityIcon = (intensity) => {
    switch (intensity) {
      case 'high': return '🔥';
      case 'medium': return '⚡';
      case 'low': return '✅';
      default: return '📊';
    }
  };

  if (loading && !timelineData) {
    return (
      <div className="waf-rule-activity">
        <div className="component-header">
          <span className="icon">🛡️</span>
          <h2>WAF Rule Activity</h2>
        </div>
        <div className="loading-state">
          <div className="loading-spinner">🔄</div>
          <p>Loading WAF rule activity...</p>
        </div>
      </div>
    );
  }

  if (error && !timelineData) {
    return (
      <div className="waf-rule-activity">
        <div className="component-header">
          <span className="icon">🛡️</span>
          <h2>WAF Rule Activity</h2>
        </div>
        <div className="error-state">
          <div className="error-icon">⚠️</div>
          <p>{error}</p>
          <button onClick={fetchWAFTimeline} className="retry-button">
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!timelineData || !timelineData.timeline || timelineData.timeline.length === 0) {
    return (
      <div className="waf-rule-activity">
        <div className="component-header">
          <span className="icon">🛡️</span>
          <h2>WAF Rule Activity</h2>
        </div>
        <div className="no-data-state">
          <div className="no-data-icon">🤖</div>
                  <p>Start Advanced Attack Traffic to see WAF rules in action</p>
        <small>WAF rules will appear here once Advanced Attack Traffic triggers them</small>
        </div>
      </div>
    );
  }

  return (
    <div className="waf-rule-activity">
      <div className="component-header">
        <span className="icon">🛡️</span>
        <h2>WAF Rule Activity</h2>
        {loading && <div className="refresh-indicator">🔄</div>}
      </div>

      {/* Session Summary */}
      <div className="session-summary">
        <div className="summary-item">
          <span className="summary-label">Bot Session Time</span>
          <span className="summary-value">{timelineData.time_elapsed_minutes} min</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Total Requests</span>
          <span className="summary-value">{timelineData.total_requests}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Rule Triggers</span>
          <span className="summary-value">{timelineData.summary.total_rule_triggers}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">Active Rules</span>
          <span className="summary-value">{timelineData.summary.active_rules}</span>
        </div>
      </div>

      {/* Rule Activity List */}
      <div className="rule-activity-list">
        <h3>🎯 Rules Triggered by Advanced Attack Traffic</h3>
        {timelineData.timeline.map((rule, index) => (
          <div key={rule.rule_id} className={`rule-item intensity-${rule.intensity}`}>
            <div className="rule-header">
              <div className="rule-info">
                <span className="rule-icon">{getIntensityIcon(rule.intensity)}</span>
                <div className="rule-details">
                  <div className="rule-name">{rule.rule_name}</div>
                  <div className="rule-id">{rule.rule_id}</div>
                </div>
              </div>
              <div className="rule-stats">
                <div className="trigger-count">{rule.trigger_count}</div>
                <div className="trigger-rate">{rule.triggers_per_minute}/min</div>
              </div>
            </div>
            <div className="rule-progress">
              <div 
                className="progress-bar"
                style={{
                  width: `${Math.min((rule.trigger_count / Math.max(...timelineData.timeline.map(r => r.trigger_count))) * 100, 100)}%`,
                  backgroundColor: getIntensityColor(rule.intensity)
                }}
              ></div>
            </div>
          </div>
        ))}
      </div>

      {/* Most Active Rule Highlight */}
      {timelineData.summary.most_triggered_rule && (
        <div className="most-active-rule">
          <h4>🏆 Most Triggered Rule</h4>
          <div className="highlight-rule">
            <span className="rule-name">{timelineData.summary.most_triggered_rule}</span>
            <span className="trigger-count">
              {timelineData.timeline[0].trigger_count} triggers
            </span>
          </div>
        </div>
      )}

      {/* Real-time Status */}
      <div className="realtime-status">
        <div className="status-indicator active">
          <span className="status-dot"></span>
          <span>Live WAF monitoring since {new Date(timelineData.bot_start_time).toLocaleTimeString()}</span>
        </div>
      </div>
    </div>
  );
};

export default WAFRuleActivity;
