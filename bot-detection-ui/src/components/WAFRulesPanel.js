import React, { useEffect } from 'react';

const WAFRulesPanel = ({ rules, setRules }) => {
  // Simulate rule triggers
  useEffect(() => {
    const interval = setInterval(() => {
      setRules(prevRules => 
        prevRules.map(rule => ({
          ...rule,
          blockedCount: rule.blockedCount + Math.floor(Math.random() * 3)
        }))
      );
    }, 5000);

    return () => clearInterval(interval);
  }, [setRules]);

  const totalBlocked = rules.reduce((sum, rule) => sum + rule.blockedCount, 0);

  return (
    <div className="waf-rules-panel">
      <div className="component-header">
        <span className="icon">🛡️</span>
        <h2>WAF Rules Engine</h2>
      </div>

      <div className="rules-summary">
        <div className="summary-card">
          <div className="summary-value">{rules.filter(r => r.status === 'ACTIVE').length}</div>
          <div className="summary-label">Active Rules</div>
        </div>
        <div className="summary-card">
          <div className="summary-value">{totalBlocked}</div>
          <div className="summary-label">Total Blocked</div>
        </div>
      </div>

      <div className="rules-list">
        {rules.map(rule => (
          <div key={rule.id} className={`rule-item ${rule.status.toLowerCase()}`}>
            <div className="rule-header">
              <div className="rule-name">{rule.name}</div>
              <div className={`rule-status ${rule.status.toLowerCase()}`}>
                {rule.status}
              </div>
            </div>
            
            <div className="rule-condition">
              {rule.condition}
            </div>
            
            <div className="rule-stats">
              <div className="rule-stat">
                <span className="stat-label">Confidence:</span>
                <span className="stat-value">{(rule.confidence * 100).toFixed(0)}%</span>
              </div>
              <div className="rule-stat">
                <span className="stat-label">Blocked:</span>
                <span className="stat-value">{rule.blockedCount}</span>
              </div>
              <div className="rule-stat">
                <span className="stat-label">Action:</span>
                <span className={`stat-value action-${rule.action.toLowerCase()}`}>
                  {rule.action} (HTTP 418)
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="rule-generation-info">
        <h4>🔧 How Rules Are Generated:</h4>
        <div className="generation-steps">
          <div className="step">
            <span className="step-number">1</span>
            <span className="step-text">ML model analyzes behavioral patterns</span>
          </div>
          <div className="step">
            <span className="step-number">2</span>
            <span className="step-text">Converts patterns to WAF conditions</span>
          </div>
          <div className="step">
            <span className="step-number">3</span>
            <span className="step-text">Deploys rules via Terraform</span>
          </div>
          <div className="step">
            <span className="step-number">4</span>
            <span className="step-text">Returns HTTP 418 "I'm a teapot" for bots</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WAFRulesPanel;
