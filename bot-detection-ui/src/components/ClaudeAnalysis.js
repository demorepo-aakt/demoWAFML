import React, { useState } from 'react';

const ClaudeAnalysis = () => {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const requestAnalysis = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:5000/api/ml/claude-analysis', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      const data = await response.json();
      
      if (data.status === 'success') {
        setAnalysis(data.analysis);
      } else {
        setError(data.message || 'Analysis failed');
      }
    } catch (err) {
      setError('Failed to connect to Claude API');
    } finally {
      setLoading(false);
    }
  };

  const parseAnalysis = (text) => {
    // Try to parse as JSON first, fallback to text
    try {
      return JSON.parse(text);
    } catch {
      return { raw_text: text };
    }
  };

  const renderAnalysisSection = (title, content) => {
    return (
      <div className="analysis-section">
        <h4>{title}</h4>
        <div className="analysis-content">
          {Array.isArray(content) ? (
            <ul>
              {content.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          ) : typeof content === 'object' ? (
            <pre>{JSON.stringify(content, null, 2)}</pre>
          ) : (
            <p>{content}</p>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="claude-analysis">
      <div className="component-header">
        <span className="icon">🧠</span>
        <h2>Claude ML Analysis</h2>
      </div>

      <div className="analysis-controls">
        <button 
          onClick={requestAnalysis} 
          disabled={loading}
          className="analysis-button"
        >
          {loading ? '🔄 Analyzing...' : '🚀 Request Claude Analysis'}
        </button>
      </div>

      {error && (
        <div className="error-message">
          <span className="error-icon">❌</span>
          <span>{error}</span>
        </div>
      )}

      {analysis && (
        <div className="analysis-results">
          <div className="analysis-header">
            <span className="success-icon">✅</span>
            <span>Analysis Complete</span>
          </div>
          
          <div className="analysis-sections">
            {(() => {
              const parsed = parseAnalysis(analysis);
              
              if (parsed.raw_text) {
                // Handle raw text response
                return (
                  <div className="analysis-section">
                    <h4>Claude's Analysis</h4>
                    <div className="analysis-content">
                      <pre className="analysis-text">{parsed.raw_text}</pre>
                    </div>
                  </div>
                );
              } else {
                // Handle structured JSON response
                return Object.entries(parsed).map(([key, value]) => 
                  renderAnalysisSection(
                    key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                    value
                  )
                );
              }
            })()}
          </div>
        </div>
      )}

      {!analysis && !loading && !error && (
        <div className="analysis-placeholder">
          <div className="placeholder-content">
            <span className="placeholder-icon">💭</span>
            <h3>Ready for Deep Analysis</h3>
            <p>
              Click "Request Claude Analysis" to send your ML training data to Claude 
              for comprehensive insights about model architecture, decision logic, 
              and production recommendations.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default ClaudeAnalysis;
