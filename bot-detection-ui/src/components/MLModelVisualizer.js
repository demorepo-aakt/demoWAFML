import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const MLModelVisualizer = ({ metrics }) => {
  const { topFeatures = [], accuracy = 0, precision = 0, recall = 0, f1Score = 0 } = metrics || {};

  const modelPerformance = [
    { metric: 'Accuracy', value: (accuracy * 100).toFixed(1) },
    { metric: 'Precision', value: (precision * 100).toFixed(1) },
    { metric: 'Recall', value: (recall * 100).toFixed(1) },
    { metric: 'F1-Score', value: (f1Score * 100).toFixed(1) }
  ];

  const featureChartData = (topFeatures || []).map(feature => ({
    name: (feature.name || '').replace(/_/g, ' ').substring(0, 15),
    importance: parseFloat(((feature.importance || 0) * 100).toFixed(1)) || 0,
    fullName: feature.name || '',
    description: feature.description || ''
  })).filter(item => item.name && typeof item.importance === 'number');

  return (
    <div className="ml-model-visualizer">
      <div className="component-header">
        <span className="icon">🧠</span>
        <h2>ML Model Brain</h2>
      </div>

      <div className="model-status">
        <div className="status-indicator active">
          <span className="status-dot"></span>
          <span>Random Forest Active</span>
        </div>
        <div className="model-info">
          <span>Behavioral Detection Engine</span>
        </div>
      </div>

      <div className="performance-metrics">
        <h3>Model Performance</h3>
        <div className="metrics-grid">
          {modelPerformance.map((metric, index) => (
            <div key={index} className="metric-card">
              <div className="metric-value">{metric.value}%</div>
              <div className="metric-label">{metric.metric}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="feature-importance">
        <h3>🔍 Top Decision Criteria</h3>
        <div className="feature-chart">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={featureChartData.length > 0 ? featureChartData : [{ name: 'No Data', importance: 0 }]} layout="horizontal">
              <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
              <XAxis 
                type="number" 
                stroke="#94a3b8"
                fontSize={10}
              />
              <YAxis 
                type="category" 
                dataKey="name" 
                stroke="#94a3b8"
                fontSize={10}
                width={80}
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'rgba(30, 41, 59, 0.95)',
                  border: '1px solid #475569',
                  borderRadius: '8px',
                  color: '#f1f5f9'
                }}
                formatter={(value, name, props) => [
                  `${value}%`,
                  'Importance',
                  props.payload.description
                ]}
              />
              <Bar 
                dataKey="importance" 
                fill="url(#featureGradient)"
                radius={[0, 4, 4, 0]}
              />
              <defs>
                <linearGradient id="featureGradient" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#60a5fa" />
                  <stop offset="100%" stopColor="#34d399" />
                </linearGradient>
              </defs>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="feature-explanations">
        <h4>What the Model Looks For:</h4>
        <div className="feature-list">
          {(topFeatures || []).slice(0, 3).map((feature, index) => (
            <div key={index} className="feature-explanation">
              <div className="feature-name">{(feature.name || '').replace(/_/g, ' ')}</div>
              <div className="feature-description">{feature.description || 'No description available'}</div>
              <div className="feature-importance">{((feature.importance || 0) * 100).toFixed(1)}%</div>
            </div>
          ))}
        </div>
      </div>

      <div className="decision-logic">
        <h4>🎯 Blocking Decision Logic:</h4>
        <div className="logic-rules">
          <div className="logic-rule">
            <span className="rule-operator">IF</span>
            <span className="rule-condition">Low header entropy + High burstiness</span>
            <span className="rule-result">→ LIKELY BOT</span>
          </div>
          <div className="logic-rule">
            <span className="rule-operator">IF</span>
            <span className="rule-condition">Off-hours activity + Fast requests</span>
            <span className="rule-result">→ SCRIPTED BEHAVIOR</span>
          </div>
          <div className="logic-rule">
            <span className="rule-operator">IF</span>
            <span className="rule-condition">Predictable timing + Low path diversity</span>
            <span className="rule-result">→ BOT PATTERNS</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MLModelVisualizer;
