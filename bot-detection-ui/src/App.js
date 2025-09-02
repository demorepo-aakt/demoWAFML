import React, { useState, useEffect } from 'react';
import './App.css';
import TrafficDashboard from './components/TrafficDashboard';
import ControlPanel from './components/ControlPanel';

const API_BASE = 'http://localhost:5000/api';

function App() {
  const [trafficData, setTrafficData] = useState([]);
  const [modelMetrics, setModelMetrics] = useState({});
  const [wafRules, setWafRules] = useState([]);
  const [logEntries, setLogEntries] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [systemStatus, setSystemStatus] = useState({
    mlModelTrained: false,
    activeTrafficGenerators: 0,
    wafRulesCount: 0
  });
  const [stepResults, setStepResults] = useState({});

  // Function to get real traffic data from backend
  const fetchRealTrafficData = async () => {
    try {
      const response = await fetch(`${API_BASE}/traffic/metrics`);
      if (response.ok) {
        const data = await response.json();
        const now = new Date();
        return {
          time: now.toLocaleTimeString(),
          humans: data.humans || 0,
          bots: data.bots || 0,
          blocked: data.blocked || 0,
          timestamp: now.toISOString()
        };
      }
    } catch (error) {
      console.log('Cannot fetch real traffic data');
    }
    
    // Return empty data if no real traffic
    const now = new Date();
    return {
      time: now.toLocaleTimeString(),
      humans: 0,
      bots: 0,
      blocked: 0,
      timestamp: now.toISOString()
    };
  };

  // Check backend connection and system status
  const checkSystemStatus = async () => {
    try {
      const response = await fetch(`${API_BASE}/status`);
      if (response.ok) {
        const data = await response.json();
        setIsConnected(true);
        setSystemStatus(prev => ({
          ...prev,
          mlModelTrained: data.system?.ml_model_trained || false,
          wafAnalysisCompleted: data.system?.waf_analysis_completed || false,
          claudeAnalysisCompleted: data.system?.claude_analysis_completed || false,
          terraformGenerated: data.system?.terraform_generated || false,
          rulesDeployed: data.system?.rules_deployed || false,
          ragStored: data.system?.rag_stored || false,
          activeTrafficGenerators: data.system?.active_traffic_generators || 0,
          wafRulesCount: data.system?.waf_rules_count || 0
        }));
      } else {
        setIsConnected(false);
      }
    } catch (error) {
      setIsConnected(false);
      // Even if backend is down, show simulated traffic data
      console.log('Backend unavailable, showing simulated data');
    }
  };

  // Check traffic generator status
  const checkTrafficStatus = async () => {
    try {
      const response = await fetch(`${API_BASE}/traffic/status`);
      if (response.ok) {
        const data = await response.json();
        const activeCount = Object.keys(data.traffic_generators || {}).length;
        setSystemStatus(prev => ({
          ...prev,
          activeTrafficGenerators: activeCount
        }));
      }
    } catch (error) {
      // Backend unavailable, but traffic might still be running
      console.log('Cannot check traffic status');
    }
  };

  // Initialize and set up polling
  useEffect(() => {
    // Initialize model metrics with default values
    setModelMetrics({
      accuracy: 0,
      precision: 0,
      recall: 0,
      f1Score: 0,
      topFeatures: []
    });

    // Initial status check
    checkSystemStatus();
    
    // Set up polling for system status
    const statusInterval = setInterval(checkSystemStatus, 5000); // Every 5 seconds
    const trafficInterval = setInterval(checkTrafficStatus, 3000); // Every 3 seconds
    
    // Set up real traffic data polling (only when backend is available)
    const dataInterval = setInterval(async () => {
      const newData = await fetchRealTrafficData();
      
      // Only update if there's actual traffic or if this is the first data point
      if (newData.humans > 0 || newData.bots > 0 || newData.blocked > 0 || trafficData.length === 0) {
        setTrafficData(prev => {
          const updated = [...prev, newData];
          // Keep only last 20 data points for performance
          return updated.slice(-20);
        });
        
        // Add to log entries only if there's real traffic
        if (newData.humans > 0 || newData.bots > 0 || newData.blocked > 0) {
          setLogEntries(prev => {
            const logEntry = {
              timestamp: newData.timestamp,
              message: `Real Traffic: ${newData.humans} humans, ${newData.bots} bots, ${newData.blocked} blocked`,
              type: 'info'
            };
            return [logEntry, ...prev.slice(0, 49)]; // Keep last 50 entries
          });
        }
      }
    }, 10000); // Every 10 seconds

    return () => {
      clearInterval(statusInterval);
      clearInterval(trafficInterval);
      clearInterval(dataInterval);
    };
  }, []);

  return (
    <div className="App">
      <header className="app-header">
        <h1>🛡️ ML/Terraform/WAF pipeline - Real-Time Cybersecurity Dashboard</h1>
        <div className="connection-status">
          <span className={`status-dot ${isConnected ? 'connected' : 'disconnected'}`}></span>
          {isConnected ? 'Live Data' : 'Disconnected'}
        </div>
      </header>

      <div className="main-container">
        {/* Left Panel - Controls */}
        <div className="left-panel">
          <ControlPanel 
            systemStatus={systemStatus}
            setSystemStatus={setSystemStatus}
            setModelMetrics={setModelMetrics}
            setWafRules={setWafRules}
            setStepResults={setStepResults}
          />
        </div>

        {/* Right Panel - Chart First, Then Terminal */}
        <div className="right-panel">
          {/* Single Chart - TOP (IMMOVABLE) */}
          <div className="chart-pane">
            <div className="dashboard-section chart-section">
              <TrafficDashboard data={trafficData} />
            </div>
          </div>

          {/* Terminal Results Section - BOTTOM (SCROLLABLE) */}
          <div className="terminal-pane">
            <div className="component-header">
              <span className="icon">💻</span>
              <h2>Terminal Output & Execution Logs</h2>
            </div>
            
            {/* Display step-by-step results */}
            <div className="step-results">
              {Object.keys(stepResults).length === 0 ? (
                <div className="no-results">
                  <p>$ Click any step button to see execution logs and results here...</p>
                </div>
              ) : (
                Object.entries(stepResults).map(([step, result]) => (
                  <div key={step} className={`step-result ${result.status}`}>
                    <div className="step-header">
                      <h4>$ {result.title || step}</h4>
                      <span className="result-icon">
                        {result.status === 'success' ? '✅' : 
                         result.status === 'error' ? '❌' : 
                         result.status === 'loading' ? '🔄' : '⏳'}
                      </span>
                    </div>
                    <div className="step-content">
                      {result.message && <p className="step-message">{result.message}</p>}
                      {result.logs && (
                        <div className="step-logs">
                          <h5>EXECUTION OUTPUT:</h5>
                          <pre className="log-content">{result.logs}</pre>
                        </div>
                      )}
                      {result.data && (
                        <div className="step-data">
                          <h5>JSON DATA:</h5>
                          <pre className="data-content">{JSON.stringify(result.data, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;