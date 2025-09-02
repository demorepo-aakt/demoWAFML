import React, { useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

const ControlPanel = ({ systemStatus, setSystemStatus, setModelMetrics, setWafRules, setStepResults }) => {
  const [loading, setLoading] = useState({});
  const [results, setResults] = useState({});
  const [albUrl, setAlbUrl] = useState('');
  const [trafficStatus, setTrafficStatus] = useState({
    humanRunning: false,
    botRunning: false
  });

  // Helper function to make API calls
  const apiCall = async (endpoint, method = 'GET', body = null) => {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : null,
    });
    return response.json();
  };

  // Set loading state for a specific action
  const setActionLoading = (action, isLoading) => {
    setLoading(prev => ({ ...prev, [action]: isLoading }));
  };

  // Set result for a specific action
  const setActionResult = (action, result) => {
    // Update both local results (for temporary notifications) and step results (for persistent display)
    setResults(prev => ({ ...prev, [action]: result }));
    setStepResults(prev => ({ ...prev, [action]: { ...result, title: getStepTitle(action) } }));
    
    setTimeout(() => {
      setResults(prev => {
        const newResults = { ...prev };
        delete newResults[action];
        return newResults;
      });
    }, 5000); // Clear temporary result after 5 seconds
  };

  // Helper to get step title from action key
  const getStepTitle = (action) => {
    const titles = {
      humanTraffic: '1. Generate Human Traffic',
      botTraffic: '1. Generate Advanced Attack Traffic', 
      trainModel: '2. Train ML Model',
      wafAnalysis: '3. ML Analysis on WAF Logs',
      claudeAnalysis: '4. Claude Expert Analysis',
      generateTerraform: '5. Generate State-Aware Terraform',
      deployRules: '6. Deploy WAF Rules',
      storeRAG: '7. Store in RAG',
      retrieveRAG: '8. Retrieve from RAG'
    };
    return titles[action] || action;
  };

  // 2. Train ML Model
  const handleTrainModel = async () => {
    setActionLoading('trainModel', true);
    setActionResult('trainModel', { 
      status: 'loading', 
      message: 'Training ML model on WAF logs...',
      logs: 'Starting ML training process...\nLoading WAF log data from S3...\nExtracting behavioral features...'
    });
    
    try {
      const result = await apiCall('/ml/train', 'POST');
      if (result.status === 'success') {
        setModelMetrics(result.metrics);
        setSystemStatus(prev => ({ ...prev, mlModelTrained: true }));
        
        const logOutput = [
          'ML Training Completed Successfully!',
          `Model Accuracy: ${(result.metrics.accuracy * 100).toFixed(1)}%`,
          `Training Samples: ${result.metrics.training_samples}`,
          `Test Samples: ${result.metrics.test_samples}`,
          `WAF Rules Generated: ${result.metrics.waf_rules?.length || 0}`,
          '',
          'Top Features:',
          ...Object.entries(result.metrics.feature_importance || {})
            .slice(0, 5)
            .map(([feature, importance]) => `  ${feature}: ${(importance * 100).toFixed(1)}%`)
        ].join('\n');
        
        setActionResult('trainModel', { 
          status: 'success', 
          message: 'ML model trained successfully with real WAF log validation!',
          logs: logOutput,
          data: result.metrics
        });
      } else {
        setActionResult('trainModel', { 
          status: 'error', 
          message: result.message,
          logs: `Training failed: ${result.message}`
        });
      }
    } catch (error) {
      setActionResult('trainModel', { 
        status: 'error', 
        message: error.message,
        logs: `Error during training: ${error.message}`
      });
    } finally {
      setActionLoading('trainModel', false);
    }
  };

  // 2. Generate Human Traffic (Toggle)
  const handleGenerateHumanTraffic = async () => {
    setActionLoading('humanTraffic', true);
    try {
      // Check if human traffic is already running
      const statusResult = await apiCall('/traffic/status');
      const isHumanRunning = statusResult.traffic_generators?.human?.running;
      
      if (isHumanRunning) {
        // Stop human traffic
        const result = await apiCall('/traffic/stop', 'POST', { type: 'human' });
        if (result.status === 'success') {
          setTrafficStatus(prev => ({ ...prev, humanRunning: false }));
          setActionResult('humanTraffic', { status: 'success', message: 'Human traffic stopped' });
        } else {
          setActionResult('humanTraffic', { status: 'error', message: result.message });
        }
      } else {
        // Start human traffic
        const result = await apiCall('/traffic/human/start', 'POST', {
          users: 5,
          duration: 300 // 5 minutes
        });
        if (result.status === 'success') {
          setTrafficStatus(prev => ({ ...prev, humanRunning: true }));
          setAlbUrl(result.target_url);
          setActionResult('humanTraffic', { status: 'success', message: result.message });
        } else {
          setActionResult('humanTraffic', { status: 'error', message: result.message });
        }
      }
    } catch (error) {
      setActionResult('humanTraffic', { status: 'error', message: error.message });
    } finally {
      setActionLoading('humanTraffic', false);
    }
  };

  // 3. Generate Bot Traffic (Toggle)
  const handleGenerateBotTraffic = async () => {
    setActionLoading('botTraffic', true);
    try {
      // Check if bot traffic is already running
      const statusResult = await apiCall('/traffic/status');
      const isBotRunning = statusResult.traffic_generators?.bot?.running;
      
      if (isBotRunning) {
        // Stop bot traffic
        const result = await apiCall('/traffic/stop', 'POST', { type: 'bot' });
        if (result.status === 'success') {
          setTrafficStatus(prev => ({ ...prev, botRunning: false }));
          setActionResult('botTraffic', { status: 'success', message: 'Advanced Attack Traffic stopped' });
        } else {
          setActionResult('botTraffic', { status: 'error', message: result.message });
        }
      } else {
        // Start bot traffic
        const result = await apiCall('/traffic/bot/start', 'POST', {
          attack_type: 'scraping',
          rate: 10,
          duration: 60 // 1 minute
        });
        if (result.status === 'success') {
          setTrafficStatus(prev => ({ ...prev, botRunning: true }));
          setAlbUrl(result.target_url);
          setActionResult('botTraffic', { status: 'success', message: result.message });
        } else {
          setActionResult('botTraffic', { status: 'error', message: result.message });
        }
      }
    } catch (error) {
      setActionResult('botTraffic', { status: 'error', message: error.message });
    } finally {
      setActionLoading('botTraffic', false);
    }
  };

  // 3. WAF Log Analysis (separate from training)
  const handleGetWafAnalysis = async () => {
    setActionLoading('wafAnalysis', true);
    setActionResult('wafAnalysis', { 
      status: 'loading', 
      message: 'Analyzing WAF logs and generating rules...',
      logs: 'Loading 23,137 WAF log entries from S3...\nGenerating behavioral rules...\nValidating rules against real traffic...'
    });
    
    try {
      const result = await apiCall('/ml/analyze-waf-logs', 'POST');
      if (result.status === 'success') {
        const analysis = result.analysis || {};
        const rules = analysis.waf_rules || [];
        const validation = analysis.waf_validation || {};
        
        const ruleDetails = rules.slice(0, 4).map((rule, i) => 
          `${i+1}. **${rule.name}**: ${rule.condition}\n   📊 Performance: ${rule.performance || 'Based on ML analysis'}\n   🎯 Rationale: ${rule.rationale || 'ML-based detection'}`
        ).join('\n\n');
        
        const logOutput = [
          '🛡️ WAF RULE GENERATION & VALIDATION COMPLETE:',
          '',
          '📊 PERFORMANCE METRICS:',
          `Total Rules Generated: ${rules.length}`,
          `Log Entries Analyzed: ${analysis.log_entries_analyzed?.toLocaleString() || '23,137'}`,
          `Precision: ${(validation.precision * 100 || 0).toFixed(1)}%`,
          `Recall: ${(validation.recall * 100 || 0).toFixed(1)}%`,
          `False Positives: ${validation.false_positives?.toLocaleString() || 0}`,
          '',
          '🛡️ GENERATED WAF RULES:',
          ruleDetails,
          '',
          '✅ Ready for Claude expert analysis'
        ].join('\n');
        
        setActionResult('wafAnalysis', { 
          status: 'success', 
          message: result.message,
          logs: logOutput,
          data: analysis
        });
      } else {
        setActionResult('wafAnalysis', { 
          status: 'error', 
          message: result.message,
          logs: `WAF analysis failed: ${result.message}`
        });
      }
    } catch (error) {
      setActionResult('wafAnalysis', { 
        status: 'error', 
        message: error.message,
        logs: `Error during WAF analysis: ${error.message}`
      });
    } finally {
      setActionLoading('wafAnalysis', false);
    }
  };

  // 4. Ask Claude for Analysis
  const handleClaudeAnalysis = async () => {
    setActionLoading('claudeAnalysis', true);
    try {
      const result = await apiCall('/ml/claude-analysis', 'POST');
      if (result.status === 'success') {
        setActionResult('claudeAnalysis', { 
          status: 'success', 
          message: '🤖 Claude Expert Analysis Complete - AI Recommendations Received',
          logs: `CLAUDE STEP 1 - WAF RULE ANALYSIS:\n\n${result.analysis || 'Claude analysis completed successfully.'}\n\n✅ Analysis stored for Terraform generation step`,
          data: {
            timestamp: result.timestamp,
            analysis_type: 'Expert AI WAF Rule Analysis',
            recommendations: result.analysis,
            step: 'Claude Step 1 of 2'
          }
        });
      } else {
        setActionResult('claudeAnalysis', { status: 'error', message: result.message });
      }
    } catch (error) {
      setActionResult('claudeAnalysis', { status: 'error', message: error.message });
    } finally {
      setActionLoading('claudeAnalysis', false);
    }
  };

  // 5. Generate Terraform Config (State-Aware)
  const handleGenerateTerraform = async () => {
    setActionLoading('generateTerraform', true);
    try {
      const result = await apiCall('/terraform/generate', 'POST');
      if (result.status === 'success') {
        const stateInfo = result.current_state_summary || {};
        const awsStateDetails = `AWS STATE DETECTED:
📋 Existing WAF ACLs: ${stateInfo.existing_acls || 'Unknown'}
🛡️  Existing Rules: ${stateInfo.existing_rules || 'Unknown'}  
🔒 Protection Level: ${stateInfo.protection_level || 'Unknown'}
🌐 Service Type: ALB/API Gateway`;

        // Format deployment summary
        const deploymentSummary = result.deployment_summary || {};
        const resourcesToCreate = (deploymentSummary.resources_to_create || []).map(
          (resource, i) => `${i+1}. ${resource.type}: ${resource.name}\n   ${resource.description}`
        ).join('\n');
        const safetyNotes = (deploymentSummary.safety_notes || []).join('\n');
        
        const summaryText = `📋 DEPLOYMENT SUMMARY:
${resourcesToCreate}

🛡️ SAFETY ANALYSIS:
${safetyNotes}

⚠️ IMPACT LEVEL: ${deploymentSummary.estimated_impact || 'MEDIUM'}

${result.requires_confirmation ? '⏳ WAITING FOR USER CONFIRMATION...' : ''}`;
        
        setActionResult('generateTerraform', { 
          status: 'success', 
          message: result.requires_confirmation ? 
            `🏗️ Terraform Generated - Review and Confirm Deployment` :
            `🏗️ State-Aware Terraform Generated - Ready for Deployment`,
          logs: `CLAUDE STEP 2 - TERRAFORM GENERATION:\n\n${awsStateDetails}\n\n${summaryText}\n\n📝 TERRAFORM CODE:\n${result.terraform_code || 'Terraform code generated successfully'}`,
          data: {
            terraform_code: result.terraform_code,
            deployment_summary: result.deployment_summary,
            current_state_summary: result.current_state_summary,
            deployment_notes: result.deployment_notes,
            aws_state_analyzed: true,
            requires_confirmation: result.requires_confirmation,
            step: 'Claude Step 2 of 2'
          }
        });
        
        // Update system status to enable deployment confirmation
        if (result.requires_confirmation) {
          setSystemStatus(prev => ({
            ...prev,
            terraformGenerated: true,
            awaitingDeploymentConfirmation: true
          }));
        }
      } else {
        setActionResult('generateTerraform', { status: 'error', message: result.message });
      }
    } catch (error) {
      setActionResult('generateTerraform', { status: 'error', message: error.message });
    } finally {
      setActionLoading('generateTerraform', false);
    }
  };

  // 6. Confirm and Deploy Terraform
  const handleConfirmDeploy = async (confirmed) => {
    setActionLoading('confirmDeploy', true);
    try {
      const result = await apiCall('/terraform/deploy-confirm', 'POST', { confirmed });
      if (result.status === 'success') {
        setActionResult('confirmDeploy', { 
          status: 'success', 
          message: '🚀 Terraform Deployed Successfully to ALB WAF!',
          logs: `DEPLOYMENT COMPLETE:\n\n✅ Terraform applied successfully\n📊 Deployment Result: ${result.deployment_result.message}\n🛡️ WAF rules now active in COUNT mode\n\n📈 Next Steps:\n1. Monitor WAF metrics for 24-48 hours\n2. Review false positive rates\n3. Switch to BLOCK mode if acceptable`,
          data: {
            deployment_result: result.deployment_result,
            terraform_applied: true
          }
        });
        
        // Update system status
        setSystemStatus(prev => ({
          ...prev,
          rulesDeployed: true,
          awaitingDeploymentConfirmation: false
        }));
      } else if (result.status === 'cancelled') {
        setActionResult('confirmDeploy', { 
          status: 'cancelled', 
          message: '❌ Deployment Cancelled by User',
          logs: 'User chose not to deploy the Terraform configuration.'
        });
        
        setSystemStatus(prev => ({
          ...prev,
          awaitingDeploymentConfirmation: false
        }));
      } else {
        setActionResult('confirmDeploy', { status: 'error', message: result.message });
      }
    } catch (error) {
      setActionResult('confirmDeploy', { status: 'error', message: error.message });
    } finally {
      setActionLoading('confirmDeploy', false);
    }
  };

  // Legacy function removed - now using handleConfirmDeploy instead

  // 7. Store in RAG
  const handleStoreRAG = async () => {
    setActionLoading('storeRAG', true);
    try {
      // Create context from the successful deployment
      const context = `
Successful ML-WAF Deployment:
- ML Model Accuracy: ${results.trainML?.data?.accuracy || 'N/A'}
- WAF Rules Generated: ${results.analyzeWafLogs?.data?.rules_generated || 'N/A'}
- Claude Recommendations: ${results.claudeAnalysis?.data?.recommendations || 'Expert analysis completed'}
- Deployment Status: ${results.confirmDeploy?.data?.deployment_result?.success ? 'SUCCESS' : 'FAILED'}
- Rules Added: ${results.confirmDeploy?.data?.deployment_result?.rules_added || 0}
- WebACL: ${results.confirmDeploy?.data?.deployment_result?.webacl_name || 'Unknown'}
- Deployment Steps: ${results.confirmDeploy?.data?.deployment_result?.steps_completed?.join(', ') || 'None'}
      `.trim();

      const result = await apiCall('/rag/store-decision', 'POST', { context });
      if (result.status === 'success') {
        setActionResult('storeRAG', { 
          status: 'success', 
          message: `Decision context stored in RAG successfully (ID: ${result.rag_id})`
        });
      } else {
        setActionResult('storeRAG', { status: 'error', message: result.message });
      }
    } catch (error) {
      setActionResult('storeRAG', { status: 'error', message: error.message });
    } finally {
      setActionLoading('storeRAG', false);
    }
  };

  // 8. Retrieve from RAG
  const handleRetrieveRAG = async () => {
    setActionLoading('retrieveRAG', true);
    try {
      const result = await apiCall('/rag/retrieve-decision', 'GET');
      if (result.status === 'success') {
        const ragData = result.data;
        const decisions = ragData.relevant_decisions || [];
        
        // Categorize decisions by type for better display
        const deploymentDecisions = decisions.filter(d => d.waf_rules && d.waf_rules.length > 0);
        const knowledgeEntries = decisions.filter(d => !d.waf_rules || d.waf_rules.length === 0);
        
        // Format the retrieved knowledge for detailed terminal display
        let displayMessage = `📚 PERSISTENT RAG KNOWLEDGE RETRIEVAL\n`;
        displayMessage += `═══════════════════════════════════════\n`;
        displayMessage += `📊 Total entries in storage: ${result.total_count}\n`;
        displayMessage += `🔍 Retrieved for analysis: ${decisions.length}\n`;
        displayMessage += `💾 Storage type: Persistent JSON (survives restarts)\n`;
        displayMessage += `📋 Entry types: ${deploymentDecisions.length} deployments, ${knowledgeEntries.length} knowledge entries\n\n`;
        
        // Show deployment decisions first (most valuable)
        if (deploymentDecisions.length > 0) {
          displayMessage += `🚀 DEPLOYMENT DECISIONS (${deploymentDecisions.length}):\n`;
          displayMessage += `─────────────────────────────────────\n`;
          
          deploymentDecisions.slice(0, 2).forEach((decision, index) => {
            const timestamp = new Date(decision.timestamp).toLocaleString();
            const timeDiff = index === 0 ? '' : ` (${Math.round((new Date(deploymentDecisions[0].timestamp) - new Date(decision.timestamp)) / 60000)} min earlier)`;
            
            displayMessage += `🔹 DEPLOYMENT ${index + 1}: ${decision.id}${timeDiff}\n`;
            displayMessage += `   📅 ${timestamp}\n`;
            
            // Performance metrics in compact format
            if (decision.performance_metrics && Object.keys(decision.performance_metrics).length > 0) {
              displayMessage += `   📊 ML Performance: `;
              displayMessage += `Precision=${(decision.performance_metrics.precision * 100).toFixed(1)}%, `;
              displayMessage += `Recall=${(decision.performance_metrics.recall * 100).toFixed(1)}%, `;
              displayMessage += `Tested=${decision.performance_metrics.total_entries?.toLocaleString() || 'N/A'}\n`;
            }
            
            // Show rule summary
            if (decision.waf_rules && decision.waf_rules.length > 0) {
              displayMessage += `   🛡️  ${decision.waf_rules.length} WAF Rules Generated:\n`;
              decision.waf_rules.forEach((rule, ruleIndex) => {
                const rulePerf = decision.performance_metrics?.rule_performance?.[rule.name];
                const matchRate = rulePerf ? ((rulePerf.matches / rulePerf.total_tested) * 100).toFixed(2) : 'N/A';
                displayMessage += `      ${ruleIndex + 1}. ${rule.name} (${matchRate}% match rate)\n`;
                displayMessage += `         • ${rule.condition.substring(0, 80)}${rule.condition.length > 80 ? '...' : ''}\n`;
              });
            }
            displayMessage += `\n`;
          });
          
          if (deploymentDecisions.length > 2) {
            displayMessage += `   ... and ${deploymentDecisions.length - 2} more deployment decisions\n\n`;
          }
        }
        
        // Analyze knowledge categories
        const categories = {};
        knowledgeEntries.forEach(entry => {
          const firstLine = entry.context.split('\n')[0].trim();
          const category = firstLine.split(':')[0] || 'General';
          if (!categories[category]) categories[category] = 0;
          categories[category]++;
        });
        
        // Show knowledge entries summary
        if (knowledgeEntries.length > 0) {
          displayMessage += `📚 KNOWLEDGE BASE ENTRIES (${knowledgeEntries.length}):\n`;
          displayMessage += `─────────────────────────────────────\n`;
          
          Object.entries(categories).forEach(([category, count]) => {
            displayMessage += `   📖 ${category}: ${count} entries\n`;
          });
          
          displayMessage += `\n   📋 Knowledge entries with details:\n`;
          knowledgeEntries.slice(0, 8).forEach((entry, index) => {
            const topic = entry.context.split('\n')[0].trim().replace(':', '');
            const timestamp = new Date(entry.timestamp).toLocaleDateString();
            
            // Extract first meaningful content line (skip empty lines and headers)
            const contextLines = entry.context.split('\n');
            let contentPreview = '';
            for (let i = 1; i < contextLines.length && i < 5; i++) {
              const line = contextLines[i].trim();
              if (line && !line.startsWith('─') && !line.startsWith('═') && line.length > 10) {
                contentPreview = line.substring(0, 120);
                if (line.length > 120) contentPreview += '...';
                break;
              }
            }
            
            displayMessage += `      ${index + 1}. ${topic} (${timestamp})\n`;
            displayMessage += `         💡 ${contentPreview || 'Knowledge entry details available'}\n`;
          });
          
          if (knowledgeEntries.length > 8) {
            displayMessage += `      ... and ${knowledgeEntries.length - 8} more knowledge entries\n`;
          }
          displayMessage += `\n`;
        }
        
        // Send simple message to left panel, detailed info to terminal
        const summaryMessage = `Retrieved ${result.total_count} total entries from persistent RAG (${deploymentDecisions.length} deployments, ${knowledgeEntries.length} knowledge entries)`;
        
        setActionResult('retrieveRAG', { 
          status: 'success', 
          message: summaryMessage
        });
        
        // Add the detailed analysis to the terminal via setStepResults
        if (setStepResults) {
          setStepResults(prev => ({
            ...prev,
            'retrieveRAG': {
              title: '8. Retrieve from RAG',
              status: 'success',
              message: summaryMessage,
              logs: displayMessage, // This will show in the terminal with proper formatting
              timestamp: new Date().toISOString()
            }
          }));
        }
      } else {
        setActionResult('retrieveRAG', { status: 'error', message: result.message });
      }
    } catch (error) {
      setActionResult('retrieveRAG', { status: 'error', message: error.message });
    } finally {
      setActionLoading('retrieveRAG', false);
    }
  };

  // Reset traffic metrics
  const handleResetMetrics = async () => {
    try {
      const result = await apiCall('/traffic/reset', 'POST');
      if (result.status === 'success') {
        setActionResult('resetMetrics', { status: 'success', message: 'Traffic metrics reset to zero' });
      } else {
        setActionResult('resetMetrics', { status: 'error', message: result.message });
      }
    } catch (error) {
      setActionResult('resetMetrics', { status: 'error', message: error.message });
    }
  };

  // Get ALB URL and update traffic status
  const handleGetAlbUrl = async () => {
    try {
      const result = await apiCall('/alb-url');
      if (result.status === 'success') {
        setAlbUrl(result.alb_url);
      }
    } catch (error) {
      console.error('Failed to get ALB URL:', error);
    }
  };

  // Update traffic status from backend
  const updateTrafficStatus = async () => {
    try {
      const result = await apiCall('/traffic/status');
      if (result.status === 'success') {
        setTrafficStatus({
          humanRunning: result.traffic_generators?.human?.running || false,
          botRunning: result.traffic_generators?.bot?.running || false
        });
      }
    } catch (error) {
      console.error('Failed to get traffic status:', error);
    }
  };

  // Load ALB URL and traffic status on component mount
  React.useEffect(() => {
    handleGetAlbUrl();
    updateTrafficStatus();
    
    // Update traffic status every 5 seconds
    const interval = setInterval(updateTrafficStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="control-panel">
      <div className="component-header">
        <span className="icon">🎮</span>
        <h2>Interactive Demo Controls</h2>
      </div>

      <div className="system-status">
        <h3>System Status</h3>
        <div className="status-grid">
          <div className={`status-item ${systemStatus.mlModelTrained ? 'active' : 'inactive'}`}>
            <span className="status-icon">{systemStatus.mlModelTrained ? '✅' : '❌'}</span>
            <span>ML Model Trained</span>
          </div>
          <div className={`status-item ${systemStatus.activeTrafficGenerators > 0 ? 'active' : 'inactive'}`}>
            <span className="status-icon">{systemStatus.activeTrafficGenerators > 0 ? '🟢' : '🔴'}</span>
            <span>Traffic Generators: {systemStatus.activeTrafficGenerators}</span>
          </div>
          <div className={`status-item ${systemStatus.wafRulesCount > 0 ? 'active' : 'inactive'}`}>
            <span className="status-icon">{systemStatus.wafRulesCount > 0 ? '🛡️' : '⚪'}</span>
            <span>WAF Rules: {systemStatus.wafRulesCount}</span>
          </div>
        </div>
      </div>

      {albUrl && (
        <div className="alb-info">
          <h4>Target URL:</h4>
          <div className="alb-url">{albUrl}</div>
        </div>
      )}

      <div className="control-buttons">
        <h3>Demo Actions</h3>
        
        {/* Step 1: Generate Traffic */}
        <div className="control-group">
          <h4>1. Generate Traffic</h4>
          <div className="button-row">
            <button 
              className={`control-button ${trafficStatus.humanRunning ? 'secondary' : 'success'} ${loading.humanTraffic ? 'loading' : ''}`}
              onClick={handleGenerateHumanTraffic}
              disabled={loading.humanTraffic}
            >
              {loading.humanTraffic ? '🔄 Processing...' : 
               trafficStatus.humanRunning ? '🛑 Stop Human Traffic' : '👥 Generate Human Traffic'}
            </button>
            <button 
              className={`control-button ${trafficStatus.botRunning ? 'secondary' : 'danger'} ${loading.botTraffic ? 'loading' : ''}`}
              onClick={handleGenerateBotTraffic}
              disabled={loading.botTraffic}
            >
              {loading.botTraffic ? '🔄 Processing...' : 
               trafficStatus.botRunning ? '🛑 Stop Advanced Attack Traffic' : '🤖 Generate Advanced Attack Traffic'}
            </button>
          </div>
          <p className="control-description">
            Click to start/stop realistic human traffic or bot attacks - buttons toggle between start and stop
          </p>
        </div>

        {/* Step 2: Train ML Model */}
        <div className="control-group">
          <h4>2. Train Robust ML Model</h4>
          <button 
            className={`control-button primary ${loading.trainModel ? 'loading' : ''}`}
            onClick={handleTrainModel}
            disabled={loading.trainModel}
          >
            {loading.trainModel ? '🔄 Training...' : '🧠 Train ML Model'}
          </button>
          <p className="control-description">
            Trains the robust Random Forest model on WAF logs using behavioral features
          </p>
        </div>

        {/* Step 3: ML Analysis on WAF Logs */}
        <div className="control-group">
          <h4>3. ML Analysis on WAF Logs</h4>
          <button 
            className={`control-button info ${loading.wafAnalysis ? 'loading' : ''}`}
            onClick={handleGetWafAnalysis}
            disabled={loading.wafAnalysis || !systemStatus.mlModelTrained}
          >
            {loading.wafAnalysis ? '🔄 Analyzing...' : '📊 Run WAF Log Analysis'}
          </button>
          <p className="control-description">
            ML model analyzes WAF logs and tests rules against all 23,137 log entries
          </p>
        </div>

        {/* Step 4: Ask Claude for Best Analysis */}
        <div className="control-group">
          <h4>4. Ask Claude for Expert Analysis</h4>
          <button 
            className={`control-button primary ${loading.claudeAnalysis ? 'loading' : ''}`}
            onClick={handleClaudeAnalysis}
            disabled={loading.claudeAnalysis || !systemStatus.wafAnalysisCompleted}
          >
            {loading.claudeAnalysis ? '🔄 Claude Analyzing...' : '🤖 Claude Step 1: Analyze WAF Rules'}
          </button>
          <p className="control-description">
            Claude AI analyzes ML + WAF performance and recommends optimal blocking rules
          </p>
        </div>

        {/* Step 5: Generate Terraform Config */}
        <div className="control-group">
          <h4>5. Claude Creates Terraform File</h4>
          <button 
            className={`control-button warning ${loading.generateTerraform ? 'loading' : ''}`}
            onClick={handleGenerateTerraform}
            disabled={loading.generateTerraform || !systemStatus.claudeAnalysisCompleted}
          >
            {loading.generateTerraform ? '🔄 Claude Generating TF...' : '🏗️ Claude Step 2: Generate Terraform'}
          </button>
          <p className="control-description">
            Claude reads current Terraform state + rule analysis to generate safe infrastructure changes
          </p>
        </div>

        {/* Step 6: Confirm and Deploy Terraform */}
        <div className="control-group">
          <h4>6. Deploy Terraform File</h4>
          {systemStatus.awaitingDeploymentConfirmation ? (
            <div className="confirmation-buttons">
              <div className="confirmation-message">
                <p>⚠️ Review the deployment summary above. Deploy to ALB WAF?</p>
              </div>
              <div className="button-row">
                <button 
                  className={`control-button success ${loading.confirmDeploy ? 'loading' : ''}`}
                  onClick={() => handleConfirmDeploy(true)}
                  disabled={loading.confirmDeploy}
                >
                  {loading.confirmDeploy ? '🔄 Deploying...' : '✅ Yes, Deploy'}
                </button>
          <button 
                  className={`control-button danger ${loading.confirmDeploy ? 'loading' : ''}`}
                  onClick={() => handleConfirmDeploy(false)}
                  disabled={loading.confirmDeploy}
                >
                  {loading.confirmDeploy ? '🔄 Cancelling...' : '❌ No, Cancel'}
          </button>
              </div>
            </div>
          ) : (
            <div className="deployment-message">
              <p>⚠️ <strong>Go through Claude workflow first:</strong></p>
              <ol>
                <li>✅ Complete Claude Step 1 (Analyze Rules)</li>
                <li>✅ Complete Claude Step 2 (Generate Terraform)</li>
                <li>🎯 Then you'll see the deployment confirmation here</li>
              </ol>
            </div>
          )}
          <p className="control-description">
            {systemStatus.awaitingDeploymentConfirmation ? 
              'Confirm deployment after reviewing the Terraform changes above' :
              'Deploy the Claude-generated Terraform configuration to AWS WAF'
            }
          </p>
        </div>

        {/* Step 7: Store in RAG */}
        <div className="control-group">
          <h4>7. Store Decision Rules in RAG</h4>
          <button 
            className={`control-button info ${loading.storeRAG ? 'loading' : ''}`}
            onClick={handleStoreRAG}
            disabled={loading.storeRAG || !systemStatus.rulesDeployed}
          >
            {loading.storeRAG ? '🔄 Storing...' : '📚 Store in RAG'}
          </button>
          <p className="control-description">
            Store lessons learned and decision rules for future reference
          </p>
        </div>

        {/* Step 8: Retrieve from RAG */}
        <div className="control-group">
          <h4>8. Read RAG While Making Decisions</h4>
          <button 
            className={`control-button secondary ${loading.retrieveRAG ? 'loading' : ''}`}
            onClick={handleRetrieveRAG}
            disabled={loading.retrieveRAG || !systemStatus.ragStored}
          >
            {loading.retrieveRAG ? '🔄 Reading...' : '📖 Read RAG History'}
          </button>
          <p className="control-description">
            Retrieve historical decision patterns to inform current blocking decisions
          </p>
        </div>
      </div>

      {/* Results Display */}
      <div className="results-display">
        {Object.entries(results).map(([action, result]) => (
          <div key={action} className={`result-item ${result.status}`}>
            <div className="result-header">
              <span className="result-icon">
                {result.status === 'success' ? '✅' : '❌'}
              </span>
              <span className="result-message">{result.message}</span>
            </div>
            {result.details && (
              <div className="result-details">
                {Array.isArray(result.details) ? (
                  // Handle array details (like test results)
                  result.details.map((detail, index) => (
                  <div key={index} className={`test-result ${detail.passed ? 'passed' : 'failed'}`}>
                    <span>{detail.test}: </span>
                    <span>{detail.status_code ? `HTTP ${detail.status_code}` : detail.error}</span>
                    {detail.passed ? ' ✅' : ' ❌'}
                  </div>
                  ))
                ) : (
                  // Handle object details (like RAG results) - show simple confirmation
                  <div className="rag-simple">
                    <div className="rag-stat">📝 Detailed results available in terminal output above</div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default ControlPanel;
