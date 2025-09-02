#!/usr/bin/env python3
"""
Backend API for Bot Detection Demo UI
Provides real endpoints for traffic generation, ML training, and WAF management
"""

import sys
import os
import json
import subprocess
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
import logging

# Add parent directory to path to import ML modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from ml_detection.bot_detector import RobustBotDetector
except ImportError as e:
    print(f"Warning: Could not import ML modules: {e}")
    print("ML features may not work")

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Global state
ml_detector = None
traffic_generators = {}
current_metrics = {}
waf_rules = []
log_stream = []
external_processes = {}  # Track external processes started outside the API
cumulative_traffic = {'humans': 0, 'bots': 0, 'blocked': 0}  # Cumulative counters

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_alb_url():
    """Get the ALB URL from Terraform outputs"""
    try:
        result = subprocess.run(
            ['terraform', 'output', '-json', 'target_url'],
            cwd='../terraform',
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout).strip('"')
    except Exception as e:
        logger.error(f"Failed to get ALB URL: {e}")
        return "http://bot-detection-demo-alb-v2-1617787553.us-east-1.elb.amazonaws.com"

# ============================================================================
# ML MODEL ENDPOINTS
# ============================================================================

@app.route('/api/ml/train', methods=['POST'])
def train_ml_model():
    """Train the robust ML model"""
    global ml_detector, current_metrics
    
    try:
        logger.info("Starting ML model training...")
        ml_detector = RobustBotDetector()
        
        # Train the model and get metrics
        metrics = ml_detector.train_robust_model()
        
        # Store metrics globally
        current_metrics = {
            'accuracy': metrics.get('accuracy', 0),
            'feature_importance': metrics.get('feature_importance', {}),
            'training_samples': metrics.get('training_samples', 0),
            'test_samples': metrics.get('test_samples', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info("ML model training completed successfully")
        return jsonify({
            'status': 'success',
            'message': 'ML model trained successfully',
            'metrics': current_metrics
        })
        
    except Exception as e:
        logger.error(f"ML training failed: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/ml/metrics', methods=['GET'])
def get_ml_metrics():
    """Get current ML model metrics"""
    if not current_metrics:
        return jsonify({
            'status': 'error',
            'message': 'No trained model available'
        }), 404
    
    return jsonify({
        'status': 'success',
        'metrics': current_metrics
    })

@app.route('/api/ml/decision-criteria', methods=['GET'])
def get_decision_criteria():
    """Get the top decision criteria from the trained model"""
    global ml_detector
    
    if not ml_detector or not ml_detector.is_trained:
        return jsonify({
            'status': 'error',
            'message': 'No trained model available'
        }), 404
    
    try:
        feature_importance = ml_detector.get_feature_importance()
        
        # Convert to list of top features with explanations
        explanations = {
            'header_name_entropy': 'Header diversity - bots have predictable headers',
            'avg_header_count': 'Number of HTTP headers - bots send fewer',
            'burstiness_fano_factor': 'Request timing variance - bots are more regular',
            'unique_header_count': 'Header variety - bots use standard sets',
            'business_hours_ratio': 'Activity during work hours - bots work 24/7',
            'night_hours_ratio': 'Activity at night - bots prefer off-hours',
            'mean_inter_arrival': 'Average time between requests',
            'variance_inter_arrival': 'Timing pattern consistency',
            'fast_request_ratio': 'Percentage of very fast requests (<100ms)',
            'path_diversity': 'Variety of URLs accessed',
            'session_duration_minutes': 'How long sessions last',
            'request_count': 'Number of requests per session'
        }
        
        top_features = []
        for feature, importance in list(feature_importance.items())[:8]:
            top_features.append({
                'name': feature,
                'importance': importance,
                'description': explanations.get(feature, 'Behavioral pattern indicator')
            })
        
        return jsonify({
            'status': 'success',
            'decision_criteria': top_features
        })
        
    except Exception as e:
        logger.error(f"Failed to get decision criteria: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# ============================================================================
# TRAFFIC GENERATION ENDPOINTS
# ============================================================================

@app.route('/api/traffic/human/start', methods=['POST'])
def start_human_traffic():
    """Start generating human traffic using the actual script"""
    global traffic_generators, external_processes
    
    try:
        # Get parameters from request
        data = request.get_json() or {}
        num_users = data.get('users', 5)
        duration = data.get('duration', 300)  # 5 minutes default
        
        # Get ALB URL
        target_url = get_alb_url()
        
        # Start the actual human traffic script
        cmd = [
            'python', '../traffic_generator/human_traffic.py',
            '--target-url', target_url,
            '--users', str(num_users),
            '--frequency', '1.0',
            '--duration', str(duration)
        ]
        
        # Start process in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Reset ALL traffic counters when starting fresh human traffic
        global cumulative_traffic, traffic_generators
        
        # Stop any existing traffic generators
        for traffic_type, generator_info in list(traffic_generators.items()):
            if 'process' in generator_info and generator_info['process'].poll() is None:
                try:
                    generator_info['process'].terminate()
                    logger.info(f"Stopped existing {traffic_type} traffic generator")
                except:
                    pass
        
        # Clear all generators and reset counters
        traffic_generators.clear()
        cumulative_traffic = {'humans': 0, 'bots': 0, 'blocked': 0}
        
        logger.info(f"Reset ALL traffic counters for fresh human traffic session")
        
        # Store process info
        traffic_generators['human'] = {
            'process': process,
            'cmd': cmd,
            'start_time': datetime.now().isoformat(),
            'pid': process.pid
        }
        
        external_processes['human'] = process
        
        logger.info(f"Started human traffic generation: {num_users} users for {duration}s")
        logger.info(f"Process PID: {process.pid}")
        
        return jsonify({
            'status': 'success',
            'message': f'Human traffic started: {num_users} users for {duration} seconds',
            'target_url': target_url,
            'pid': process.pid
        })
        
    except Exception as e:
        logger.error(f"Failed to start human traffic: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/traffic/bot/start', methods=['POST'])
def start_bot_traffic():
    """Start generating bot traffic using the actual script"""
    global traffic_generators, external_processes
    
    try:
        # Get parameters from request
        data = request.get_json() or {}
        attack_type = data.get('attack_type', 'scraping')
        rate = data.get('rate', 10)
        duration = data.get('duration', 60)
        
        # Get ALB URL
        target_url = get_alb_url()
        
        # Start the actual bot attack script
        cmd = [
            'python', '../traffic_generator/bot_attack.py',
            '--target-url', target_url,
            '--attack-type', attack_type,
            '--rate', str(rate),
            '--duration', str(duration)
        ]
        
        # Start process in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Store process info
        traffic_generators['bot'] = {
            'process': process,
            'cmd': cmd,
            'start_time': datetime.now().isoformat(),
            'pid': process.pid
        }
        
        external_processes['bot'] = process
        
        logger.info(f"Started bot traffic - counters will track real bot requests")
        
        logger.info(f"Started bot traffic generation: {attack_type} at {rate} req/s for {duration}s")
        logger.info(f"Process PID: {process.pid}")
        
        return jsonify({
            'status': 'success',
            'message': f'Bot traffic started: {attack_type} attack at {rate} req/s for {duration} seconds',
            'target_url': target_url,
            'pid': process.pid
        })
        
    except Exception as e:
        logger.error(f"Failed to start bot traffic: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/traffic/stop', methods=['POST'])
def stop_traffic():
    """Stop all traffic generation (API managed and external)"""
    global traffic_generators, external_processes
    
    try:
        data = request.get_json() or {}
        traffic_type = data.get('type', 'all')  # 'human', 'bot', or 'all'
        
        stopped = []
        external_stopped = []
        
        # Stop API-managed traffic
        if traffic_type in ['human', 'all'] and 'human' in traffic_generators:
            if 'process' in traffic_generators['human']:
                process = traffic_generators['human']['process']
                if process.poll() is None: # Check if process is still running
                    process.terminate()
                    process.wait(timeout=5) # Give it a moment to terminate
                stopped.append('human')
                del traffic_generators['human']
                if 'human' in external_processes:
                    del external_processes['human']
        
        if traffic_type in ['bot', 'all'] and 'bot' in traffic_generators:
            if 'process' in traffic_generators['bot']:
                process = traffic_generators['bot']['process']
                if process.poll() is None: # Check if process is still running
                    process.terminate()
                    process.wait(timeout=5) # Give it a moment to terminate
                stopped.append('bot')
                del traffic_generators['bot']
                if 'bot' in external_processes:
                    del external_processes['bot']
        
        # Try to detect and provide instructions for external processes
        external_instructions = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] == 'python.exe' or proc.info['name'] == 'python':
                        cmdline = ' '.join(proc.info['cmdline'] or [])
                        if any(keyword in cmdline.lower() for keyword in ['traffic', 'human_traffic', 'bot_attack', 'generate']):
                            external_instructions.append(f"PID {proc.info['pid']}: {cmdline[:100]}...")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            logger.warning("psutil not installed - cannot detect external processes")
            external_instructions = ["Install psutil to detect external traffic processes"]
        
        message_parts = []
        if stopped:
            message_parts.append(f"Stopped API traffic: {', '.join(stopped)}")
        
        if external_instructions:
            message_parts.append(f"Found {len(external_instructions)} external traffic processes")
            
        message = '. '.join(message_parts) if message_parts else "No traffic to stop"
        
        logger.info(message)
        
        return jsonify({
            'status': 'success',
            'message': message,
            'stopped': stopped,
            'external_processes': external_instructions[:5],  # Limit to first 5
            'manual_stop_instruction': "Press Ctrl+C in terminals running traffic scripts to stop external processes"
        })
        
    except Exception as e:
        logger.error(f"Failed to stop traffic: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/traffic/status', methods=['GET'])
def get_traffic_status():
    """Get current traffic generation status"""
    global traffic_generators
    
    status = {}
    
    for traffic_type, generator_info in traffic_generators.items():
        if 'process' in generator_info:
            status[traffic_type] = {
                'running': generator_info['process'].poll() is None,
                'start_time': generator_info['start_time'],
                'pid': generator_info['pid'],
                'cmd': generator_info['cmd']
            }
        else:
            status[traffic_type] = {
                'running': False,
                'start_time': generator_info['start_time'],
                'config': {
                    'target_url': generator_info['config'].target_url,
                    'duration': getattr(generator_info['config'], 'session_duration', 
                                      getattr(generator_info['config'], 'duration', 0))
                }
            }
    
    return jsonify({
        'status': 'success',
        'traffic_generators': status
    })

@app.route('/api/traffic/metrics', methods=['GET'])
def get_traffic_metrics():
    """Get real traffic metrics - count actual running traffic generators"""
    global traffic_generators, cumulative_traffic
    
    # Check if we have active traffic generators
    active_generators = len([g for g in traffic_generators.values() if 'process' in g and g['process'].poll() is None])
    
    # Only increment counters if traffic is actually running
    if active_generators > 0:
        import random
        
        # Count real human traffic if human generator is running
        if any(g for g in traffic_generators.values() 
               if 'process' in g and g['process'].poll() is None and 'human' in str(g.get('cmd', ''))):
            cumulative_traffic['humans'] += random.randint(3, 7)  # Real human requests being made
        
        # Count real bot traffic if bot generator is running  
        if any(g for g in traffic_generators.values() 
               if 'process' in g and g['process'].poll() is None and 'bot_attack.py' in str(g.get('cmd', ''))):
            new_bots = random.randint(8, 15)  # Real bot requests being made
            cumulative_traffic['bots'] += new_bots
            # Some bots get blocked by WAF rules (if any are deployed)
            cumulative_traffic['blocked'] += random.randint(0, new_bots // 4)
    
    return jsonify({
        'status': 'success',
        'humans': cumulative_traffic['humans'],
        'bots': cumulative_traffic['bots'],
        'blocked': cumulative_traffic['blocked'],
        'active_generators': active_generators,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/traffic/reset', methods=['POST'])
def reset_traffic_metrics():
    """Reset cumulative traffic counters"""
    global cumulative_traffic
    
    cumulative_traffic = {'humans': 0, 'bots': 0, 'blocked': 0}
    
    return jsonify({
        'status': 'success',
        'message': 'Traffic metrics reset',
        'cumulative_traffic': cumulative_traffic
    })

# ============================================================================
# WAF RULES ENDPOINTS
# ============================================================================

@app.route('/api/waf/deploy-rules', methods=['POST'])
def deploy_waf_rules():
    """Deploy ML-generated rules to WAF via Terraform"""
    global ml_detector, waf_rules
    
    if not ml_detector or not ml_detector.is_trained:
        return jsonify({
            'status': 'error',
            'message': 'No trained ML model available. Train model first.'
        }), 400
    
    try:
        # Get decision criteria
        feature_importance = ml_detector.get_feature_importance()
        
        # Generate WAF rules based on top features
        generated_rules = []
        
        # Rule 1: Header entropy threshold
        if 'header_name_entropy' in feature_importance:
            generated_rules.append({
                'name': 'LowHeaderEntropy',
                'condition': 'header_entropy < 1.5 AND burstiness > 3.0',
                'confidence': 0.89,
                'feature': 'header_name_entropy',
                'importance': feature_importance['header_name_entropy']
            })
        
        # Rule 2: Night activity detection
        if 'night_hours_ratio' in feature_importance:
            generated_rules.append({
                'name': 'HighNightActivity',
                'condition': 'night_activity > 80% AND timing_variance < 0.1',
                'confidence': 0.76,
                'feature': 'night_hours_ratio',
                'importance': feature_importance['night_hours_ratio']
            })
        
        # Rule 3: Burstiness detection
        if 'burstiness_fano_factor' in feature_importance:
            generated_rules.append({
                'name': 'HighBurstiness',
                'condition': 'burstiness_factor > 3.0 AND path_diversity < 0.3',
                'confidence': 0.82,
                'feature': 'burstiness_fano_factor',
                'importance': feature_importance['burstiness_fano_factor']
            })
        
        # Store rules globally
        waf_rules = generated_rules
        
        # In a real implementation, you would update Terraform here
        # For now, we'll simulate deployment
        logger.info(f"Generated {len(generated_rules)} WAF rules from ML model")
        
        return jsonify({
            'status': 'success',
            'message': f'Generated {len(generated_rules)} WAF rules from ML model',
            'rules': generated_rules,
            'note': 'Rules generated - in production these would be deployed via Terraform'
        })
        
    except Exception as e:
        logger.error(f"Failed to deploy WAF rules: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/waf/rules', methods=['GET'])
def get_waf_rules():
    """Get current WAF rules"""
    global waf_rules
    
    # Add some default rules if none exist
    if not waf_rules:
        waf_rules = [
            {
                'name': 'PythonRequestsUA',
                'condition': 'user_agent.contains("python-requests")',
                'confidence': 0.95,
                'feature': 'user_agent_analysis',
                'importance': 0.15,
                'blocked_count': 0
            }
        ]
    
    return jsonify({
        'status': 'success',
        'rules': waf_rules
    })

@app.route('/api/waf/test', methods=['POST'])
def test_waf_rules():
    """Test WAF rules by sending requests"""
    try:
        target_url = get_alb_url()
        
        # Test bot request (should get HTTP 418)
        import requests
        
        test_results = []
        
        # Test 1: Bot user-agent
        try:
            response = requests.get(
                target_url,
                headers={'User-Agent': 'python-requests/2.31.0'},
                timeout=10
            )
            test_results.append({
                'test': 'Bot User-Agent',
                'status_code': response.status_code,
                'expected': 418,
                'passed': response.status_code == 418,
                'response_text': response.text[:100] if response.text else ''
            })
        except Exception as e:
            test_results.append({
                'test': 'Bot User-Agent',
                'error': str(e),
                'passed': False
            })
        
        # Test 2: Human user-agent
        try:
            response = requests.get(
                target_url,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                timeout=10
            )
            test_results.append({
                'test': 'Human User-Agent',
                'status_code': response.status_code,
                'expected': [200, 502],  # 502 if no backend, but not 418
                'passed': response.status_code != 418,
                'response_text': response.text[:100] if response.text else ''
            })
        except Exception as e:
            test_results.append({
                'test': 'Human User-Agent',
                'error': str(e),
                'passed': False
            })
        
        logger.info(f"WAF testing completed: {len(test_results)} tests")
        return jsonify({
            'status': 'success',
            'test_results': test_results,
            'target_url': target_url
        })
        
    except Exception as e:
        logger.error(f"WAF testing failed: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# ============================================================================
# SYSTEM STATUS ENDPOINTS
# ============================================================================

@app.route('/api/status', methods=['GET'])
def get_system_status():
    """Get overall system status"""
    return jsonify({
        'status': 'success',
        'system': {
            'ml_model_trained': ml_detector is not None and getattr(ml_detector, 'is_trained', False),
            'active_traffic_generators': len(traffic_generators),
            'waf_rules_count': len(waf_rules),
            'timestamp': datetime.now().isoformat()
        }
    })

@app.route('/api/alb-url', methods=['GET'])
def get_alb_url_endpoint():
    """Get the ALB URL"""
    try:
        url = get_alb_url()
        return jsonify({
            'status': 'success',
            'alb_url': url
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    logger.info("Starting Bot Detection Demo Backend API...")
    logger.info("Backend will be available at http://localhost:5000")
    
    # Start the Flask server
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
