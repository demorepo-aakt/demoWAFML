#!/usr/bin/env python3
"""
Terraform RAG (Retrieval Augmented Generation) System
Provides intelligent Terraform best practices and WAF rule optimization using RAG
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import chromadb
from sentence_transformers import SentenceTransformer
import requests
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class TerraformKnowledge:
    """Container for Terraform knowledge base entry"""
    content: str
    source: str
    category: str  # 'best_practice', 'security', 'waf', 'performance'
    confidence: float
    metadata: Dict

class TerraformRAG:
    """RAG system for Terraform and AWS WAF best practices"""
    
    def __init__(self, knowledge_base_path: str = "terraform_knowledge"):
        self.knowledge_base_path = Path(knowledge_base_path)
        self.knowledge_base_path.mkdir(exist_ok=True)
        
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        self.chroma_client = chromadb.PersistentClient(path=str(self.knowledge_base_path / "chroma_db"))
        self.collection = self.chroma_client.get_or_create_collection(
            name="terraform_knowledge",
            metadata={"description": "Terraform and AWS WAF best practices"}
        )
        
        if self.collection.count() == 0:
            self._initialize_knowledge_base()
    
    def _initialize_knowledge_base(self):
        """Initialize the knowledge base with curated Terraform and WAF best practices"""
        logger.info("Initializing Terraform knowledge base...")
        

        terraform_best_practices = [
            {
                "content": """
                Terraform State Management Best Practices:
                1. Always use remote state backends (S3 + DynamoDB for locking)
                2. Enable state file encryption at rest
                3. Use state file versioning
                4. Implement proper IAM policies for state access
                5. Never commit state files to version control
                
                Example:
                terraform {
                  backend "s3" {
                    bucket         = "my-terraform-state"
                    key            = "prod/terraform.tfstate"
                    region         = "us-east-1"
                    encrypt        = true
                    dynamodb_table = "terraform-locks"
                  }
                }
                """,
                "source": "terraform_docs",
                "category": "best_practice",
                "confidence": 0.95
            },
            {
                "content": """
                AWS WAF Rule Optimization Guidelines:
                1. Order rules by specificity - most specific first
                2. Use rate-based rules for DDoS protection (start with 2000 req/5min)
                3. Implement geo-blocking for known malicious regions
                4. Use managed rule groups as baseline protection
                5. Custom rules should target specific attack patterns
                6. Always test rules in COUNT mode before BLOCK
                7. Monitor CloudWatch metrics for rule effectiveness
                
                Rule Priority Best Practices:
                - IP whitelist/blacklist: 1-10
                - Rate limiting: 11-20  
                - Managed rule groups: 21-50
                - Custom detection rules: 51-100
                """,
                "source": "aws_waf_docs",
                "category": "waf",
                "confidence": 0.9
            },
            {
                "content": """
                Security Best Practices for Terraform WAF Resources:
                1. Use least privilege IAM policies
                2. Enable logging for all WAF rules
                3. Implement proper resource tagging
                4. Use data sources instead of hardcoded values
                5. Validate input variables with proper types and constraints
                6. Use locals for complex expressions
                7. Implement proper error handling
                
                Example WAF rule structure:
                resource "aws_wafv2_web_acl" "example" {
                  name  = var.waf_name
                  scope = "REGIONAL"
                  
                  default_action {
                    allow {}
                  }
                  
                  rule {
                    name     = "RateLimitRule"
                    priority = 1
                    
                    action {
                      block {}
                    }
                    
                    statement {
                      rate_based_statement {
                        limit              = var.rate_limit
                        aggregate_key_type = "IP"
                      }
                    }
                    
                    visibility_config {
                      cloudwatch_metrics_enabled = true
                      metric_name                 = "RateLimitRule"
                      sampled_requests_enabled    = true
                    }
                  }
                }
                """,
                "source": "terraform_security_guide",
                "category": "security",
                "confidence": 0.92
            },
            {
                "content": """
                Dynamic WAF Rule Generation Best Practices:
                1. Use consistent naming conventions for generated rules
                2. Implement rule versioning and rollback capabilities
                3. Set appropriate TTL for temporary rules
                4. Use terraform workspaces for environment separation
                5. Implement proper validation before rule deployment
                6. Monitor rule performance and adjust thresholds
                7. Use terraform modules for reusable rule patterns
                
                Dynamic Rule Naming Convention:
                - ML_Generated_<timestamp>_<rule_type>
                - Predictive_<attack_type>_<confidence_level>
                - Auto_Block_<ip_hash>_<detection_method>
                
                Rule Management:
                - Maximum 100 custom rules per Web ACL
                - Use rule groups for complex logic
                - Implement rule cleanup for expired temporary blocks
                """,
                "source": "aws_best_practices",
                "category": "waf",
                "confidence": 0.88
            },
            {
                "content": """
                Performance Optimization for WAF Rules:
                1. Minimize regex complexity in string matching
                2. Use byte match instead of regex when possible  
                3. Limit the number of OR conditions in rules
                4. Use IP sets for large IP lists instead of individual rules
                5. Optimize rule evaluation order based on traffic patterns
                6. Use sampling for high-volume logging
                7. Implement rule caching where appropriate
                
                Rule Evaluation Optimization:
                - Place most likely to match rules first
                - Use NOT conditions sparingly
                - Combine similar conditions into single rules
                - Use managed rule groups for common patterns
                
                Cost Optimization:
                - Monitor WCU (Web ACL Capacity Units) usage
                - Use appropriate sampling rates for logging
                - Implement rule lifecycle management
                """,
                "source": "aws_performance_guide",
                "category": "performance",
                "confidence": 0.85
            },
            {
                "content": """
                ML-Driven WAF Rule Generation Patterns:
                1. Feature-based rule creation from ML model insights
                2. Confidence thresholds for automatic vs manual review
                3. A/B testing framework for new rules
                4. Feedback loops from blocked traffic analysis
                5. Integration with SIEM systems for correlation
                
                ML Rule Categories:
                - Behavioral anomaly detection (user patterns)
                - Request signature analysis (headers, cookies, params)
                - IP reputation and geolocation analysis
                - Temporal pattern recognition (request timing)
                - Content analysis (payload inspection)
                
                Implementation Strategy:
                - Start with high-confidence rules (>0.9)
                - Implement gradual rollout with monitoring
                - Use canary deployments for rule testing
                - Maintain human oversight for critical rules
                """,
                "source": "ml_security_patterns",
                "category": "best_practice",
                "confidence": 0.87
            },
            {
                "content": """
                Terraform Module Best Practices for WAF:
                1. Create reusable modules for common WAF patterns
                2. Use proper variable validation and descriptions
                3. Implement comprehensive outputs for integration
                4. Use semantic versioning for module releases
                5. Include examples and documentation
                6. Implement proper testing with terratest
                
                Module Structure:
                modules/
                ├── waf-basic/
                │   ├── main.tf
                │   ├── variables.tf
                │   ├── outputs.tf
                │   └── README.md
                ├── waf-advanced/
                └── waf-ml-rules/
                
                Variable Validation Example:
                variable "rate_limit" {
                  description = "Rate limit for requests per 5 minutes"
                  type        = number
                  default     = 2000
                  validation {
                    condition     = var.rate_limit >= 100 && var.rate_limit <= 20000000
                    error_message = "Rate limit must be between 100 and 20,000,000."
                  }
                }
                """,
                "source": "terraform_modules_guide",
                "category": "best_practice",
                "confidence": 0.91
            }
        ]
        

        for i, knowledge in enumerate(terraform_best_practices):
            self.add_knowledge(
                content=knowledge["content"],
                source=knowledge["source"],
                category=knowledge["category"],
                confidence=knowledge["confidence"],
                metadata={"index": i}
            )
        
        logger.info(f"Initialized knowledge base with {len(terraform_best_practices)} entries")
    
    def add_knowledge(self, content: str, source: str, category: str, 
                     confidence: float, metadata: Dict = None) -> str:
        """Add knowledge to the RAG system"""
        if metadata is None:
            metadata = {}
        

        content_hash = hashlib.md5(content.encode()).hexdigest()
        doc_id = f"{category}_{source}_{content_hash[:8]}"
        

        embedding = self.embedding_model.encode(content).tolist()
        

        self.collection.add(
            documents=[content],
            embeddings=[embedding],
            metadatas=[{
                "source": source,
                "category": category,
                "confidence": confidence,
                **metadata
            }],
            ids=[doc_id]
        )
        
        return doc_id
    
    def query_knowledge(self, query: str, category: Optional[str] = None, 
                       top_k: int = 3) -> List[TerraformKnowledge]:
        """Query the knowledge base for relevant information"""
        

        query_embedding = self.embedding_model.encode(query).tolist()
        

        where_clause = {"category": category} if category else None
        

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where_clause
        )
        

        knowledge_items = []
        for i in range(len(results['documents'][0])):
            knowledge = TerraformKnowledge(
                content=results['documents'][0][i],
                source=results['metadatas'][0][i]['source'],
                category=results['metadatas'][0][i]['category'],
                confidence=results['metadatas'][0][i]['confidence'],
                metadata=results['metadatas'][0][i]
            )
            knowledge_items.append(knowledge)
        
        return knowledge_items
    
    def get_terraform_recommendations(self, context: Dict) -> Dict[str, str]:
        """Get Terraform recommendations based on current context"""
        
        recommendations = {}
        

        if 'waf_rules' in context:
            rule_count = len(context['waf_rules'])
            query = f"WAF optimization for {rule_count} rules, performance best practices"
            knowledge = self.query_knowledge(query, category="performance", top_k=2)
            
            recommendations['performance'] = self._synthesize_recommendations(
                knowledge, "Performance optimization recommendations"
            )
        

        if 'detected_attacks' in context:
            attack_types = context['detected_attacks']
            query = f"WAF security rules for {', '.join(attack_types)} attacks"
            knowledge = self.query_knowledge(query, category="security", top_k=2)
            
            recommendations['security'] = self._synthesize_recommendations(
                knowledge, "Security enhancement recommendations"
            )
        

        query = "dynamic WAF rule generation and management best practices"
        knowledge = self.query_knowledge(query, category="best_practice", top_k=2)
        
        recommendations['best_practices'] = self._synthesize_recommendations(
            knowledge, "Best practices for dynamic rule management"
        )
        
        return recommendations
    
    def optimize_terraform_config(self, current_config: str, 
                                 optimization_goals: List[str]) -> str:
        """Optimize Terraform configuration based on best practices"""
        

        all_knowledge = []
        for goal in optimization_goals:
            knowledge = self.query_knowledge(f"Terraform {goal} optimization", top_k=2)
            all_knowledge.extend(knowledge)
        

        optimizations = []
        

        if "remote state" not in current_config.lower():
            optimizations.append(
                "Consider implementing remote state backend with S3 and DynamoDB locking"
            )
        
        if "encrypt" not in current_config.lower():
            optimizations.append(
                "Enable encryption for state files and sensitive resources"
            )
        
        if "variable" in current_config and "validation" not in current_config:
            optimizations.append(
                "Add variable validation blocks to ensure input correctness"
            )
        

        for knowledge in all_knowledge:
            if knowledge.confidence > 0.8:
                optimizations.append(f"Best Practice: {knowledge.content[:200]}...")
        
        return "\n".join(f"• {opt}" for opt in optimizations[:10])
    
    def generate_waf_rule_terraform(self, rule_spec: Dict) -> str:
        """Generate optimized Terraform code for WAF rules"""
        

        query = f"WAF {rule_spec.get('type', 'generic')} rule Terraform configuration"
        knowledge = self.query_knowledge(query, category="waf", top_k=2)
        

        terraform_template = f'''
resource "aws_wafv2_web_acl_rule" "{rule_spec.get('name', 'generated_rule')}" {{
  name     = "{rule_spec.get('name', 'ML_Generated_Rule')}"
  priority = {rule_spec.get('priority', 100)}

  action {{
    {rule_spec.get('action', 'block')} {{}}
  }}

  statement {{'''
        

        rule_type = rule_spec.get('type', 'byte_match')
        
        if rule_type == 'ip_set':
            terraform_template += f'''
    ip_set_reference_statement {{
      arn = aws_wafv2_ip_set.{rule_spec.get('name', 'generated')}_ip_set.arn
    }}'''
        
        elif rule_type == 'rate_based':
            terraform_template += f'''
    rate_based_statement {{
      limit              = {rule_spec.get('limit', 2000)}
      aggregate_key_type = "IP"
    }}'''
        
        else:  # byte_match
            terraform_template += f'''
    byte_match_statement {{
      search_string = "{rule_spec.get('search_string', 'bot')}"
      field_to_match {{
        single_header {{
          name = "{rule_spec.get('header_name', 'user-agent')}"
        }}
      }}
      text_transformation {{
        priority = 1
        type     = "{rule_spec.get('text_transformation', 'LOWERCASE')}"
      }}
      positional_constraint = "{rule_spec.get('positional_constraint', 'CONTAINS')}"
    }}'''
        
        terraform_template += f'''
  }}

  visibility_config {{
    cloudwatch_metrics_enabled = true
    metric_name                 = "{rule_spec.get('name', 'GeneratedRule')}"
    sampled_requests_enabled    = true
  }}

  tags = {{
    Name        = "{rule_spec.get('name', 'ML Generated Rule')}"
    Source      = "ML_Detection"
    Confidence  = "{rule_spec.get('confidence', 0.8)}"
    Generated   = "{rule_spec.get('timestamp', 'unknown')}"
  }}
}}'''
        

        comments = []
        for knowledge in knowledge:
            if knowledge.confidence > 0.85:

                lines = knowledge.content.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['best practice', 'recommendation', 'should']):
                        comments.append(f"# {line.strip()}")
        
        if comments:
            terraform_template = "\n".join(comments[:3]) + "\n" + terraform_template
        
        return terraform_template
    
    def _synthesize_recommendations(self, knowledge_items: List[TerraformKnowledge], 
                                  context: str) -> str:
        """Synthesize multiple knowledge items into coherent recommendations"""
        
        if not knowledge_items:
            return f"No specific recommendations found for: {context}"
        

        key_points = []
        for knowledge in knowledge_items:

            lines = knowledge.content.split('\n')
            for line in lines:
                line = line.strip()
                if (line.startswith(('1.', '2.', '3.', '4.', '5.')) or 
                    line.startswith(('-', '•', '*')) or
                    'best practice' in line.lower()):
                    key_points.append(line)
        

        unique_points = []
        seen = set()
        
        for knowledge in sorted(knowledge_items, key=lambda k: k.confidence, reverse=True):
            for point in key_points:
                point_key = point.lower().replace(' ', '')[:50]
                if point_key not in seen and len(point) > 10:
                    unique_points.append(point)
                    seen.add(point_key)
                    if len(unique_points) >= 5:
                        break
        
        if unique_points:
            return f"{context}:\n" + "\n".join(f"• {point}" for point in unique_points)
        else:
            return f"General recommendation: Review current configuration against Terraform and AWS WAF best practices"
    
    def get_knowledge_stats(self) -> Dict:
        """Get statistics about the knowledge base"""
        count = self.collection.count()
        

        results = self.collection.get()
        categories = {}
        sources = {}
        
        for metadata in results['metadatas']:
            category = metadata.get('category', 'unknown')
            source = metadata.get('source', 'unknown')
            
            categories[category] = categories.get(category, 0) + 1
            sources[source] = sources.get(source, 0) + 1
        
        return {
            'total_documents': count,
            'categories': categories,
            'sources': sources
        }

# Example usage and testing
if __name__ == '__main__':
    # Initialize RAG system
    rag = TerraformRAG()
    
    # Test queries
    test_queries = [
        "How to optimize WAF rules for performance?",
        "Best practices for Terraform state management",
        "Security considerations for dynamic WAF rules",
        "ML-driven WAF rule generation patterns"
    ]
    
    print("=== Terraform RAG System Test ===\n")
    
    for query in test_queries:
        print(f"Query: {query}")
        knowledge = rag.query_knowledge(query, top_k=2)
        
        for i, k in enumerate(knowledge):
            print(f"  Result {i+1} ({k.category}, confidence: {k.confidence}):")
            print(f"    {k.content[:150]}...")
        print()
    
    # Test recommendations
    context = {
        'waf_rules': ['rate_limit', 'ip_block', 'user_agent_filter'],
        'detected_attacks': ['cookie_manipulation', 'parameter_tampering']
    }
    
    recommendations = rag.get_terraform_recommendations(context)
    print("=== Recommendations ===")
    for category, rec in recommendations.items():
        print(f"{category.upper()}:")
        print(rec)
        print()
    
    # Test Terraform generation
    rule_spec = {
        'name': 'ml_cookie_block',
        'type': 'byte_match',
        'action': 'block',
        'search_string': 'attack_cookie',
        'header_name': 'cookie',
        'confidence': 0.92
    }
    
    terraform_code = rag.generate_waf_rule_terraform(rule_spec)
    print("=== Generated Terraform ===")
    print(terraform_code)
