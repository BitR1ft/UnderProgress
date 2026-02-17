"""
Query Graph Tool

Tool for querying Neo4j graph database with natural language to Cypher conversion.
"""

from typing import Dict, Any
from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.core.config import settings
from neo4j import AsyncGraphDatabase
import logging

logger = logging.getLogger(__name__)


class QueryGraphTool(BaseTool):
    """
    Tool for querying the Neo4j attack graph.
    
    Converts natural language queries to Cypher and executes them.
    """
    
    def __init__(self, user_id: str = None, project_id: str = None):
        """
        Initialize QueryGraphTool.
        
        Args:
            user_id: Current user ID for tenant filtering
            project_id: Current project ID for tenant filtering
        """
        self.user_id = user_id
        self.project_id = project_id
        super().__init__()
    
    def _define_metadata(self) -> ToolMetadata:
        """Define tool metadata"""
        return ToolMetadata(
            name="query_graph",
            description="""Query the Neo4j attack surface graph using natural language or Cypher.
            
Examples:
- "Find all domains and their subdomains"
- "Show all high severity vulnerabilities"
- "List open ports for IP 10.0.0.1"
- "Find all endpoints with XSS vulnerabilities"
            
The tool converts natural language to Cypher queries and returns results.""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural language query or Cypher query to execute"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 10)",
                        "default": 10
                    }
                },
                "required": ["query"]
            }
        )
    
    async def execute(self, query: str, limit: int = 10, **kwargs) -> str:
        """
        Execute graph query.
        
        Args:
            query: Natural language or Cypher query
            limit: Maximum results
            
        Returns:
            Query results as formatted string
        """
        try:
            # Convert natural language to Cypher if needed
            cypher_query = self._convert_to_cypher(query, limit)
            
            # Add tenant filtering
            cypher_query = self._add_tenant_filter(cypher_query)
            
            # Execute query
            driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
            
            async with driver.session() as session:
                result = await session.run(cypher_query)
                records = await result.data()
            
            await driver.close()
            
            if not records:
                return "No results found."
            
            # Format results
            return self._format_results(records, limit)
            
        except Exception as e:
            logger.error(f"Query graph error: {e}", exc_info=True)
            return f"Error executing query: {str(e)}"
    
    def _convert_to_cypher(self, query: str, limit: int) -> str:
        """
        Convert natural language query to Cypher.
        
        Args:
            query: Natural language query
            limit: Result limit
            
        Returns:
            Cypher query string
        """
        query_lower = query.lower()
        
        # Check if already Cypher
        if any(keyword in query_lower for keyword in ['match', 'return', 'where', 'create']):
            # Add LIMIT if not present
            if 'limit' not in query_lower:
                return f"{query} LIMIT {limit}"
            return query
        
        # Convert common natural language patterns to Cypher
        
        # Domains and subdomains
        if 'domain' in query_lower and 'subdomain' in query_lower:
            return f"""
            MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
            RETURN d.name as domain, collect(s.name) as subdomains
            LIMIT {limit}
            """
        
        # Vulnerabilities
        if 'vulnerabilit' in query_lower:
            severity_filter = ""
            if 'high' in query_lower or 'critical' in query_lower:
                severity_filter = "WHERE v.severity IN ['high', 'critical']"
            
            return f"""
            MATCH (v:Vulnerability)
            {severity_filter}
            RETURN v.title as title, v.severity as severity, v.type as type
            LIMIT {limit}
            """
        
        # Open ports
        if 'port' in query_lower and 'open' in query_lower:
            ip_match = ""
            words = query_lower.split()
            for i, word in enumerate(words):
                if word == 'ip' and i + 1 < len(words):
                    ip_match = f"WHERE ip.address = '{words[i+1]}'"
            
            return f"""
            MATCH (ip:IP)-[:HAS_PORT]->(p:Port)
            {ip_match}
            WHERE p.state = 'open'
            RETURN ip.address as ip, p.port as port, p.protocol as protocol
            LIMIT {limit}
            """
        
        # Technologies
        if 'technolog' in query_lower:
            return f"""
            MATCH (t:Technology)
            RETURN t.name as technology, t.version as version
            LIMIT {limit}
            """
        
        # Endpoints
        if 'endpoint' in query_lower:
            return f"""
            MATCH (e:Endpoint)
            RETURN e.url as endpoint, e.method as method
            LIMIT {limit}
            """
        
        # Default: Search across multiple node types
        return f"""
        MATCH (n)
        WHERE n.name CONTAINS '{query}' OR n.title CONTAINS '{query}'
        RETURN labels(n) as type, n.name as name, n.title as title
        LIMIT {limit}
        """
    
    def _add_tenant_filter(self, cypher_query: str) -> str:
        """
        Add tenant filtering to Cypher query.
        
        Args:
            cypher_query: Original Cypher query
            
        Returns:
            Modified query with tenant filters
        """
        # Only add if user_id or project_id is set
        if not self.user_id and not self.project_id:
            return cypher_query
        
        # This is a simplified implementation
        # In production, you'd need more sophisticated query rewriting
        filters = []
        if self.user_id:
            filters.append(f"n.user_id = '{self.user_id}'")
        if self.project_id:
            filters.append(f"n.project_id = '{self.project_id}'")
        
        if filters:
            filter_clause = " AND ".join(filters)
            # Insert WHERE clause or append to existing
            if 'WHERE' in cypher_query.upper():
                return cypher_query.replace('WHERE', f'WHERE ({filter_clause}) AND', 1)
            else:
                # Insert before RETURN
                parts = cypher_query.split('RETURN')
                if len(parts) == 2:
                    return f"{parts[0]} WHERE {filter_clause} RETURN {parts[1]}"
        
        return cypher_query
    
    def _format_results(self, records: list, limit: int) -> str:
        """
        Format query results for display.
        
        Args:
            records: Query results
            limit: Maximum results shown
            
        Returns:
            Formatted string
        """
        if not records:
            return "No results found."
        
        # Format as a table-like structure
        output = f"Found {len(records)} result(s):\n\n"
        
        for i, record in enumerate(records[:limit], 1):
            output += f"{i}. "
            for key, value in record.items():
                if isinstance(value, list):
                    output += f"{key}: [{', '.join(map(str, value))}]  "
                else:
                    output += f"{key}: {value}  "
            output += "\n"
        
        if len(records) > limit:
            output += f"\n(Showing {limit} of {len(records)} results)"
        
        return output
