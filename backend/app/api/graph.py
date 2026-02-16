"""
Graph API endpoints for Neo4j attack surface graph.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
from app.db.neo4j_client import get_neo4j_client, Neo4jClient
from app.graph.ingestion import (
    ingest_domain_discovery,
    ingest_port_scan,
    ingest_http_probe,
    ingest_resource_enumeration,
    ingest_vulnerability_scan,
    ingest_mitre_data
)
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])


class GraphIngestRequest(BaseModel):
    """Request model for graph data ingestion."""
    phase: str  # domain_discovery, port_scan, http_probe, resource_enum, vuln_scan, mitre
    data: Dict[str, Any]
    user_id: Optional[str] = None
    project_id: Optional[str] = None


class GraphQueryRequest(BaseModel):
    """Request model for graph queries."""
    query: str
    parameters: Optional[Dict[str, Any]] = None


@router.post("/ingest")
async def ingest_data(
    request: GraphIngestRequest,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Ingest data into the Neo4j graph database.
    
    Args:
        request: Ingestion request with phase, data, and tenant info
        client: Neo4j client instance
        
    Returns:
        Ingestion statistics
    """
    try:
        # Route to appropriate ingestion function
        if request.phase == "domain_discovery":
            stats = ingest_domain_discovery(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "port_scan":
            stats = ingest_port_scan(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "http_probe":
            stats = ingest_http_probe(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "resource_enum":
            stats = ingest_resource_enumeration(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "vuln_scan":
            stats = ingest_vulnerability_scan(
                client, request.data, request.user_id, request.project_id
            )
        elif request.phase == "mitre":
            stats = ingest_mitre_data(
                client, request.data, request.user_id, request.project_id
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown phase: {request.phase}")
        
        return {
            "success": True,
            "phase": request.phase,
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"Error ingesting data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/query")
async def execute_query(
    request: GraphQueryRequest,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Execute a Cypher query on the graph database.
    
    Args:
        request: Query request with Cypher query and parameters
        client: Neo4j client instance
        
    Returns:
        Query results
    """
    try:
        results = client.execute_query(request.query, request.parameters)
        
        return {
            "success": True,
            "count": len(results),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-surface/{project_id}")
async def get_attack_surface(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get the complete attack surface for a project.
    
    Args:
        project_id: Project identifier
        client: Neo4j client instance
        
    Returns:
        Attack surface graph data
    """
    try:
        data = client.get_attack_surface(project_id)
        
        return {
            "success": True,
            "project_id": project_id,
            "data": data
        }
        
    except Exception as e:
        logger.error(f"Error getting attack surface: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerabilities/{project_id}")
async def get_vulnerabilities(
    project_id: str,
    severity: Optional[str] = None,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get vulnerabilities for a project.
    
    Args:
        project_id: Project identifier
        severity: Optional severity filter (info, low, medium, high, critical)
        client: Neo4j client instance
        
    Returns:
        List of vulnerabilities
    """
    try:
        query = """
        MATCH (v:Vulnerability {project_id: $project_id})
        """
        
        parameters = {"project_id": project_id}
        
        if severity:
            query += " WHERE v.severity = $severity"
            parameters["severity"] = severity
        
        query += """
        OPTIONAL MATCH (v)-[:FOUND_AT]->(e:Endpoint)
        OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(p:Parameter)
        RETURN v, e, collect(p) as parameters
        ORDER BY v.severity DESC, v.discovered_at DESC
        """
        
        results = client.execute_query(query, parameters)
        
        return {
            "success": True,
            "project_id": project_id,
            "severity": severity,
            "count": len(results),
            "vulnerabilities": results
        }
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/technologies/{project_id}")
async def get_technologies(
    project_id: str,
    with_cves: bool = False,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get technologies detected for a project.
    
    Args:
        project_id: Project identifier
        with_cves: Whether to include CVE information
        client: Neo4j client instance
        
    Returns:
        List of technologies
    """
    try:
        if with_cves:
            query = """
            MATCH (t:Technology {project_id: $project_id})
            OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(cve:CVE)
            RETURN t, collect(cve) as cves
            ORDER BY t.name
            """
        else:
            query = """
            MATCH (t:Technology {project_id: $project_id})
            RETURN t
            ORDER BY t.name
            """
        
        results = client.execute_query(query, {"project_id": project_id})
        
        return {
            "success": True,
            "project_id": project_id,
            "count": len(results),
            "technologies": results
        }
        
    except Exception as e:
        logger.error(f"Error getting technologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/project/{project_id}")
async def clear_project_data(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Clear all graph data for a project.
    
    Args:
        project_id: Project identifier
        client: Neo4j client instance
        
    Returns:
        Number of nodes deleted
    """
    try:
        deleted_count = client.clear_project_data(project_id)
        
        return {
            "success": True,
            "project_id": project_id,
            "deleted_count": deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error clearing project data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check(
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Check Neo4j database health.
    
    Returns:
        Health status information
    """
    try:
        health = client.health_check()
        return health
        
    except Exception as e:
        logger.error(f"Error checking health: {e}")
        return {
            "status": "error",
            "healthy": False,
            "error": str(e)
        }


@router.get("/stats/{project_id}")
async def get_stats(
    project_id: str,
    client: Neo4jClient = Depends(get_neo4j_client)
) -> Dict[str, Any]:
    """
    Get statistics for a project's graph data.
    
    Args:
        project_id: Project identifier
        client: Neo4j client instance
        
    Returns:
        Graph statistics
    """
    try:
        query = """
        MATCH (n {project_id: $project_id})
        WITH labels(n) as node_labels
        UNWIND node_labels as label
        RETURN label, count(*) as count
        ORDER BY count DESC
        """
        
        results = client.execute_query(query, {"project_id": project_id})
        
        # Convert to dictionary
        stats = {result['label']: result['count'] for result in results}
        
        return {
            "success": True,
            "project_id": project_id,
            "node_counts": stats,
            "total_nodes": sum(stats.values())
        }
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
