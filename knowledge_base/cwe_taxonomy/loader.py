"""
CWE Taxonomy Loader.

Loads the MITRE Common Weakness Enumeration (CWE) hierarchy into Neo4j,
allowing the system to reason about vulnerability categories
(e.g., recognizing that CWE-89 SQLi is a child of CWE-74 Injection).
"""
from __future__ import annotations

import json
from pathlib import Path
from loguru import logger
from typing import Any

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None


class CWETaxonomyLoader:
    def __init__(self, neo4j_uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "secureai_neo4j"):
        self.driver = None
        if GraphDatabase:
            try:
                self.driver = GraphDatabase.driver(neo4j_uri, auth=(user, password))
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j: {e}")

    def load_from_json(self, json_path: str) -> None:
        """
        Load CWE nodes and parent-child relationships from a JSON taxonomy file.
        Format expected: list of dicts with 'cwe_id', 'name', 'parents'
        """
        path = Path(json_path)
        if not path.exists():
            logger.warning(f"CWE taxonomy file not found: {json_path}")
            return
            
        with open(path, "r") as f:
            cwe_list = json.load(f)
            
        if not self.driver:
            logger.error("Neo4j driver not initialized")
            return

        def _create_cwe(tx, cwe_id, name):
            query = """
            MERGE (c:CWE {id: $cwe_id})
            SET c.name = $name
            """
            tx.run(query, cwe_id=cwe_id, name=name)

        def _create_relationship(tx, child_id, parent_id):
            query = """
            MATCH (child:CWE {id: $child_id})
            MATCH (parent:CWE {id: $parent_id})
            MERGE (child)-[:IS_A]->(parent)
            """
            tx.run(query, child_id=child_id, parent_id=parent_id)

        with self.driver.session() as session:
            # 1. Create all nodes
            for cwe in cwe_list:
                session.execute_write(_create_cwe, cwe.get("cwe_id"), cwe.get("name"))
                
            # 2. Create relationships
            for cwe in cwe_list:
                child_id = cwe.get("cwe_id")
                for parent_id in cwe.get("parents", []):
                    session.execute_write(_create_relationship, child_id, parent_id)
                    
        logger.info(f"Loaded {len(cwe_list)} CWEs into Neo4j taxonomy graph")

if __name__ == "__main__":
    loader = CWETaxonomyLoader()
    # Path to a pre-processed CWE JSON file
    loader.load_from_json("data/raw/cwe_taxonomy.json")
