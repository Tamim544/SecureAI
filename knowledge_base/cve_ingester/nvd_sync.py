"""
NVD CVE Ingester.

Fetches CVE data from the NIST National Vulnerability Database (NVD) API
and populates the Neo4j Knowledge Graph.
"""
from __future__ import annotations

import requests
import time
from datetime import datetime, timedelta
from loguru import logger
from typing import Any

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None


class NVDSyncEngine:
    def __init__(self, neo4j_uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "secureai_neo4j"):
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.driver = None
        if GraphDatabase:
            try:
                self.driver = GraphDatabase.driver(neo4j_uri, auth=(user, password))
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j: {e}")

    def fetch_recent_cves(self, days_back: int = 7) -> list[dict[str, Any]]:
        """Fetch CVEs published in the last N days."""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        # NVD API expects ISO 8601 format like: 2021-08-04T13:00:00.000
        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "resultsPerPage": 2000
        }
        
        logger.info(f"Fetching CVEs from {start_str} to {end_str}")
        cves = []
        try:
            # Note: NVD API rate limits strictly (5 req/min without API key, 50 req/min with API key)
            # Add API key if scaling up: headers={"apiKey": "YOUR_KEY"}
            response = requests.get(self.api_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                cves = data.get("vulnerabilities", [])
                logger.info(f"Fetched {len(cves)} CVEs")
            else:
                logger.error(f"NVD API returned {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to fetch from NVD: {e}")
            
        return cves

    def ingest_to_neo4j(self, cves: list[dict[str, Any]]) -> None:
        """Ingest CVE data into Neo4j graph database."""
        if not self.driver:
            logger.error("Neo4j driver not initialized")
            return
            
        def _create_cve(tx, cve_id, description, published_date, cvss_score):
            query = """
            MERGE (c:CVE {id: $cve_id})
            SET c.description = $description,
                c.published = $published_date,
                c.cvss = $cvss_score
            """
            tx.run(query, cve_id=cve_id, description=description, 
                   published_date=published_date, cvss_score=cvss_score)

        with self.driver.session() as session:
            for item in cves:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                    
                # Extract english description
                desc = ""
                for d in cve_data.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value")
                        break
                        
                published = cve_data.get("published")
                
                # Extract CVSS v3 score if available
                cvss = 0.0
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
                    
                session.execute_write(_create_cve, cve_id, desc, published, cvss)
                
        logger.info(f"Ingested {len(cves)} CVEs into Neo4j")

    def close(self):
        if self.driver:
            self.driver.close()

if __name__ == "__main__":
    engine = NVDSyncEngine()
    data = engine.fetch_recent_cves(days_back=1)
    if data:
        engine.ingest_to_neo4j(data)
    engine.close()
