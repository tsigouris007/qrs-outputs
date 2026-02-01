#!/usr/bin/env python3
"""
CVE Database Search Module
Provides CVE database lookups.
"""
import requests
import time
from typing import Dict, List, Optional, Any


class CVESearcher:
  """Search NVD CVE database."""

  def __init__(self, api_key: Optional[str] = None):
    """
    Initialize CVE searcher.

    Args:
      api_key: Optional NVD API key for higher rate limits
    """
    self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    self.api_key = api_key
    # Rate limiting: 1s with API key, 10s without
    self.rate_limit_delay = 1 if api_key else 10.0
    self.last_request_time = 0

  def _rate_limit(self):
    """Enforce NVD API rate limits."""
    elapsed = time.time() - self.last_request_time
    if elapsed < self.rate_limit_delay:
      time.sleep(self.rate_limit_delay - elapsed)
    self.last_request_time = time.time()

  def _make_request(self, params: Dict[str, Any]) -> Dict:
    """Make API request."""
    self._rate_limit()

    headers = {}
    if self.api_key:
      headers["apiKey"] = self.api_key

    try:
      response = requests.get(
        self.base_url,
        params=params,
        headers=headers,
        timeout=30
      )
      response.raise_for_status()
      return response.json()
    except requests.exceptions.RequestException as e:
      return {"error": str(e), "success": False}

  def _extract_cve_data(self, vuln_data: Dict) -> Dict:
    """Extract CVE data from object."""
    cve_data = vuln_data.get("cve", {})

    # Extract CWE IDs
    cwe_ids = []
    for weakness in cve_data.get("weaknesses", []):
      for desc in weakness.get("description", []):
        cwe_value = desc.get("value", "")
        if cwe_value.startswith("CWE-"):
          cwe_ids.append(cwe_value.lower())

    # Extract severity
    severity = "unknown"
    cvss_score = None
    metrics = cve_data.get("metrics", {})
    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
      cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
      severity = cvss_data.get("baseSeverity", "unknown").lower()
      cvss_score = cvss_data.get("baseScore")
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
      severity = metrics["cvssMetricV2"][0].get("baseSeverity", "unknown").lower()
      cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

    return {
      "cve_id": cve_data.get("id"),
      "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
      "severity": severity,
      "cvss_score": cvss_score,
      "published": cve_data.get("published", ""),
      "last_modified": cve_data.get("lastModified", ""),
      "cwe_ids": cwe_ids
    }

  def search(
    self,
    package_name: str,
    version: Optional[str] = None,
    cwe_ids: Optional[List[str]] = None,
    limit: int = 20
  ) -> Dict:
    """
    Search for CVEs with flexible parameters.

    Args:
      package_name: Package name (e.g., "pyyaml")
      version: Optional specific version (e.g., "6.0.3")
      cwe_ids: Optional list of CWE IDs to filter by (e.g., ["cwe-502", "cwe-22"])
      limit: Maximum results to return (default 20)

    Returns:
      {
        "query": {
          "package": str,
          "version": str or None,
          "cwe_ids": [str] or None
        },
        "total_results": int,
        "cves": [
          {
            "cve_id": str,
            "description": str,
            "severity": str,
            "cvss_score": float or None,
            "published": str,
            "last_modified": str,
            "cwe_ids": [str]
          }
        ]
      }
    """
    # Build keyword search with package and optional version
    keyword = package_name.lower()
    if version:
      keyword = f"{keyword} {version}"

    params = {
      "keywordSearch": keyword,
      "resultsPerPage": limit
    }

    data = self._make_request(params)

    if "error" in data:
      return data

    # Extract and optionally filter CVEs
    all_cves = []
    for vuln in data.get("vulnerabilities", []):
      cve_info = self._extract_cve_data(vuln)

      # Filter by CWE if specified
      if cwe_ids:
        cwe_ids_normalized = [c.lower().replace("cwe-", "") for c in cwe_ids]
        cve_cwes_normalized = [c.replace("cwe-", "") for c in cve_info["cwe_ids"]]

        # Only include if at least one CWE matches
        if any(cwe in cve_cwes_normalized for cwe in cwe_ids_normalized):
          all_cves.append(cve_info)
      else:
        all_cves.append(cve_info)

    return {
      "query": {
        "package": package_name,
        "version": version,
        "cwe_ids": cwe_ids
      },
      "total_results": len(all_cves),
      "cves": all_cves[:limit]
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
      description="Search NVD CVE database for package vulnerabilities",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog="""
Examples:
  # Search by package only
  python3 cve_searcher.py --package pyyaml
  
  # Search by package and version
  python3 cve_searcher.py --package pyyaml --version 6.0.3
  
  # Search by package and CWE
  python3 cve_searcher.py --package pyyaml --cwe cwe-502
  
  # Search by package, version, and multiple CWEs
  python3 cve_searcher.py --package pyyaml --version 6.0.3 --cwe cwe-502 cwe-22
        """
    )

    parser.add_argument("--package", required=True, help="Package name (e.g., pyyaml)")
    parser.add_argument("--version", help="Package version (e.g., 6.0.3)")
    parser.add_argument("--cwe", nargs="+", help="One or more CWE IDs (e.g., cwe-502 cwe-22)")
    parser.add_argument("--limit", type=int, default=20, help="Maximum number of results (default: 20)")
    parser.add_argument("--api-key", help="NVD API key for higher rate limits")

    args = parser.parse_args()

    searcher = CVESearcher(api_key=args.api_key)
    result = searcher.search(
      package_name=args.package,
      version=args.version,
      cwe_ids=args.cwe,
      limit=args.limit
    )

    print(json.dumps(result, indent=2))
