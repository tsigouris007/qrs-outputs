#!/usr/bin/env python3
"""
CWE Lookup Module

This module provides functionality to download, parse, and query the CWE database
from MITRE's official XML source.
"""

import requests
import zipfile
import io
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Optional, Any
import json


class MitreHelper:
  """
  A class to download and query the Common Weakness Enumeration (CWE) database.
  """

  CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
  CACHE_FILE = "cwec_latest.json"

  def __init__(self, use_cache: bool = True):
    """
    Initialize the CWE lookup tool.
    
    Args:
        use_cache: If True, use cached data if available. Otherwise, download fresh data.
    """
    self.use_cache = use_cache
    self.cwe_data = {}
    self.NS = {'cwe': 'http://cwe.mitre.org/cwe-7'} # XML namespace used in CWE files
    self._load_data()

  def _download_and_parse(self) -> Dict[str, Dict[str, Any]]:
    """
    Download and parse the CWE XML file from MITRE.
    """
    print("[*] Downloading CWE database from MITRE.")
    response = requests.get(self.CWE_URL, timeout=30)
    response.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
      # Get the first XML file from the zip
      xml_filename = [name for name in zf.namelist() if name.endswith('.xml')][0]
      with zf.open(xml_filename) as xml_file:
        tree = ET.parse(xml_file)
        root = tree.getroot()

    return self._parse_cwe_xml(root)
  
  def _parse_cwe_xml(self, root: ET.Element) -> Dict[str, Dict[str, Any]]:
    """
    Parse the CWE XML structure and extract relevant information.
    """
    cwe_dict = {}

    # Parse Weaknesses
    weaknesses = root.find('cwe:Weaknesses', self.NS)
    if weaknesses is not None:
      for weakness in weaknesses.findall('cwe:Weakness', self.NS):
        cwe_id = weakness.get('ID')
        cwe_info = self._extract_weakness_info(weakness)
        cwe_dict[cwe_id] = cwe_info

    # Parse Categories
    categories = root.find('cwe:Categories', self.NS)
    if categories is not None:
      for category in categories.findall('cwe:Category', self.NS):
        cwe_id = category.get('ID')
        cwe_info = self._extract_category_info(category)
        cwe_dict[cwe_id] = cwe_info

    # Parse Views
    views = root.find('cwe:Views', self.NS)
    if views is not None:
      for view in views.findall('cwe:View', self.NS):
        cwe_id = view.get('ID')
        cwe_info = self._extract_view_info(view)
        cwe_dict[cwe_id] = cwe_info

    return cwe_dict

  def _extract_weakness_info(self, weakness: ET.Element) -> Dict[str, Any]:
    """Extract information from a Weakness element."""
    info = {
      'id': weakness.get('ID'),
      'name': weakness.get('Name'),
      'abstraction': weakness.get('Abstraction'),
      'structure': weakness.get('Structure'),
      'status': weakness.get('Status'),
      'type': 'Weakness'
    }

    # Description
    desc_elem = weakness.find('cwe:Description', self.NS)
    if desc_elem is not None:
      info['description'] = self._get_element_text(desc_elem)

    # Extended Description
    ext_desc = weakness.find('cwe:Extended_Description', self.NS)
    if ext_desc is not None:
      info['extended_description'] = self._get_element_text(ext_desc)

    # Likelihood of Exploit
    likelihood = weakness.find('cwe:Likelihood_Of_Exploit', self.NS)
    if likelihood is not None:
      info['likelihood_of_exploit'] = likelihood.text.lower()

    # Common Consequences
    consequences = weakness.find('cwe:Common_Consequences', self.NS)
    if consequences is not None:
      info['consequences'] = []
      for consequence in consequences.findall('cwe:Consequence', self.NS):
        scope = consequence.find('cwe:Scope', self.NS)
        impact = consequence.find('cwe:Impact', self.NS)
        if scope is not None and impact is not None:
          info['consequences'].append({
            'scope': scope.text,
            'impact': impact.text
          })

    # Related Weaknesses
    related = weakness.find('cwe:Related_Weaknesses', self.NS)
    if related is not None:
      info['related_weaknesses'] = []
      for relation in related.findall('cwe:Related_Weakness', self.NS):
        info['related_weaknesses'].append({
          'nature': relation.get('Nature'),
          'cwe_id': relation.get('CWE_ID'),
          'view_id': relation.get('View_ID')
        })

    # Modes of Introduction
    modes = weakness.find('cwe:Modes_Of_Introduction', self.NS)
    if modes is not None:
      info['modes_of_introduction'] = []
      for mode in modes.findall('cwe:Introduction', self.NS):
        phase = mode.find('cwe:Phase', self.NS)
        if phase is not None:
          info['modes_of_introduction'].append(phase.text)

    # Observed Examples (can indicate rarity/frequency)
    examples = weakness.find('cwe:Observed_Examples', self.NS)
    if examples is not None:
      observed = examples.findall('cwe:Observed_Example', self.NS)
      info['observed_examples_count'] = len(observed)
    else:
      info['observed_examples_count'] = 0

    # Applicable Platforms (CRITICAL for prevalence!)
    platforms = weakness.find('cwe:Applicable_Platforms', self.NS)
    if platforms is not None:
      info['applicable_platforms'] = []

      # Extract language-specific prevalence
      for lang in platforms.findall('cwe:Language', self.NS):
        lang_info = {
          'type': 'Language',
          'name': lang.get('Name'),
          'prevalence': lang.get('Prevalence', 'Undetermined').lower()
        }
        info['applicable_platforms'].append(lang_info)

      # Extract technology-specific prevalence
      for tech in platforms.findall('cwe:Technology', self.NS):
        tech_info = {
          'type': 'Technology',
          'name': tech.get('Name'),
          'class': tech.get('Class'),
          'prevalence': tech.get('Prevalence', 'Undetermined').lower()
        }
        info['applicable_platforms'].append(tech_info)

    return info

  def _extract_category_info(self, category: ET.Element) -> Dict[str, Any]:
    """Extract information from a Category element."""
    info = {
      'id': category.get('ID'),
      'name': category.get('Name'),
      'status': category.get('Status'),
      'type': 'Category'
    }

    summary = category.find('cwe:Summary', self.NS)
    if summary is not None:
      info['summary'] = self._get_element_text(summary)

    return info
  
  def _extract_view_info(self, view: ET.Element) -> Dict[str, Any]:
    """Extract information from a View element."""
    info = {
      'id': view.get('ID'),
      'name': view.get('Name'),
      'type': view.get('Type'),
      'status': view.get('Status'),
      'type': 'View'
    }

    objective = view.find('cwe:Objective', self.NS)
    if objective is not None:
        info['objective'] = self._get_element_text(objective)

    return info

  def _get_element_text(self, element: ET.Element) -> str:
    """
    Extract all text content from an element, including nested elements.
    """
    return ''.join(element.itertext()).strip()

  def _load_data(self):
    """Load CWE data from cache or download if necessary."""
    cache_path = Path(self.CACHE_FILE)

    if self.use_cache and cache_path.exists():
      print(f"[*] Loading CWE data from MITRE database local cache ({self.CACHE_FILE}).")
      with open(cache_path, 'r', encoding='utf-8') as f:
        self.cwe_data = json.load(f)
      print(f"[*] Loaded {len(self.cwe_data)} CWE entries from cache.")
    else:
      self.cwe_data = self._download_and_parse()
      # Save to cache
      print(f"[*] Saving to cache ({self.CACHE_FILE})...")
      with open(self.CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(self.cwe_data, f, indent=2)
      print(f"[*] Cached {len(self.cwe_data)} CWE entries.")

  def get_cwe_info(self, cwe_id: str) -> Optional[Dict[str, Any]]:
    return self.cwe_data.get(cwe_id)

  def search_by_name(self, search_term: str) -> list:
    results = []
    search_term_lower = search_term.lower()

    for cwe_id, cwe_info in self.cwe_data.items():
      name = cwe_info.get('name', '')
      if search_term_lower in name.lower():
        results.append({
          'id': cwe_id,
          'name': name,
          'type': cwe_info.get('type', 'Unknown')
        })

    return results


def main():
  import argparse
  parser = argparse.ArgumentParser(description="MITRE CWE Lookup Tool")
  parser.add_argument("--cwe", required=True, type=int, help="The CWE ID to lookup. Only use the numeric part, e.g., '79' for CWE-79.")
  parser.add_argument("--no-cache", action='store_true', default=False, help="Do not use cached data.")
  args = parser.parse_args()

  lookup = MitreHelper(use_cache=not args.no_cache)

  cwe = lookup.get_cwe_info(str(args.cwe))
  print(json.dumps(cwe, indent=2))


if __name__ == "__main__":
  main()
