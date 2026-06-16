"""
VTService - VirusTotal API Integration

This script provides a Python interface to interact with the VirusTotal API. It allows users to:
- Rescan a file based on its hash.
- Retrieve a VirusTotal report for a specific file hash.
- Handle API request retries in case of failure.
- Extract antivirus engine detection results.

Author: [Your Name]
"""

import requests
import time

class VTService:
    """A service class to interact with the VirusTotal API for malware scanning and reporting."""

    def rescan_virus(self, resource, api_key):
        """
        Request VirusTotal to rescan a file based on its hash.

        Parameters:
        - resource (str): The file hash to be rescanned.
        - api_key (str): The API key for authentication.

        Returns:
        - dict: JSON response from VirusTotal API containing the rescan status.
        """
        params = {'apikey': api_key, 'input': resource}

        response = requests.post('https://www.virustotal.com/vtapi/v3/file/rescan', params=params)
        json_response = response.json()
        print(json_response)
        return json_response

    def report_virus(self, resource, api_key):
        """
        Retrieve a VirusTotal report for a given file hash.

        Parameters:
        - resource (str): The file hash to check.
        - api_key (str): The API key for authentication.

        Returns:
        - dict: JSON response from VirusTotal API containing scan results.
        """
        params = {'apikey': api_key, 'resource': resource}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip, My Python requests library example client or username"
        }
        response = requests.get('https://www.virustotal.com/vtapi/v3/file/report', params=params, headers=headers)
        json_response = response.json()
        return json_response

    def ask_to_virus_total_service(self, resource, api_key):
        """
        Recursively attempt to fetch a VirusTotal report, handling API failures gracefully.

        Parameters:
        - resource (str): The file hash to query.
        - api_key (str): The API key for authentication.

        Returns:
        - dict: JSON response from VirusTotal API containing scan results.
        """
        try:
            return self.report_virus(resource, api_key)
        except Exception as e:
            print(f"ask_to_virus_total_service... {str(e)}")
            time.sleep(3)
            return self.ask_to_virus_total_service(resource, api_key)

    def fetch_engine_values(self, resource, api_key):
        """
        Extract antivirus engine detection results from a VirusTotal report.

        Parameters:
        - resource (str): The file hash to query.
        - api_key (str): The API key for authentication.

        Returns:
        - str: A formatted string containing detection results from multiple antivirus engines.
        """
        result_str = resource + ":"
        response = self.ask_to_virus_total_service(resource, api_key)
        scans = response.get("scans", {})  # Default to an empty dictionary if scans are missing

        for engine, engine_info in scans.items():
            if engine_info.get("detected") is True:
                tmp_str = str(engine_info.get("result"))
                result_str += f"{engine}_{tmp_str},"

        return result_str