#Automated-System-Vulnerabilities-Report-Creation

This tool automates the process of generation vulnerabilities report.

There are several requirements that need to be taking into account before using this tool:

-Install "cve-search" and its requirements: https://github.com/cve-search/cve-search
-Provide the path to "cve-search" in "searchCVE.py" module:
  Change line #18 to the correct path for the "db_updater.py" module of cve-search.
  Change line #50 to the correct path for the "search.py" module of cve-search.
  
