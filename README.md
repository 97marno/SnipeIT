# SnipeIT
Scripts for Azure Runbooks to update Intune, ABM and Knox devices

# Usage

## snipeit-update-all.models.ps1
This check the models against Intune, Autopilot and Apple Business Manager (ABM). 
If the models or Manufactruers are missing in Snipe IT, it will add them. 

*This script need to be present as a runbook for the other scripts to work, since they are calling this script.* 
