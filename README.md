# SnipeIT
Scripts for Azure Runbooks to update Intune, ABM and Knox devices

# Usage
+ snipeit-update-all.models.ps1 - *This script need to be present as a runbook for the other scripts to work, since they are calling this script.* 


## snipeit-update-all.models.ps1
This check the models against Intune, Autopilot and Apple Business Manager (ABM). 
If the models or Manufactruers are missing in Snipe IT, it will add them. 

## snipeit-abm-add-devices.ps1
This runbook will add all apple devices in SnipeIT. 
The script has an dependency on the *snipeit-update-all-models* so make sure that you add that as a runbook. 
This script is also dependent of certain CustomFieldNames, so read through the instructions in the script. 

