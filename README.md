# ManagedAvailabilityTroubleshooter
Exchange 2013/2016 has a Monitoring system called Managed Availability which detects and recovers automatically from problems as they occur and as they are discovered.
The large majority of bluescreen and process recycle you can encounter on Exchange server are triggered by this module in order to restore the service as quick as possible by forcing a restart.

Managed Availability Troubleshooter script can help troubleshoot issues related to this module.

This tool helps troubleshoot these scenarios :
——————————————————————————————————————————————
– Bluescreen / Force reboot
Here is the information you will see if you capture a memory.dmp during a crash triggered by Managed Availability:
The crash will be a stop F4 or EF on wininit.
kd> !analyze –v
…
MODULE_NAME: wininit
PROCESS_NAME:  msexchangerepl
BUGCHECK_STR:  0xEF_msexchangerepl
DEFAULT_BUCKET_ID:  WIN8_DRIVER_FAULT
– Service & application pool restart , components disabled , and all possible recovery actions triggered by Managed Availability
– SCOM alerts reporting Managed Availability failures
– Unhealthy monitor
– Collect all related logs and analyze offline

ManagedAvailabilityTroubleshooter script allows to :
————————————————————————————————————————————————————
– Automatically identify related responder , monitor & probe for these different scenarios and dump their properties
– Easily visualize the related events with detailed fields
– Provide the PowerShell command to disable the recovery action as a workaround if needed while troubleshooting
– Provide automatic resolution recommendation if you are looking at a probe which has known issue
– provided PowerShell command used with verbose switch. Most properties can’t be seen by opening related eventlog and require to run PowerShell commands to see related attributes.

Further info on this blog :
https://blogs.technet.microsoft.com/jcoiffin/2015/10/21/troubleshoot-exchange-20132016-managed-availability/
