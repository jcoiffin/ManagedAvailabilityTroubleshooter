# Managed Availability Troubleshooter
# The goal of this script is to more easily investigate issues related of Managed Availability including ForceReboot/Recovery Actions triggered by Exchange 2013
# Written by Jérôme Coiffin
#  Provide your feedback to jcoiffin@microsoft.com

[cmdletbinding()]
Param([string]$pathforlogs,[switch]$Collect , [switch] $AllServers , [switch] $OnlyThisServer , [switch]$Help)

$Script:lastProbeerror = $null
$Script:foundissue = $false
$Script:checkforknownissue =$false
$Script:KnownIssueDetectionAlreadydone = $false
$Script:LoggingMonitoringpath = ""

function TestFileorCmd
{
[cmdletbinding()]
Param( [String] $FileorCmd )

	if ($FileorCmd -like "File missing for this action*")
	{
		Write-Host -foregroundcolor red $FileorCmd;
		exit;
	}
}

function ParseProbeResult
{
[cmdletbinding()]
Param( [String] $FilterXpath , [String] $MonitorToInvestigate , [String] $ResponderToInvestigate)

	TestFileorCmd $ProbeResulteventcmd;
	ParseProbeResult2 ($ProbeResulteventcmd + " -maxevents 200" ) $FilterXpath "Parsing only last 200 probe events for quicker response time" $MonitorToInvestigate $ResponderToInvestigate
	if ("yes","YES","Y","y" -contains (Read-Host ("`nParsed last 200 probe events for quicker response.`nDo you like to parse all probe events ? Y/N (default is ""N"")")))
	{ ParseProbeResult2 $ProbeResulteventcmd $FilterXpath "Parsing all probe events. this may be slow as there is lots of events" $MonitorToInvestigate $ResponderToInvestigate}
}

function ParseProbeResult2
{
[cmdletbinding()]
Param( [String] $ProbeResulteventcompletecmd , [String] $FilterXpath , [String] $waitstring , [String] $MonitorToInvestigate , [String] $ResponderToInvestigate)

	TestFileorCmd $ProbeResulteventcmd;
	$Probeeventscmd = '(' + $ProbeResulteventcompletecmd + ' -FilterXPath ("' + $FilterXpath +'") -ErrorAction SilentlyContinue | % {[XML]$_.toXml()}).event.userData.eventXml'	
	Write-verbose $Probeeventscmd
	$titleprobeevents = "Probe events"
	if ( $ProbeDetailsfullname )
	{	$titleprobeevents = $ProbeDetailsfullname + " events" }	
	if ($waitstring)
	{
		write-progress "Checking Probe Result Events" -status $waitstring
	}
	else
	{
		write-progress "Checking Probe Result Events"
	}
	$checkerrorcount = $error.count
	$Probeevents = invoke-expression $Probeeventscmd
	write-progress "Checking Probe Result Events" -completed
	$checkerrorcount = $error.count - $checkerrorcount
	if ($checkerrorcount -gt 0)
	{
		for ($j=0;$j -lt $checkerrorcount;$j++)
		{
			if ($error[$j].FullyQualifiedErrorId -like "NoMatchingEventsFound*")
			{ write-host -foreground red "No events were found"}
			else
			{ write-host -foreground red $error[$j].exception.message}
		}
	}
	if ($Probeevents)
	{
		foreach ($Probeevt in $Probeevents)
		{
		    If ($Probeevt.ResultType -eq 4)
		    {
			$Script:lastProbeerror = $Probeevt
			if ($Script:KnownIssueDetectionAlreadydone -eq $false) {KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate}
			Break;
		    }
		}
		if ($Script:KnownIssueDetectionAlreadydone -eq $false) {KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate}
		$Probeevents | Select-Object -Property @{n="ExecutionStartTime (GMT)";e={$_.ExecutionStartTime}},@{n="ExecutionEndTime (GMT)";e={$_.ExecutionEndTime}},@{n='ResultType';e={$_.ResultType -replace "1","Timeout"-replace "2","Poisoned" -replace "3","Succeeded" -replace "4","Failed" -replace "5","Quarantined" -replace "6","Rejected"}},@{n='Error';e={$_.Error -replace "`r`n","`r"}},@{n='Exception';e={$_.Exception -replace "`r`n","`r"}},FailureContext,@{n='ExecutionContext';e={$_.ExecutionContext -replace "`r`n","`r"}},RetryCount,ServiceName,ResultName,StateAttribute*| Out-GridView -title $titleprobeevents
	}
	if ($Script:KnownIssueDetectionAlreadydone -eq $false) {KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate}
}


function InvestigateProbe
{
[cmdletbinding()]
Param([String]$ProbeToInvestigate , [String]$MonitorToInvestigate , [String]$ResponderToInvestigate , [String]$ResourceNameToInvestigate , [String]$ResponderTargetResource )

	TestFileorCmd $ProbeDefinitioneventcmd;
    if (-Not ($ResponderTargetResource) -and ($ProbeToInvestigate.split("/").Count -gt 1))
    {
        $ResponderTargetResource = $ProbeToInvestigate.split("/")[1]
    }
	$ProbeDetailscmd = '(' + $ProbeDefinitioneventcmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -like "' + $ProbeToInvestigate.split("/")[0] + '*" }'
	Write-verbose $ProbeDetailscmd
	write-progress "Checking Probe definition"
	$ProbeDetails = invoke-expression $ProbeDetailscmd
	write-progress "Checking Probe definition" -completed
	if ( $ProbeDetails)
	{
		if ($ProbeDetails.Count -gt 1)
		{
			if ($ResourceNameToInvestigate)
			{
				$ProbeDetailsforselectedResourceName = $ProbeDetails | Where-Object {$_.TargetResource -eq $ResourceNameToInvestigate}
				if ($ProbeDetailsforselectedResourceName )
				{   $ProbeDetails = $ProbeDetailsforselectedResourceName }
			}
			if ($ProbeDetails.Count -gt 1)
			{
				if ($ResponderTargetResource)
				{
					$ProbeDetailsforselectedResourceName = $ProbeDetails | Where-Object {$_.TargetResource -eq $ResponderTargetResource}
					if ($ProbeDetailsforselectedResourceName )
					{   $ProbeDetails = $ProbeDetailsforselectedResourceName }
				}

				if ($ProbeDetails.Count -gt 1)
				{
					Write-Host -foregroundcolor red ("Found no probe for " + $ResourceNameToInvestigate + " TargetResource")
					Write-Host "`nSelected all possible Probes in this list: "
					if ($ProbeDetails.Count -gt 20)
					{
						Write-host -foregroundcolor red ("more than 30 Probes in the list. Keeping only the 30 first probes")
						$ProbeDetails = $ProbeDetails[0..19]
					}
				}
			}
		}
		$ProbeDetails | Format-List *
		$ProbeDetailsfullname = $null								
		foreach ($ProbeInfo in $ProbeDetails)
		{
			$probename2add = $ProbeInfo.Name
			if ($ProbeInfo.TargetResource)
			{
				if ( -not ($ProbeInfo.TargetResource -eq "[null]"))
				{ $probename2add += "/" + $ProbeInfo.TargetResource}
			}
			if ($ProbeDetailsfullname -eq $null )
			{$ProbeDetailsfullname = $Probename = $probename2add }
			else
			{
				$ProbeNameAlreadyinthelist = $false
				foreach ( $PresentProbeName in ($Probename -replace " and ",";").split(";"))
				{
					if ($PresentProbeName -eq $probename2add)
					{$ProbeNameAlreadyinthelist = $true}
				}
				if ($ProbeNameAlreadyinthelist -eq $false)
				{
					$ProbeDetailsfullname += "' or ResultName='" + $probename2add
					$Probename += " and " + $probename2add
				}
			}
		}
							
		if ($MonitorToInvestigate)
		{
			$relationdescription = "`n" + $Probename +" errors can result in the failure of " + $MonitorToInvestigate + " monitor"
			if ( $ResponderToInvestigate)
			{
				$relationdescription +=	" which triggered " + $ResponderToInvestigate
			}
			Write-host $relationdescription
		}
		If ( $Probename -eq "EacBackEndLogonProbe")
		{
			if ($Script:KnownIssueDetectionAlreadydone -eq $false) {KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate}
			
			$EacBackEndLogonProbefolder = $Script:LoggingMonitoringpath +"\ECP\EacBackEndLogonProbe"
			if ( Test-Path $EacBackEndLogonProbefolder)
			{
				$EacBackEndLogonProbefile = Get-ChildItem ($EacBackEndLogonProbefolder) | Select-Object -last 1
				if ($EacBackEndLogonProbefile)
				{
					write-host "found and opening EacBackEndLogonProbe log / check the file for further error details"
					notepad $EacBackEndLogonProbefile.fullname
				}
			}
			else
			{ write-host -foregroundcolor red ("Missing logs from path $EacBackEndLogonProbefolder ")}
		}
		else
		{
			ParseProbeResult ("*[UserData[EventXML[ResultName='" + $ProbeDetailsfullname + "']]]") $MonitorToInvestigate $ResponderToInvestigate
		}
	}
	else
	{   write-host("`nFound no definitions for " + $ProbeToInvestigate + " probe") }
}

Function InvestigateMonitor
{
[cmdletbinding()]
Param( [String]$MonitorToInvestigate ,[String]$ResourceNameToInvestigate , [String]$ResponderTargetResource , [String] $ResponderToInvestigate)

	if($MonitorToInvestigate -like "MaintenanceFailureMonitor*")
	{
		$MaintenanceFailureMonitor = $MonitorToInvestigate.split(".")[1]
		Write-host ("`nThis is triggered by MaintenanceFailureMonitor " + $MaintenanceFailureMonitor)
		InvestigateMaintenanceMonitor $MaintenanceFailureMonitor $ResponderToInvestigate
		break;
	}
	
	TestFileorCmd $MonitorDefinitioncmd;
	$MonitorDetailscmd = '(' + $MonitorDefinitioncmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -like "' + $MonitorToInvestigate.split("/")[0] + '*" }'
	Write-verbose $MonitorDetailscmd
	write-progress "Checking Monitor definition"
	$MonitorDetails = invoke-expression $MonitorDetailscmd | Select-Object -uniq
	write-progress "Checking Monitor definition" -completed
	if ($MonitorDetails.Count -gt 1)
	{
		if ( $ResourceNameToInvestigate )
		{
			$MonitorDetailsforselectedResourceName = $MonitorDetails | Where-Object {$_.TargetResource -eq $ResourceNameToInvestigate }
			if ($MonitorDetailsforselectedResourceName)
			{ $MonitorDetails = $MonitorDetailsforselectedResourceName }
		}
		if ($MonitorDetails.Count -gt 1)
		{
			if ($ResponderTargetResource)
			{
				$MonitorDetailsforselectedResourceName = $MonitorDetails | Where-Object {$_.TargetResource -eq $ResponderTargetResource }
				if ($MonitorDetailsforselectedResourceName)
				{ $MonitorDetails = $MonitorDetailsforselectedResourceName }
			}
			if ($MonitorDetails.Count -gt 1)
			{
				Write-Host -foregroundcolor yellow ("Found multiple monitors , select the Monitor you like to investigate")			
				$MonitorDetailsChosen = $MonitorDetails | Select-Object -Property name,TargetResource,SampleMask | Group-Object SampleMask
				$NumberofGroupsofSampleMask = 0;$MonitorDetailsChosen |Foreach-Object{$NumberofGroupsofSampleMask ++};$NumberofGroupsofSampleMask
				if ($NumberofGroupsofSampleMask -gt 1)
				{
					Write-Host "`nMutiple Monitor, Select the Monitor you like to investigate"
					$MonitorDetailsChosen | Out-GridView -PassThru -title "Mutiple Monitor, Select the Monitor you like to investigate"			
				}			
				else
				{ Write-Host -foregroundcolor yellow ("All Monitors have same SampleMask , thus using one of them to check related probe")}
				if ($MonitorDetailsChosen)
				{
					$MonitorDetails = $MonitorDetails | Where-Object {$_.SampleMask -eq $MonitorDetailsChosen.Name} |sort-object -unique					
				}
			}

			if ($MonitorDetails.Count -gt 1)
			{
				Write-Host -foregroundcolor red ("Found no matching Monitor")
				exit
			}
		}
	}
	$MonitorDetails |Format-List *
	$ProbeToInvestigate = $MonitorDetails.SampleMask | Select-Object -uniq

	if ($ProbeToInvestigate)
	{
		if ($ProbeToInvestigate.Count -gt 1)
		{
			Write-host ("`nMultiple probes linked with the monitor " + $MonitorToInvestigate + " , here is the list : " + $ProbeToInvestigate)
			foreach ($individualProbetoInvestigate in $ProbeToInvestigate)
			{InvestigateProbe $individualProbetoInvestigate $MonitorToInvestigate $ResponderToInvestigate $ResourceNameToInvestigate $ResponderTargetResource}
		}
		else
		{
			Write-host ("`nThe probe triggering " + $MonitorToInvestigate + " monitor is " + $ProbeToInvestigate)
			InvestigateProbe $ProbeToInvestigate $MonitorToInvestigate $ResponderToInvestigate $ResourceNameToInvestigate $ResponderTargetResource
		}
	}						
	else
	{   Write-host ("`nFound no probe triggering " + $MonitorToInvestigate ) }
}

function InvestigateMaintenanceMonitor
{
[cmdletbinding()]
Param([String]$MaintenanceFailureMonitor , [String] $ResponderToInvestigate)

	TestFileorCmd $MaintenanceDefinitioncmd;
	$MaintenanceDefinitioncmd= '(' + $MaintenanceDefinitioncmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.ServiceName -like "' + $MaintenanceFailureMonitor + '*" }'
	Write-verbose $MaintenanceDefinitioncmd
	write-progress "Checking Maintenance definition"
	$MaintenanceDetails = invoke-expression $MaintenanceDefinitioncmd
	write-progress "Checking Maintenance definition" -completed
	if ( $MaintenanceDetails)
	{
		$MaintenanceDetailsGroups = $MaintenanceDetails |Group-Object Name
		$NumberofGroupsofServiceName = 0;$MaintenanceDetailsGroups |Foreach-Object{$NumberofGroupsofServiceName ++}
		if ($NumberofGroupsofServiceName -gt 1)
		{
			Write-Host "`nSelect the Maintenance you like to investigate"
			$MaintenanceDetailsGroups | Out-GridView -PassThru -title "Mutiple Monitor, Select the Monitor you like to investigate"			
		}			
		
		$MaintenanceDetails = $MaintenanceDetails | Where-Object {$_.Name -eq $MaintenanceDetailsGroups.Name} |sort-object -unique
		
		$MaintenanceDetails |Format-List
		
		TestFileorCmd $MaintenanceResultcmd;
		$MaintenanceResultcmd = '(' + $MaintenanceResultcmd + ' -FilterXPath "*/System/Level<=3" | % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.ResultName -like "' + $MaintenanceDetails.Name + '*" }'
		Write-verbose $MaintenanceResultcmd
		write-progress "Checking Maintenance Result warnings and errors"
		$MaintenanceResults = invoke-expression $MaintenanceResultcmd
		write-progress "Checking Maintenance Result warnings and errors"
		$Script:lastProbeerror = $MaintenanceResults[0]
		if ($Script:KnownIssueDetectionAlreadydone -eq $false) {KnownIssueDetection $MonitorToInvestigate $ResponderToInvestigate}
		$MaintenanceResults |out-gridview -title "Maintenance warnings and alerts"	
	}
}

Function OverrideIfNeeded
{
[cmdletbinding()]
Param( [String]$ResponderToInvestigate , [String]$ResponderServiceName)
	if ( -not ( $ResponderServiceName))
	{
		write-host -foreground red ("`nFound no ServiceName for " + $ResponderToInvestigate + " Responder. Thus can't provide the override command to disable this responder if needed.")
		return
	}

	Write-host ("`nThe Responder that triggered the RecoveryAction you selected is " + $ResponderToInvestigate + " .")
	Write-host ("This action was taken to restore the service as soon as possible to end users.")
	Write-host ("In case this recovery action happens too often or does not help , you may like to temporarily disable this failover response while you investigate.")

	$ResponderwithServiceName = $ResponderServiceName + "`\" + $ResponderToInvestigate
	$AddGlobalMonitoringOverridecmd = "Add-GlobalMonitoringOverride -Identity $ResponderwithServiceName  -ItemType Responder -PropertyName Enabled -PropertyValue 0"
	$RemoveGlobalMonitoringOverridecmd = "Remove-GlobalMonitoringOverride -Identity $ResponderwithServiceName  -ItemType Responder -PropertyName Enabled"
	if ( $pathforlogsspecified )
	{
		write-host ("If you like to disable " + $ResponderToInvestigate + " Responder , run this command in Exchange Powershell")
		write-host -foreground yellow $AddGlobalMonitoringOverridecmd
		write-host -foreground yellow ("`nTo remove the override afterwards to enable " + $ResponderToInvestigate + " Responder again ,use the command:")
		Write-host -foreground yellow $RemoveGlobalMonitoringOverridecmd
	}
	else
	{
		if ("yes","YES","Y","y" -contains (Read-Host ("Do you like to disable " + $ResponderToInvestigate + " Responder ? Y/N")))
		{
			write-host ("`nHere is the command used to disable " + $ResponderToInvestigate + " Responder :")
			write-host -foreground yellow $AddGlobalMonitoringOverridecmd
			invoke-expression $AddGlobalMonitoringOverridecmd
			Write-host ("It may take some time to apply the change to disable " + $ResponderToInvestigate + " Responder.")
			$continuetocheckifresponderisenabled = $true
			while ( $continuetocheckifresponderisenabled)
			{
				if ("yes","YES","Y","y" -contains (Read-Host ("Do you like to check if " + $ResponderToInvestigate + " Responder is now disabled ? Y/N")))
				{
					TestFileorCmd $ResponderDefinitioncmd;
					$ResponderDetailscmd = '(' + $ResponderDefinitioncmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -eq "' + $ResponderToInvestigate + '" }'
					Write-verbose $ResponderDetailscmd
					write-progress "Checking Responder definition"
					$ResponderDetails = invoke-expression $ResponderDetailscmd
					write-progress "Checking Responder definition" -completed
					if ($ResponderDetails)
					{
						if ( $ResponderDetails.enabled -eq 1)
						{
							write-host ("`n" + $ResponderToInvestigate + " Responder is currently still enabled.")
							$ResponderDetails | Format-Table ServiceName,Name,Enabled -a
							$MSExchangeHMservice = get-service MSExchangeHM
							if ($MSExchangeHMservice)
							{
								if (($MSExchangeHMservice).Status -eq "Stopped")
								{
									Write-host ("`nThe Microsoft Exchange Health Manager service is stopped.")
									Write-host ("As a result , all Exchange monitoring is currently disabled.")
									Write-host ("The status of this responder will be calculated as disabled next time you start the Microsoft Exchange Health Manager service.")
								}
								else
								{
									Write-host ("It may take some time to apply the change to disable " + $ResponderToInvestigate + " Responder.")
									Write-host ("You may wait a few minutes and check again.")
								}
							}
							else
							{   write-host ("`nCan't check the status of MSExchangeHM/Microsoft Exchange Health Manager service. If this service is not started , all Exchange monitoring is disabled.") }
						}
						else
						{
							write-host ("`n" + $ResponderToInvestigate + " Responder is now disabled and similar reboot should not currently be triggered by this responder")
							$ResponderDetails | Format-Table ServiceName,Name,Enabled -a
							Write-host ("When you have fixed the issue triggering this responder, you can reenable it again using this command :")
							write-host ("remove-GlobalMonitoringOverride -Identity " + $ResponderwithServiceName + "  -ItemType Responder -PropertyName Enabled")
							$continuetocheckifresponderisenabled = $false
						}
					}
					else
					{   write-host ("`nFound no events related to " + $ResponderToInvestigate + " Responder. If you have restarted Microsoft Exchange Health Manager service recently , this is probably normal and you have to wait for the service to rediscover the responders") }
				}
				else
				{   $continuetocheckifresponderisenabled = $false }
			}
			write-host -foreground yellow ("`nTo remove the override afterwards to enable " + $ResponderToInvestigate + " Responder again , use this command:")
			write-host -foreground yellow $RemoveGlobalMonitoringOverridecmd
			Read-Host ("Take note of this command to remove the override afterwards, then type enter to continue")
		}
	}
}

Function InvestigateResponder
{
[cmdletbinding()]
Param( [String]$ResponderToInvestigate , [String]$ResourceNameToInvestigate )

	if ($ResponderToInvestigate -eq "ManagedAvailabilityStartup")
	{
		Write-host "`nManagedAvailabilityStartup means HealthManager can't find the information about the Responder which triggered this reboot."
		write-host "`nSuch events can be seen when Exchange Server 2013 was rebooted."
		write-host "`nThis can happen as well when there is a bluscreen not triggered by Managed Availability , for example in case of Hanged I/O : https://technet.microsoft.com/en-us/library/ff625233(v=exchg.141).aspx"
		write-host "`nIn case it is a reboot , there can be related 1074 events in system log showing that a user forced a rebooted around that time."
		write-host "looking for 1074 events ..."

		TestFileorCmd $Systemcmd;
		$Systemcmd = $Systemcmd + ' -FilterXPath ("*[System[(EventID=''1074'')]]")'
		Write-verbose $Systemcmd
		trap [System.Exception] {continue}
		$1074events = invoke-expression $Systemcmd
		if ($1074events.Count -eq 0)
		{ write-host ("Found no 1074 events in system log")}
		else
		{
			write-host ("Found 1074 events in system log :")
		 	$1074events |Format-List
		}
	}
	else
	{
		TestFileorCmd $ResponderDefinitioncmd;
		$ResponderDetailscmd = '(' + $ResponderDefinitioncmd + '| % {[XML]$_.toXml()}).event.userData.eventXml| ? {$_.Name -eq "' + $ResponderToInvestigate + '" }'
		Write-verbose $ResponderDetailscmd
		write-progress "Checking Responder definition"
		$ResponderDetails = invoke-expression $ResponderDetailscmd | Select-Object -uniq
		write-progress "Checking Responder definition" -completed
		if ( $ResponderDetails)
		{
			if ($ResponderDetails.Count -gt 1)
			{
				if ($ResourceNameToInvestigate)
				{
					$ResponderDetailsforselectedResourceName = $ResponderDetails | Where-Object {$_.TargetResource -eq $ResourceNameToInvestigate}
					if ($ResponderDetailsforselectedResourceName)
					{  $ResponderDetails = $ResponderDetailsforselectedResourceName }
					if ($ResponderDetails.Count -gt 1)
					{
						$ResponderDetailsforselectedResourceName = $ResponderDetails | Where-Object {$_.TargetExtension -eq $ResourceNameToInvestigate}
						if ($ResponderDetailsforselectedResourceName)
						{  $ResponderDetails = $ResponderDetailsforselectedResourceName }
					}
				}
				if ($ResponderDetails.Count -gt 1)
				{
					Write-Host -foregroundcolor red ("Found no " + $ResponderToInvestigate + " Responder for " + $ResourceNameToInvestigate + " TargetResource")						
					write-host "Select the responder you like to investigate"
					Start-Sleep -s 1
					$Responderchoosen= $ResponderDetails | Out-GridView -PassThru -title "Select the responder you like to investigate"
					if ($Responderchoosen)
					{
						if ($Responderchoosen.Count -gt 1 )
						{   $ResponderDetails = $Responderchoosen[0] }
						else
						{   $ResponderDetails = $Responderchoosen }
					}
					else
					{
						Write-Host -foregroundcolor red ("No responder selected")
					exit
					}
				}
			}

			if ( $ResponderDetails.enabled -eq 1)
			{
				OverrideIfNeeded $ResponderToInvestigate $ResponderDetails.ServiceName
			}
			else
			{
				write-host ("`n" + $ResponderToInvestigate + " Responder is already disabled and similar reboot should not currently be triggered by this responder.")
				$ResponderDetails | Format-Table ServiceName,Name,Enabled -a
			}
				
			write-host ("`n" + $ResponderToInvestigate + " Responder properties :")
			$ResponderDetails |Format-List *
			$MonitorToInvestigate = $ResponderDetails.AlertMask
			if ($MonitorToInvestigate)
			{
				Write-host ("`nThe monitor triggering " + $ResponderToInvestigate + " Responder is " + $MonitorToInvestigate)
				InvestigateMonitor $MonitorToInvestigate $ResourceNameToInvestigate $ResponderDetails.TargetResource $ResponderToInvestigate				
			}
			else
			{	Write-host ("`nFound no monitor triggering " + $ResponderToInvestigate + "`n" ) }
			if ($Script:KnownIssueDetectionAlreadydone -eq $false) {KnownIssueDetection $null $ResponderToInvestigate}
		}
		else
		{   Write-host ("`nFound no responder properties for the responder " + $ResponderToInvestigate ) }
	}
}


function KnownIssueDetection
{
[cmdletbinding()]
Param( [String]$MonitorToInvestigate ,[String]$ResponderToInvestigate)

	if ($MonitorToInvestigate -or $ResponderToInvestigate)
	{
		write-host "`nKnown Issue Detection :"
		write-host "------------------------`n"
		if ($MonitorToInvestigate)   {CheckifthiscanbeaknownissueusingMonitor $MonitorToInvestigate}
		if ($ResponderToInvestigate) { CheckifthiscanbeaknownissueusingResponder $ResponderToInvestigate }
		if ( $Script:foundissue -eq $false)
		{
			Write-host "Found no known issue in this script matching this monitor"
		}
		else
		{
			write-Host -foreground yellow ("`n`nKnown issue found !! Please check the issue detected upper. To continue and check probe events anyway , press any key")
			$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")	
		}
		$Script:KnownIssueDetectionAlreadydone = $true
	}
}

function CheckifthiscanbeaknownissueusingResponder
{
[cmdletbinding()]
Param( [String]$ResponderToInvestigate )

	$Script:checkforknownissue =$true
	if (($ResponderToInvestigate -eq "ActiveDirectoryConnectivityConfigDCServerReboot") -and ($Majorexchangeversion -eq 15) -and ($Minorexchangeversion -eq 0) -and ($Buildexchangeversion -lt 775))
	{
		write-host -foreground yellow ("There is a known issue with restarts initiated by the  ActiveDirectoryConnectivityConfigDCServerReboot prior to CU3 which appears to be your case" )
		write-host -foreground yellow ("Check https://support.microsoft.com/en-us/kb/2883203" )
		$Script:foundissue =$true;return;
	}

	if ($ResponderToInvestigate -eq "ImapProxyTestCafeOffline")
	{
		write-host -foreground yellow ("ImapProxyTestCafeOffline can set ImapProxy component as inactive when 127.0.0.1 is blocked in IMAP bindings." )
		write-host -foreground yellow ("Check ImapSettings using Exchange Powershell command : Get-ImapSettings." )
		write-host ("Change the settings if needed with Set-ImapSettings - https://technet.microsoft.com/en-us/library/aa998252(v=exchg.150).aspx")
		$Script:foundissue =$true;return;
	}
	if ($ResponderToInvestigate -eq "PopProxyTestCafeOffline")
	{
		write-host -foreground yellow ("PopProxyTestCafeOffline can set POPProxy component as inactive when 127.0.0.1 is blocked in POP bindings." )
		write-host -foreground yellow ("Check PopSettings using Exchange Powershell command : Get-POPSettings." )
		write-host -foreground yellow ("Change the settings if needed with Set-POPSettings - https://technet.microsoft.com/en-us/library/aa997154(v=exchg.150).aspx")
		$Script:foundissue =$true;return;
	}
	if (($ResponderToInvestigate -eq "OutlookMapiHttpSelfTestRestart") -and ($Majorexchangeversion -eq 15) -and ($Minorexchangeversion -eq 0) -and ($Buildexchangeversion -lt 1130))
	{
		write-host -foreground yellow ("There is a known issue with OutlookMapiHttpSelfTestRestart prior to CU10 ( for reference OfficeMain: 1541090)" )
		write-host -foreground yellow ("You may plan to apply CU10 : https://support.microsoft.com/en-us/kb/3078678" )
		$Script:foundissue =$true;return;
	}
}

function CheckifthiscanbeaknownissueusingMonitor
{
[cmdletbinding()]
Param( [String]$MonitorToInvestigate )

	$Script:checkforknownissue =$true
	if (($MonitorToInvestigate -like "*Mapi.Submit.Monitor") -and ($Majorexchangeversion -eq 15) -and ($Minorexchangeversion -eq 0))
	{
		write-host -foreground yellow ("There is a known issue with Mapi.Submit.Monitor. This issue is fixed in CU11 ( OfficeMain: 1956332) " )
		$Script:foundissue =$true;return;
	}
	if (($MonitorToInvestigate -like "MaintenanceFailureMonitor.Network") -and ($Majorexchangeversion -eq 15) -and ($Minorexchangeversion -eq 0) -and ($Buildexchangeversion -lt 1130)) 
	{
		write-host -foreground yellow ("There is a known issue with MaintenanceFailureMonitor.Network/IntraDagPingProbe is fixed in CU10.( for reference OfficeMain: 2080370)" )
		write-host -foreground yellow ("You may plan to apply CU10 : https://support.microsoft.com/en-us/kb/3078678" )
		$Script:foundissue =$true;return;
	}
	if (($MonitorToInvestigate -like "MaintenanceFailureMonitor.ShadowService") -and ($Majorexchangeversion -eq 15) -and ($Minorexchangeversion -eq 1) ) 
	{
		write-host -foreground yellow ("There is a known issue with MaintenanceFailureMonitor.ShadowService which fix will be included in Exchange 2016 CU5 and upper.( for reference OfficeMain: 142253)" )
		$Script:foundissue =$true;return;
	}
	
	if (($MonitorToInvestigate -like "EacBackEndLogonMonitor") -and ($Majorexchangeversion -eq 15) -and ($Minorexchangeversion -eq 1) ) 
	{
		write-host -foreground yellow ("EacBackEndLogonMonitor has been seen unhealthy linked uninitilized culture on test mailboxes. You may run this command and check if this helps : get-mailbox -Monitoring -server $env:computername | Set-MailboxRegionalConfiguration -Language En-US -TimeZone ""Pacific Standard Time""" )
		$Script:foundissue =$true;return;
	}
	
	if ($MonitorToInvestigate -like "ActiveSyncCTPMonitor")
	{
		$ActiveSyncCTPpossible401issue = $true
		if($Script:lastProbeerror)
		{
			if ($Script:lastProbeerror.StateAttribute6 -ne 401)
			{$ActiveSyncCTPpossible401issue = $false}
		}
		if ($ActiveSyncCTPpossible401issue)
		{
			write-host ("ActiveSyncCTPMonitor can fail with error 401 when BasicAuthEnabled setting in get-activesyncvirtualdirectory has been changed and set to `$false.  - KB 3125818" )
			write-host("If this is your case , Enable Basic Authentication again if possible using the command :`nSet-activesyncvirtualdirectory -basicAuthEnabled `$true." ) 
			write-host("Or disable this monitor using an override :`nAdd-GlobalMonitoringOverride -Identity ActiveSync\ActiveSyncCTPMonitor  -ItemType Monitor -PropertyName Enabled -PropertyValue 0" )
			$Script:foundissue =$true;return;
		}
	}
	
	if ($MonitorToInvestigate -like "ActiveSyncDeepTestMonitor")
	{
		$ActiveSyncDeepTestpossibleIndexwasoutofrangeissue = $true
		if($Script:lastProbeerror)
		{
			if ($Script:lastProbeerror.Error -like "*Index was out of range*")
			{Write-host -foreground yellow "Index was out of range error in the probe`n"}
			else
			{$ActiveSyncDeepTestpossibleIndexwasoutofrangeissue = $false}
		}
		if ($ActiveSyncDeepTestpossibleIndexwasoutofrangeissue)
		{
			write-host ("ActiveSyncDeepTestMonitor can fail with Index was out of range error when no active database are found on the server" )
			write-host("If this is your case , disable this monitor with this command : " ) 
			write-host("Add-GlobalMonitoringOverride -Identity ActiveSync\ActiveSyncDeepTestMonitor  -ItemType Monitor -PropertyName Enabled -PropertyValue 0" )
			$Script:foundissue =$true;return;
		}		
	}

	if ($MonitorToInvestigate -like "ServerOneCopyInternalMonitor*")
	{
		$ServerOneCopyInternalpossibleWMIissue = $true
		if($Script:lastProbeerror)
		{
			if ($Script:lastProbeerror.Exception -like "*Microsoft.Exchange.Monitoring.ActiveMonitoring.HighAvailability.Probes.ServiceMonitorProbe.GetCurrentSystemUpTime*")
			{Write-host -foreground yellow "Found ProbeException in Microsoft.Exchange.Monitoring.ActiveMonitoring.HighAvailability.Probes.ServiceMonitorProbe.GetCurrentSystemUpTime`n"}
			else
			{$ServerOneCopyInternalpossibleWMIissue = $false}
		}
		if ($ServerOneCopyInternalpossibleWMIissue )
		{
			write-host -foreground yellow "ServerOneCopyInternalMonitor is failing to request information via WMI in GetCurrentSystemUpTime."
			write-host -foreground yellow "WMI request failing should be : SELECT LastBootUpTime FROM Win32_OperatingSystem WHERE Primary='true'"
			write-host -foreground yellow "This may be investiguated at WMI level looking for this request"
			write-host  -foreground yellow "This WMI request is planned to be replaced in future version higher than 15.00.1187.000 likely CU13 by direct Windows native call without going through WMI layer.( for reference OfficeMain:2908185)"
			$Script:foundissue =$true;return;
		}		
	}
	if ($MonitorToInvestigate -like "ServiceHealthMSExchangeReplEndpointMonitor*")
	{
		$ServiceHealthMSExchangeReplEndpointpossibleDNSissue = $true
		if($Script:lastProbeerror)
		{
			if ($Script:lastProbeerror.Exception -like "*because DNS didn't return any information.*")
			{Write-host -foreground yellow "Found Exception pointing to DNS missing information`n"}
			else
			{$ServiceHealthMSExchangeReplEndpointpossibleDNSissue = $false}
		}
		if ($ServiceHealthMSExchangeReplEndpointpossibleDNSissue)
		{
			write-host -foreground yellow "ServiceHealthMSExchangeReplEndpointMonitor is failing due to missing DNS entry."
			write-host -foreground yellow "Make sure that the 'Register this connection’s addresses in DNS' property is selected on the network adapter"
			write-host -foreground yellow "https://support.microsoft.com/en-us/kb/2969070"
			$Script:foundissue =$true;return;
		}		
	}
	if ($MonitorToInvestigate -like "DiscoveryErrorReportMonitor*")
	{
		write-host -foreground yellow "DiscoveryErrorReportMonitor is Disabled by default and should not be enabled"
		$Script:foundissue =$true;return;
	}
	if($Script:lastProbeerror)
	{
			if ($Script:lastProbeerror.Exception -like "*The underlying connection was closed*")
			{
				Write-host -foreground yellow "This probe error message related to underlying connection closed has been seen when connection for loopback adapter has been blocked at lower level before reaching Exchange`n"
				Write-host -foreground yellow "You can check in IIS Default Web Site /Actions pane / Bindings that “All Unassigned” is used and this has not been changed to only allow specific IP.`n"
				Write-host -foreground yellow "This has been seen when blocking some TLS version using Secureprotocols registry key or through GPO.`n"
				Write-host -foreground yellow "You can check if some TLS version are disabled under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols (https://techcommunity.microsoft.com/t5/exchange-team-blog/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and/ba-p/607761).`n"
				Write-host -foreground yellow "You may also check if this is linked with antivirus or local firewall rules.`n"
				$Script:foundissue =$true;return;
			}
	}
}

function InvestigateUnhealthyMonitor
{
[cmdletbinding()]
Param([String]$ServerHealthfile )

	write-progress "Checking MonitorHealth"
	if ($pathforlogsspecified)
	{
		TestFileorCmd $ServerHealthfile;
		if ( -not (Test-Path $ServerHealthfile))
		{ Write-Host -foregroundcolor red ("Path to ServerHealth file is invalid : $ServerHealthfile");exit }

	    $myHealthEntryList = New-Object System.Collections.ArrayList                             
		$currentHealthEntry = New-Object -TypeName PSObject
		$firstline = $true
		foreach ($line in (Get-Content $ServerHealthfile))
		{
			$propname = $line.split(" ")[0];
			if ( -not $propname) { continue; }
			if ($propname -eq "SerializationData" -or $propname -eq "Result" -or $propname -eq "PSComputerName" -or $propname -eq "PSShowComputerName") { continue; }
			if ($propname -eq "RunspaceId")
			{
				if ($firstline)
				{  $firstline = $false}
				else
				{
	                		if ($currentHealthEntry.alertValue )
	                		{
	                    			if (-not ($currentHealthEntry.AlertValue.ToString() -eq "Healthy"))
	                    				{ $addresult = $myHealthEntryList.Add($currentHealthEntry)}
	                		}
	                		$currentHealthEntry = New-Object -TypeName PSObject           
				}
				continue;
			}
			$propvalue = ($line.split(":")[1]).split(" ")[1];
	        if ($propvalue) {$currentHealthEntry | Add-Member -Name $propname -Value $propvalue -MemberType NoteProperty}
		}
	}	
	else
	{
		TestFileorCmd $ServerHealthcmd;
		$ServerHealthcmd = $ServerHealthcmd +'|?{$_.AlertValue -ne "Healthy"}'
		Write-verbose $ServerHealthcmd
		$myHealthEntryList = invoke-expression $ServerHealthcmd
	}
	write-progress "Checking MonitorHealth" -completed
	
	if ( $myHealthEntryList.count -gt 1)
	{
		$Selectunhealthymonitor = "Select the Unhealthy Monitor that you like to investigate"
		write-host $Selectunhealthymonitor
		Start-Sleep -s 1
		$UnhealthyMonitorToInvestigate = $myHealthEntryList | Out-GridView -PassThru -title $Selectunhealthymonitor
		if ( $UnhealthyMonitorToInvestigate)
		{
			if (([string]::Compare($UnhealthyMonitorToInvestigate.Server,$env:computername,$true) -eq 0) -or ($pathforlogsspecified))
			{	InvestigateMonitor $UnhealthyMonitorToInvestigate.Name $null $UnhealthyMonitorToInvestigate.TargetResource $null }
			else
			{
				Write-host -foregroundcolor yellow ("`nThe Monitor you select is regarding a different server : " + $UnhealthyMonitorToInvestigate.Server + " .")
				Write-host -foregroundcolor yellow ("Run this script on this server directly to analyse this monitor further." )
			}
		}
		else
		{ Write-host ("`nYou have not selected any unhealthy monitor. Run the script again and select an occurrence" ) }
	}
	else
	{ Write-host ("`nFound no unhealthy monitor." ) }
}

function CollectMaLogs
{
[cmdletbinding()]
Param([String] $InvocationPath )
	try
	{
		$ExchangeServerinfo = Get-ExchangeServer -identity $env:computername -status |Format-List
	}
	catch [System.Management.Automation.CommandNotFoundException]
	{
		write-host -foregroundcolor red "Exchange Powershell not loaded.`nYou likely ran the script inside Windows powershell. Run it again inside Exchange powershell"
		exit
	}
	catch
	{
		write-host -foregroundcolor red ($error[0]|format-list -force |out-string)
		exit
	}

	$OutputPath = (split-path -parent $InvocationPath) + "\LogsCollected"
	if (-not (Test-Path($OutputPath)))
	{  New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }
	if (-not (Test-Path($OutputPath)))
	{ write-host "Failed to create " + $OutputPath + " to store logs collected";exit }

	$ExchangeServerinfofile = $OutputPath + "\" + $env:computername + "_ExchangeServer_FL.TXT"
	$ExchangeServerinfo |out-file $ExchangeServerinfofile

    $GlobalMOverride = Get-GlobalMonitoringOverride
    $GlobalMonitoringOverridefile = $OutputPath + "\GlobalMonitoringOverride.TXT"
    if ($GlobalMOverride.Count -ne 0) { $GlobalMOverride | Format-List > $GlobalMonitoringOverridefile }

    $ServerMOverride = Get-serverMonitoringOverride -Server $env:computername
    $ServerMOverridefile = $OutputPath + "\serverMonitoringOverride.TXT"
    if ($ServerMOverride.Count -ne 0) { $ServerMOverride | Format-List > $ServerMOverridefile }

    $ServerComponentStatesfile = $OutputPath + "\ServerComponentStates.TXT"
    reg query HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\ServerComponentStates /s > $ServerComponentStatesfile

	write-progress "Collecting Get-ServerHealth"
	$ServerHealthfile = $OutputPath + "\" + $env:computername +"_ServerHealth_FL.TXT"
	Get-ServerHealth -Identity $env:computername |Format-List > $ServerHealthfile
	write-progress "Collecting Get-ServerHealth" -completed

	$EventLogNames = wevtutil.exe el | Select-String "Microsoft-Exchange"
	$EventLogNames +=  "Application","System"

	ForEach ($EventLogName in $EventLogNames) 
	{
		$progresseventlogmessage = "Collecting " + $EventLogName + " eventlog"
		write-progress $progresseventlogmessage
		$wevtutilcmd = $EventLogName -replace "/",""
		$evtxpath = $OutputPath + '\' + $wevtutilcmd + '.evtx'
		if ((Test-Path($evtxpath)))
		{   Remove-Item $evtxpath | Out-Null }
		wevtutil epl "$EventLogName" "$evtxpath"
		write-progress $progresseventlogmessage -completed
	}
	$monitoringfolders = Get-ChildItem ( $env:exchangeinstallpath + "\Logging\Monitoring" ) -recurse | Where-Object {$_.PSIsContainer -eq $True}
	foreach ($monitoringfolder in $monitoringfolders)
	{
		$logcollectionmonitoringfolder = $OutputPath + "\" + $monitoringfolder.Fullname.Substring(($env:exchangeinstallpath + "\Logging\Monitoring").length)	
		if (-not (Test-Path($logcollectionmonitoringfolder)))
		{  New-Item -ItemType Directory -Force -Path $logcollectionmonitoringfolder | Out-Null }
		if (-not (Test-Path($logcollectionmonitoringfolder)))
		{ write-host "Failed to create " + $logcollectionmonitoringfolder + " to store logs collected";exit }
	
		$monitoringfiles = Get-ChildItem ( $monitoringfolder.Fullname ) | Where-Object {$_.PSIsContainer -eq $false}
		if ($monitoringfolder.Name -eq "ActiveMonitoringTraceLogs")
		{  $monitoringfiles = $monitoringfiles | Sort-Object LastAccessTime -Descending | Select-Object -First 2 }
	
		foreach ($monitoringfile in $monitoringfiles )
		{
			write-progress ("Collecting " + $monitoringfile.Fullname)
			Copy-Item $monitoringfile.Fullname -Destination $logcollectionmonitoringfolder
			write-progress ("Collecting " + $monitoringfile.Fullname) -completed
		}
	}

	$HighAvailabilityfiles = Get-ChildItem ($env:exchangeinstallpath + "\Logging\HighAvailability") | Where-Object {$_.PSIsContainer -eq $false}
	$logHighAvailabilityfolder = $OutputPath + "\HighAvailability"
	if (-not (Test-Path($logHighAvailabilityfolder)))
	{  New-Item -ItemType Directory -Force -Path $logHighAvailabilityfolder | Out-Null }
	if (-not (Test-Path($logHighAvailabilityfolder)))
	{ write-host "Failed to create " + $logHighAvailabilityfolder + " to store HighAvailability logs collected";exit }
	foreach ($HighAvailabilityfile in $HighAvailabilityfiles )
	{
		write-progress ("Collecting " + $HighAvailabilityfile.Fullname)
		Copy-Item $HighAvailabilityfile.Fullname -Destination $logHighAvailabilityfolder
		write-progress ("Collecting " + $HighAvailabilityfile.Fullname) -completed
	}

	$zipfilename = (split-path -parent $InvocationPath) + "\MALogs" + (get-date -uFormat "%Y%m%d%H%M%S") + ".zip"
	write-progress "Zipping the logs collected"
	Add-Type -Assembly System.IO.Compression.FileSystem
	[System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath,$zipfilename, [System.IO.Compression.CompressionLevel]::Optimal, $false)
	write-progress "Zipping Log Collected" -completed
	Write-host ("You can delete the temporary directory " + $OutputPath)
	Write-host ("The logs have been zipped in " + $zipfilename)
	exit
}


$ScriptUsage = "Run this script without parameter using Exchange Powershell to do the analysis on the Exchange server directly or collect the logs for analysis (option C in the menu).`nUse this link for the documentation http://blogs.technet.com/b/jcoiffin/archive/2015/10/21/troubleshoot-exchange-2013-2016-managed-availability.aspx"
if ($Help)
{
		Write-Host $ScriptUsage
		exit
}

if ($PSVersionTable.PSVersion.Major -lt 3)
{
	write-host -foregroundcolor red ("Current powershell version is " + $PSVersionTable.PSVersion.Major)
	write-host ("Upgrade to powershell 3 or higher to run this script")
	write-host ("Here is the link to download powershell version 4 : http://www.microsoft.com/en-US/download/details.aspx?id=40855")
	exit
}

if ($Collect)
{  CollectMaLogs $MyInvocation.MyCommand.Path}

$pathforlogsspecified =$false
$usinglocalpath =$false
$exchangeversion = $false 
if ( -not ($pathforlogs))
{	
	try
	{
		$exchangeversion = (get-exchangeserver -identity $env:computername).AdminDisplayVersion.tostring()
	}
	catch [System.Management.Automation.CommandNotFoundException]
	{
		$pathforlogs = (split-path -parent $MyInvocation.MyCommand.Path) +'\'
		if ((Get-ChildItem | ?{ ($_.PSIsContainer) -and ( "Exchange_Server_Data","Windows_Event_Logs" -contains $_.Name) } | measure-Object).Count -eq 2)
		{
			try
			{
				write-host -foregroundcolor Yellow "Log structure appears to come from ExchangeLogCollector" 
				$maanalysispath = $pathforlogs + "ManagedAvailabilityTroubleshooterAnalysis\"
				If(!(test-path $maanalysispath))
				{
					New-Item -ItemType Directory -Force -Path $maanalysispath | Out-Null
					write-progress "Unzip logs from ExchangeLogCollector to ManagedAvailabilityTroubleshooterAnalysis folder"
					Add-Type -AssemblyName System.IO.Compression.FileSystem				
					[System.IO.Compression.ZipFile]::ExtractToDirectory($pathforlogs + "Windows_Event_Logs\Microsoft-Exchange-ManagedAvailability.zip", $maanalysispath)
					[System.IO.Compression.ZipFile]::ExtractToDirectory($pathforlogs + "Windows_Event_Logs\Microsoft-Exchange-ActiveMonitoring.zip", $maanalysispath)
					[System.IO.Compression.ZipFile]::ExtractToDirectory($pathforlogs + "Windows_Event_Logs\Windows-Logs.zip", $maanalysispath)
					[System.IO.Compression.ZipFile]::ExtractToDirectory($pathforlogs + "ManagedAvailabilityMonitoringLogs.zip", $maanalysispath)
					$excollectorserverlog = Get-ChildItem -path ($pathforlogs + "Exchange_Server_Data") | ?{ $_.Name -like "*_ExchangeServer.txt"}				
					Copy-item $excollectorserverlog.fullname ($maanalysispath + ($excollectorserverlog.name -replace "_ExchangeServer.txt","_ExchangeServer_FL.TXT"))
					$excollectorerverHealthlog = Get-ChildItem -path ($pathforlogs + "Exchange_Server_Data") | ?{ $_.Name -like "*ServerHealth.txt"}
					Copy-item $excollectorerverHealthlog.fullname ($maanalysispath + ($excollectorerverHealthlog.name -replace "_ServerHealth.txt","_ServerHealth_FL.TXT"))
					foreach ($fileinmapath in Get-ChildItem -Path $maanalysispath | Where-Object {$_.PSIsContainer -eq $false}) 
					{
						$newfilewithoutdashinActiveM= $fileinmapath.fullname.Replace("ActiveMonitoring-","ActiveMonitoring")   
						$newfilewithoutdashinMA = $newfilewithoutdashinActiveM.Replace("ManagedAvailability-","ManagedAvailability")   
						Rename-Item $fileinmapath.fullname $newfilewithoutdashinMA
					}
					
					write-progress "Unzip logs from ExchangeLogCollector to ManagedAvailabilityTroubleshooterAnalysis folder"  -completed
				}
				$pathforlogs = $maanalysispath
			}
			catch
			{
				write-host -foregroundcolor red "Encountered a failure when trying to extract logs from ExchangeLogCollector"
				write-host -foregroundcolor red ($error[0]|format-list -force |out-string)
				exit
			}
		}
		$usinglocalpath =$true
	}
	catch
	{
		write-host -foregroundcolor red ($error[0]|format-list -force |out-string) 
		exit
	}
	
	if ($exchangeversion)
	{
		$ProbeDefinitioneventcmd  = "Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ActiveMonitoring/ProbeDefinition "
		$ProbeResulteventcmd      = "Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ActiveMonitoring/ProbeResult "
		$MonitorDefinitioncmd     = "Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ActiveMonitoring/MonitorDefinition "
		$ResponderDefinitioncmd   = "Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ActiveMonitoring/responderdefinition "
		$MaintenanceDefinitioncmd = "Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ActiveMonitoring/MaintenanceDefinition "
		$MaintenanceResultcmd     = "Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ActiveMonitoring/MaintenanceResult "
		$Systemcmd = "Get-WinEvent –ComputerName $env:computername -LogName System "
		$Script:LoggingMonitoringpath = $env:exchangeinstallpath + "\Logging\Monitoring"

		if ((((Get-ExchangeServer| Where-Object {$_.AdminDisplayVersion.Major -gt 14}).Count -lt 20) -or $AllServers) -and ($OnlyThisServer -eq $false))
		{
			$ServerList = $ServerTestList =  Get-ExchangeServer|?{$_.AdminDisplayVersion.Major -gt 14}
			foreach ($exserver in $ServerTestList)
			{
				try
				{
					Get-WinEvent -ComputerName $exserver -LogName Microsoft-Exchange-ManagedAvailability/RecoveryActionResults -Maxevents 1 >$null
				}
				catch
				{
					$ServerList = $ServerList | ?{$_.name -ne $exserver.name}
					write-host "Analyze will skip server $exserver as requests to get server events are failing ( maybe the machine is stopped or is an Edge behind a firewall ) "
				}
			}
			$RecoveryActionResultscmd = '$ServerList | Foreach-Object { $exserver = $_ ; $RAindex = $RecoveryActions.Count;$RecoveryActions+=( Get-WinEvent -ComputerName $exserver -LogName Microsoft-Exchange-ManagedAvailability/RecoveryActionResults '
			$ServerHealthcmd          = '$ServerList | Get-ServerHealth'
			$ManagedAvailabilityMonitoringcmd  = '$ServerList | Foreach-Object { $alertevents+= Get-WinEvent -ComputerName $_ -LogName Microsoft-Exchange-ManagedAvailability/Monitoring '
		}
		else
		{
			$RecoveryActionResultscmd = "( Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ManagedAvailability/RecoveryActionResults "
			$ServerHealthcmd          = "Get-ServerHealth -Identity $env:computername"
			$ManagedAvailabilityMonitoringcmd  = "Get-WinEvent –ComputerName $env:computername -LogName Microsoft-Exchange-ManagedAvailability/Monitoring "
		}
	}
}
if ($pathforlogs)
{
	if ( Test-Path $pathforlogs)
	{
		$pathforlogsspecified =$true
		$foundnologtoanalyse = $true
		if  (-not $pathforlogs.EndsWith('\')) { $pathforlogs += '\'}
		$Script:LoggingMonitoringpath = $pathforlogs
		$Dir = Get-ChildItem ($pathforlogs+"*.evtx")
		$RecoveryActionResultsLog = ($Dir| Where-Object {$_.Name -like "*RecoveryActionResults.evtx" })
		if ( $RecoveryActionResultsLog.Count -ne 1)
		{
			if ($RecoveryActionResultsLog.Count -eq 0)
			{
				$errormsg = "Can't find RecoveryActionResults evtx file in " + $pathforlogs + " directory. Check the directory";
				if ($usinglocalpath)
				{
					write-host -foregroundcolor yellow "Exchange Powershell not loaded.`nIn case you like to analyse directly on the Exchange server , run this script in Exchange Powershell"
					write-host ("No path for logs specified , using local path " + $pathforlogs)
				}
			}
			else
			{
				$errormsg = "Too much RecoveryActionResults evtx files in " + $pathforlogs + " directory.";
				foreach ($RecoveryActionResultsLogFile in $RecoveryActionResultsLog)
				{$errormsg += "`n" + $RecoveryActionResultsLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$RecoveryActionResultscmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $RecoveryActionResultsLog.FullName)
			$RecoveryActionResultscmd = "( Get-WinEvent -path ""$RecoveryActionResultsLog"""
			$foundnologtoanalyse = $false
		}
		$ResponderDefinitionLog = ($Dir| Where-Object {$_.Name -like "*ResponderDefinition.evtx" })
		if ( $ResponderDefinitionLog.Count -ne 1)
		{
			if ($ResponderDefinitionLog.Count -eq 0)
			{$errormsg = "Can't find ResponderDefinition evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much ResponderDefinition evtx files in " + $pathforlogs + " directory.";
				foreach ($ResponderDefinitionLogFile in $ResponderDefinitionLog)
				{$errormsg += "`n" + $ResponderDefinitionLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$ResponderDefinitioncmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $ResponderDefinitionLog.FullName)
			$ResponderDefinitioncmd = "Get-WinEvent -path ""$ResponderDefinitionLog""" 
			$foundnologtoanalyse = $false
		}
		$MaintenanceDefinitionLog = ($Dir| Where-Object {$_.Name -like "*MaintenanceDefinition.evtx" })
		if ( $MaintenanceDefinitionLog.Count -ne 1)
		{
			if ($MaintenanceDefinitionLog.Count -eq 0)
			{$errormsg = "Can't find MaintenanceDefinition evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much MaintenanceDefinition evtx files in " + $pathforlogs + " directory.";
				foreach ($MaintenanceDefinitionLogFile in $MaintenanceDefinitionLog)
				{$errormsg += "`n" + $MaintenanceDefinitionLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$MaintenanceDefinitioncmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $MaintenanceDefinitionLog.FullName)
			$MaintenanceDefinitioncmd = "Get-WinEvent -path ""$MaintenanceDefinitionLog""" 
			$foundnologtoanalyse = $false
		}
				$MaintenanceResultLog = ($Dir| Where-Object {$_.Name -like "*MaintenanceResult.evtx" })
		if ( $MaintenanceResultLog.Count -ne 1)
		{
			if ($MaintenanceResultLog.Count -eq 0)
			{$errormsg = "Can't find MaintenanceResult evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much MaintenanceResult evtx files in " + $pathforlogs + " directory.";
				foreach ($MaintenanceResultLogFile in $MaintenanceResultLog)
				{$errormsg += "`n" + $MaintenanceResultLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$MaintenanceResultcmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $MaintenanceResultLog.FullName)
			$MaintenanceResultcmd = "Get-WinEvent -path ""$MaintenanceResultLog""" 
			$foundnologtoanalyse = $false
		}
		$MonitorDefinitionLog = ($Dir| Where-Object {$_.Name -like "*MonitorDefinition.evtx" })
		if ( $MonitorDefinitionLog.Count -ne 1)
		{
			if ($MonitorDefinitionLog.Count -eq 0)
			{$errormsg = "Can't find MonitorDefinition evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much MonitorDefinition evtx files in " + $pathforlogs + " directory.";
				foreach ($MonitorDefinitionLogFile in $MonitorDefinitionLog)
				{$errormsg += "`n" + $MonitorDefinitionLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$MonitorDefinitioncmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $MonitorDefinitionLog.FullName)
			$MonitorDefinitioncmd = "Get-WinEvent -path ""$MonitorDefinitionLog""" 
			$foundnologtoanalyse = $false
		}
		$ProbeDefinitionLog = ($Dir| Where-Object {$_.Name -like "*ProbeDefinition.evtx" })
		if ( $ProbeDefinitionLog.Count -ne 1)
		{
			if ($ProbeDefinitionLog.Count -eq 0)
			{$errormsg = "Can't find ProbeDefinition evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much ProbeDefinition evtx files in " + $pathforlogs + " directory.";
				foreach ($ProbeDefinitionLogFile in $ProbeDefinitionLog)
				{$errormsg += "`n" + $ProbeDefinitionLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$ProbeDefinitioneventcmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $ProbeDefinitionLog.FullName)
			$ProbeDefinitioneventcmd = "Get-WinEvent -path ""$ProbeDefinitionLog"""
			$foundnologtoanalyse = $false
		}		
		$ProbeResultLog = ($Dir| Where-Object {$_.Name -like "*ProbeResult.evtx" })
		if ( $ProbeResultLog.Count -ne 1)
		{
			if ($ProbeResultLog.Count -eq 0)
			{$errormsg = "Can't find ProbeResult evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much ProbeResult evtx files in " + $pathforlogs + " directory.";
				foreach ($ProbeResultLogFile in $ProbeResultLog)
				{$errormsg += "`n" + $ProbeResultLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$ProbeResulteventcmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $ProbeResultLog.FullName)
			$ProbeResulteventcmd = "Get-WinEvent -path ""$ProbeResultLog"""
			$foundnologtoanalyse = $false
		}
		$ManagedAvailabilityMonitoringLog = ($Dir| Where-Object {$_.Name -like "*Exchange-ManagedAvailabilityMonitoring.evtx" })
		if ( $ManagedAvailabilityMonitoringLog.Count -ne 1)
		{
			if ($ManagedAvailabilityMonitoringLog.Count -eq 0)
			{$errormsg = "Can't find ManagedAvailability Monitoring evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much ManagedAvailability Monitoring evtx files in " + $pathforlogs + " directory.";
				foreach ($ManagedAvailabilityMonitoringLogFile in $ManagedAvailabilityMonitoringLog)
				{$errormsg += "`n" + $ManagedAvailabilityMonitoringLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$ManagedAvailabilityMonitoringcmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $ManagedAvailabilityMonitoringLog.FullName)
			$ManagedAvailabilityMonitoringcmd = "Get-WinEvent -path ""$ManagedAvailabilityMonitoringLog"""
			$foundnologtoanalyse = $false
		}
		$SystemLog = ($Dir| Where-Object {$_.Name -like "*System.evtx" })
		if ( $SystemLog.Count -ne 1)
		{
			if ($SystemLog.Count -eq 0)
				{$errormsg = "Can't find System evtx file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much System evtx files in " + $pathforlogs + " directory.";
				foreach ($SystemLogFile in $SystemLog)
				{$errormsg += "`n" + $SystemLogFile.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$Systemcmd = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $SystemLog.FullName)
			$Systemcmd = "Get-WinEvent -path ""$SystemLog"""
			$foundnologtoanalyse = $false
		}
		$ServerHealthfile = Get-ChildItem ($pathforlogs+"*ServerHealth_FL.TXT");
		if ( $ServerHealthfile.Count -ne 1)
		{
			if ($ServerHealthfile.Count -eq 0)
			{$errormsg = "Can't find ServerHealth_FL TXT file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much ServerHealth_FL TXT files in " + $pathforlogs + " directory.";
				foreach ($ServerHealthfileinstance in $ServerHealthfile)
				{$errormsg += "`n" + $ServerHealthfileinstance.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$ServerHealthfile = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $ServerHealthfile)
			$foundnologtoanalyse = $false
		}
		$GetExchangeServerfile = Get-ChildItem ($pathforlogs+"*_ExchangeServer_FL.TXT");
		if ( $GetExchangeServerfile.Count -ne 1)
		{
			if ($GetExchangeServerfile.Count -eq 0)
			{$errormsg = "Can't find ExchangeServer_FL TXT file in " + $pathforlogs + " directory. Check the directory";}
			else
			{
				$errormsg = "Too much ExchangeServer_FL TXT files in " + $pathforlogs + " directory.";
				foreach ($GetExchangeServerfileinstance in $GetExchangeServerfile)
				{$errormsg += "`n" + $GetExchangeServerfileinstance.FullName}
			}
			Write-Host -foregroundcolor red ($errormsg) ;
			$GetExchangeServerfile = "File missing for this action.`n" + $errormsg
		}
		else
		{
			Write-Host ("Found file " + $GetExchangeServerfile)
			if ( -not (Test-Path $GetExchangeServerfile))
			{ Write-Host -foregroundcolor red ("Path to ServerHealth file is invalid : $GetExchangeServerfile") }
			else
			{
				foreach ($line in (Get-Content $GetExchangeServerfile))
				{
					$propname = $line.split(" ")[0];
					if ( -not $propname) { continue; }
					if ($propname -eq "AdminDisplayVersion")
					{
						$exchangeversion = $line.split(":")[1];
						break;
					}
				}
			}
		}
		if ($foundnologtoanalyse)
		{
			Write-Host -foregroundcolor red ("`nFound no log to analyze in "+ $pathforlogs + " directory. Check the directory")
			exit
		}
	}
	else
	{				
		if ( -not (($pathforlogs -eq "/?") -or ($pathforlogs -eq "/help"))) {Write-Host -foregroundcolor red "`nThe path provided as argument is not valid."}
		Write-Host $ScriptUsage
		exit
	}
}

if ($exchangeversion)
{
	$tmpbuildstring = $exchangeversion
	$tmpbuildstring = $tmpbuildstring.Replace(" ", "")
	$tmpbuildstring = $tmpbuildstring.Replace("Version", "")
	$tmpbuildstring = $tmpbuildstring.Replace(")", "")
	$tmpbuildstring = $tmpbuildstring.Replace("(Build", ".")
	$parsedexchangeversion = $tmpbuildstring.split(".")
	if ($parsedexchangeversion.count -ne 4)
	{
		Write-Host -foregroundcolor red "`nError while parsing build version : $exchangeversion .`nWill ignore build information"
		$exchangeversion = $null
	}
	else
	{
		$exchangeversion = $parsedexchangeversion	
		$Majorexchangeversion = [int] $exchangeversion[0]
		if ($Majorexchangeversion -lt 15)
		{ Write-Host -foregroundcolor red "`nThe Exchange version detected appears to be previous Exchange 2013 : $exchangeversion.`nManaged Availability (which this tool is helping to troubleshoot) is introduced in Exchange 2013 and upper.";exit }
		$Minorexchangeversion = [int] $exchangeversion[1]
		$Buildexchangeversion = [int] $exchangeversion[2]
#		$Revisionexchangeversion = [int] $exchangeversion[3]	
	}
}

$ForceRebootChoice = New-Object System.Management.Automation.Host.ChoiceDescription "My Exchange server is rebooting / encountered a bluescreen (&ForceReboot)", "My Exchange server is rebooting /encounter a bluescreen"
$AllRecoveryActionsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Some Exchange services are restarting , or some components are inactive (&All Recovery Actions)", "Some Exchange services are restarting , or some components are inactive"
$CheckSpecificResponderorMonitororProbe = New-Object System.Management.Automation.Host.ChoiceDescription "I need to check a specific Responder/Monitor or Probe - can be reported by SCOM (&Specific Responder/Monitor/Probe)", "I need to check a specific Responder/Monitor or Probe - can be reported by SCOM"
$UnhealthyMonitorChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Some Monitors appears as Unhealthy - this can be reported by a SCOM alert ( &Unhealthy Monitors)", "Some Monitors appears as Unhealthy - this can be reported by a SCOM alert"
$ProbeErrorsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Check last Probe Errors in order to find which probe is failing at the time of my problem (&Probe errors)", "I like to check last Probe Errors in order to find which probe is failing at the time of my problem"
$SCOMAlertsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Display SCOM Alerts (&Display SCOM Alerts)", "Display SCOM Alerts"
$CollectMALogsChoice = New-Object System.Management.Automation.Host.ChoiceDescription "Collect Managed Availability logs (&Collect Managed Availability logs)", "Collect Managed Availability logs"
$Investigationchoose = 0
if ($exchangeversion)
{
    $Investigationchoose = $host.ui.PromptForChoice("", "`nSelect the Option that best describes the issue that you are facing:", [System.Management.Automation.Host.ChoiceDescription[]]($ForceRebootChoice, $AllRecoveryActionsChoice,$CheckSpecificResponderorMonitororProbe,$SCOMAlertsChoice,$UnhealthyMonitorChoice,$ProbeErrorsChoice,$CollectMALogsChoice), 0)
}
else
{
    $Investigationchoose = $host.ui.PromptForChoice("", "`nSelect the Option that best describes the issue that you are facing:", [System.Management.Automation.Host.ChoiceDescription[]]($ForceRebootChoice, $AllRecoveryActionsChoice,$CheckSpecificResponderorMonitororProbe,$SCOMAlertsChoice,$UnhealthyMonitorChoice,$ProbeErrorsChoice), 0)
}

if ($Investigationchoose -eq 0 -or $Investigationchoose -eq 1)
{

	if ($pathforlogsspecified)
	{	$HighAvailabilitypath = $pathforlogs + "HighAvailability\"	}
	else
	{	$HighAvailabilitypath = $env:exchangeinstallpath + "\Logging\HighAvailability\"	}
	
	if (Test-Path $HighAvailabilitypath )
	{
		foreach ($HighAvailabilityfile in Get-ChildItem ($HighAvailabilitypath+"*PersistedBugcheckInfo*.dat"))
		{
			write-host -foregroundcolor yellow "`n`nPersistedBugcheckInfo file found : This persistent crash info point there was a forcereboot triggered by Exchange"
			write-host "This is likely running ouside of Managed Availability but by this crash is triggered by Exchange to force a failover"
			write-host "`nHere are the info regarding this forcereboot : `n"
			$HighAvailabilityfile = Get-Content $HighAvailabilityfile -Encoding Unknown
			write-host $HighAvailabilityfile
			write-host "`n"
			foreach ($line in $HighAvailabilityfile)
			{
				if ($line -like "*GetDiskFreeSpaceEx*")
				{
					write-host -foregroundcolor yellow "Exchange triggered this forcereboot as Exchange get no reply from GetDiskFreeSpaceEx call to check disk space for a long time"
					write-host -foregroundcolor yellow "This can be due to Cache manager throttling the request as there is too much slow disk write"
					write-host -foregroundcolor yellow "Involve your disk experts to check if you get slow disk access at that time"

					write-Host -foreground yellow ("`n`nKnown issue found !!")				
				}
			}
		write-host -foregroundcolor yellow  "Please check the issue detected upper. To continue, press any key"
		$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")	
		}
	}
	

	$CheckRecoveryActionForMultipleMachines = $RecoveryActionResultscmd -like "*Foreach-Object*"
	$RecoveryActions = $null
	if ($CheckRecoveryActionForMultipleMachines)
	{ TestFileorCmd ($RecoveryActionResultscmd + ")}")}
	else
	{ TestFileorCmd ($RecoveryActionResultscmd + ")") }
	$RecoveryActionscmd = $RecoveryActionResultscmd + '| % {[XML]$_.toXml()}).event.userData.eventXml'
	if ($Investigationchoose -eq 0)
	{ $RecoveryActionscmd += '| ? {$_.Id -eq "ForceReboot"}' }
	if ($CheckRecoveryActionForMultipleMachines)
	{ $RecoveryActionscmd += '; For ($i=$RAindex; $i -lt $RecoveryActions.Count; $i++) { $RecoveryActions[$i]|Add-Member -Name "MachineName" -Value $exserver -MemberType NoteProperty}};$RecoveryActions' }
	Write-verbose $RecoveryActionscmd
	write-progress "Checking Recovery Actions"
	$RecoveryActions = invoke-expression $RecoveryActionscmd
	write-progress "Checking Recovery Actions" -completed
	if ($RecoveryActions)
	{	
		if ($Investigationchoose -eq 0)
		{
			write-host ("`nLast Reboot was triggered by the Responder "+ $RecoveryActions[0].RequestorName + " at " + $RecoveryActions[0].StartTime + " ." )
			$SelectTitle = "Select the ForceReboot that you like to investigate"
		}
		else
		{   $SelectTitle = "Select the Recovery Action that you like to investigate" }
		write-host $SelectTitle
		Start-Sleep -s 1
		$RAoutgridviewcmd = '$RecoveryActions | select -Property '
		if ($CheckRecoveryActionForMultipleMachines)
		{$RAoutgridviewcmd += "MachineName,"}
		$RAoutgridviewcmd += '@{n="StartTime (GMT)";e={$_.StartTime}}, @{n="EndTime (GMT)";e={$_.EndTime}} , Id , ResourceName , InstanceId , RequestorName , Result , State , ExceptionName,ExceptionMessage,LamProcessStartTime,ThrottleIdentity , ThrottleParametersXml , Context | Sort-Object "StartTime (GMT)" -Descending | Out-GridView -PassThru -title $SelectTitle'
		Write-verbose $RAoutgridviewcmd
		$RecoveryActionToInvestigate = invoke-expression $RAoutgridviewcmd
		if ($RecoveryActionToInvestigate)
		{
			if ($RecoveryActionToInvestigate.Count -gt 1 )
			{   $RecoveryActionToInvestigate = $RecoveryActionToInvestigate[0] }
			if ($CheckRecoveryActionForMultipleMachines)
			{
				if ([string]::Compare($RecoveryActionToInvestigate.MachineName,$env:computername,$true) -ne 0)
				{
					Write-host -foregroundcolor yellow ("`nThe RecoveryAction you select is regarding a different server : " + $RecoveryActionToInvestigate.MachineName + " .")
					Write-host -foregroundcolor yellow ("Run this script on this server directly to analyse this RecoveryAction further." )
					exit;
				}
			}
			InvestigateResponder $RecoveryActionToInvestigate.RequestorName $RecoveryActionToInvestigate.ResourceName
		}
		else
		{   if ($Investigationchoose -eq 0) {Write-host ("`nYou have not selected any occurrence. Run the script again and select an occurrence" ) }}    
	}
	else
	{   write-host "`nFound no event with ID ForceReboot in RecoveryActionResults log. Health Manager shouldn't have triggered a reboot recently." }
}

if ($Investigationchoose -eq 2)
{
	$SpecificResponderorMonitororProbe = Read-Host ("Enter the name of the Responder/Monitor or Probe ")
	if ($SpecificResponderorMonitororProbe)
	{
		$IsitaResponderorMonitororProbe = 0
		if ($SpecificResponderorMonitororProbe.split("/")[0].ToLower().EndsWith("probe"))
		{		
			$IsitaResponderorMonitororProbe = 2
		}
		elseif ($SpecificResponderorMonitororProbe.split("/")[0].ToLower().EndsWith("monitor"))
		{
			$IsitaResponderorMonitororProbe = 1
		}
		else
		{
			$IsResponder = New-Object System.Management.Automation.Host.ChoiceDescription "&Responder", "Responder"
			$IsMonitor = New-Object System.Management.Automation.Host.ChoiceDescription "&Monitor", "Monitor"
			$IsProbe = New-Object System.Management.Automation.Host.ChoiceDescription "&Probe", "Probe"
			$IsitaResponderorMonitororProbe = $host.ui.PromptForChoice("", "Is it a : ", [System.Management.Automation.Host.ChoiceDescription[]]($IsResponder, $IsMonitor,$IsProbe), 0)
		}
		switch ( $IsitaResponderorMonitororProbe)
		{
			0 { InvestigateResponder $SpecificResponderorMonitororProbe $null}
			1 { InvestigateMonitor $SpecificResponderorMonitororProbe $null $null $null }
			2 { InvestigateProbe $SpecificResponderorMonitororProbe $null $null $null $null }
		}
	}
	else
	{ write-host -foregroundcolor red ("No name specified")}
	exit
}
if ($Investigationchoose -eq 3)
{
	$CheckAlertsForMultipleMachines = $ManagedAvailabilityMonitoringcmd -like "*Foreach-Object*"
	$alertevents =$null
	if ($CheckAlertsForMultipleMachines)
	{TestFileorCmd ($ManagedAvailabilityMonitoringcmd + " }") }
	else
	{TestFileorCmd $ManagedAvailabilityMonitoringcmd }
	$ManagedAvailabilityMonitoringcmd = $ManagedAvailabilityMonitoringcmd  + '-maxevents 200 |? {$_.Id -eq 4 }'
	if ($CheckAlertsForMultipleMachines)
	{$ManagedAvailabilityMonitoringcmd += ' };$alertevents'}
	Write-verbose $ManagedAvailabilityMonitoringcmd
	write-progress "Checking SCOM Alerts"
	$alertevents = invoke-expression $ManagedAvailabilityMonitoringcmd 
	$alerteventsprops = ($alertevents | ForEach-Object {[XML]$_.toXml()}).event.userData.eventXml
	For ($i=0; $i -lt $alerteventsprops.Count; $i++) 
	{
		$alerteventsprops[$i] | Add-Member TimeCreated $alertevents[$i].TimeCreated
		if ($CheckAlertsForMultipleMachines)
		{ $alerteventsprops[$i] | Add-Member MachineName $alertevents[$i].MachineName }
	}
	write-progress "Checking SCOM Alerts" -completed
	$alertoutgridviewcmd = '$alerteventsprops | select -Property '
	if ($CheckAlertsForMultipleMachines)
	{$alertoutgridviewcmd += "MachineName," }
	$alertoutgridviewcmd += 'TimeCreated, Monitor,HealthSet,Subject,Message | Out-GridView -title "SCOM Alerts"'
	invoke-expression $alertoutgridviewcmd
}
if ($Investigationchoose -eq 4)
{
	InvestigateUnhealthyMonitor $ServerHealthfile
}
if ($Investigationchoose -eq 5)
{	
	ParseProbeResult "*[UserData[EventXML [ResultType='4']]]" $null $null
}
if (($Investigationchoose -eq 6) -and ($exchangeversion))
{	
	CollectMaLogs $MyInvocation.MyCommand.Path
}