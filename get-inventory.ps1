<#
.SYNOPSIS
Get Server Information
.DESCRIPTION
This script will get the CPU specifications, memory usage statistics, and OS configuration of any Server or Computer listed in Serverlist.txt.
.NOTES  
The script will execute the commands on multiple machines sequentially using non-concurrent sessions. This will process all servers from Serverlist.txt in the listed order.
The info will be exported to a csv format.
Requires: Serverlist.txt must be created in the same folder where the script is.
File Name  : get-server-info.ps1
Author: Nikolay Petkov
http://power-shell.com/
#>
#Get the server list
$servers = (Get-ADComputer -SearchBase "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc" -Filter { OperatingSystem -Like "*Windows Server*" -and dnshostname -like "kv-crm*" }).name
#Run the commands for each server in the list
$infoColl = @()
Invoke-Command -ComputerName $servers -ScriptBlock {

	$CPUInfo              = Get-WmiObject Win32_Processor            #Get CPU Information
	$OSInfo               = Get-WmiObject Win32_OperatingSystem      #Get OS Information
	$CompInfo             = Get-WmiObject -class Win32_ComputerSystem
    #Get Memory Information. The data will be shown in a table as MB, rounded to the nearest second decimal.
	$OSTotalVirtualMemory = [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
	$OSTotalVisibleMemory = [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
	$PhysicalMemory       = Get-WmiObject CIM_PhysicalMemory | Measure-Object -Property capacity -Sum | % { [Math]::Round(($_.sum / 1GB), 2) }
    $VolumeSize           = (Get-CimInstance Win32_LogicalDisk -Filter drivetype=3) | % { [Math]::Round(($PSItem.Size / 1GB), 2)}
    #$VolumeFeeSpace       = Get-CimInstance Win32_LogicalDisk -Filter drivetype=3
    
    #$Sockets=$CompInfo.numberofprocessors
    #$Cores=$CompInfo.numberoflogicalprocessors
    #$Sockets
    
	$infoObject = New-Object PSObject
    $PSObject=""
    $xxx = 0
    #While ($xxx -le 0)
    #{$xxx +=1
		#The following add data to the infoObjects.	
#if  ( ($infoObject.ServerName).Count -lt 1){		
        if (($CPUInfo.Name).count -ge 2) {$CPUInfoName=$CPUInfo.Name[0]}
        else { $CPUInfoName=$CPUInfo.Name } 
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "ServerName"              -value $CompInfo.Name 
#}
		
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor"               -value $CPUInfoName
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Model"                   -value $CPUInfo.Caption
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer"            -value $CompInfo.Manufacturer
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "PhysicalCores"           -value $CPUInfo.NumberOfCores
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "PhysicalCores"           -value  $CompInfo.NumberOfProcessors
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "LogicalCores"            -value  $CompInfo.NumberOfLogicalProcessors
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L2CacheSize"         -value $CPUInfo.L2CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L3CacheSize"         -value $CPUInfo.L3CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Sockets"                 -value $CPUInfo.SocketDesignation
		
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Name"                 -value $OSInfo.Caption
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Version"              -value $OSInfo.Version
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalPhysical_Memory_GB" -value $PhysicalMemory
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVirtual_Memory_MB"  -value $OSTotalVirtualMemory
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVisible_Memory_MB"  -value $OSTotalVisibleMemory
		$infoObject #Output to the screen for a visual feedback.
		#$infoColl += $infoObject
        #}
	#}
} | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName| sort $CompInfo.Name |`
 Export-Csv -path c:\temp\Server_Inventory_$((Get-Date).ToString('MM-dd-yyyy')).csv -NoTypeInformation #Export the results in csv file.

 exit
  $cs = Get-WmiObject -class Win32_ComputerSystem
  $Sockets=$cs.numberofprocessors
  $Cores=$cs.numberoflogicalprocessors
  $Sockets
  ##OR like thos
  #$totalCores = ((Get-WmiObject Win32_Processor -ComputerName kv-crmapp-05).Numberofcores)| Measure-Object -Sum
  #$totalCores.sum