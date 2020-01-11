<#
.Synopsis
   Краткое описание
.DESCRIPTION
   Длинное описание
.EXAMPLE
   Пример использования этого командлета
.EXAMPLE
   Еще один пример использования этого командлета
.INPUTS
   Входные данные в этот командлет (при наличии)
.OUTPUTS
   Выходные данные из этого командлета (при наличии)
.NOTES
   Общие примечания
.COMPONENT
   Компонент, к которому принадлежит этот командлет
.ROLE
   Роль, к которой принадлежит этот командлет
.FUNCTIONALITY
   Функциональность, наиболее точно описывающая этот командлет
#>
function Get-RemoteHardwareSoftwareInfo
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.microsoft.com/',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Справочное описание параметра 1
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Search Base AD')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        #[ValidateCount(0,5)]
        #[ValidateSet("sun", "moon", "earth")]
        [String]
        #$SearchBaseAD= "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc",
        $SearchBaseAD= 'OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc',

        # Справочное описание параметра 2
        [Parameter(ParameterSetName='Servers Filter Set')]
        #[ValidatePattern("[a-z]*")]
        #[ValidateLength(0,15)]
        #[String]
        #$ServersFilter = "{ OperatingSystem -Like `"*Windows Server*`" -and dnshostname -like `"kv-crmapp*`"}"
        $ServersFilter = "OperatingSystem -Like '*Windows Server*' -and dnshostname -like 'kv-crmapp*'"
    )

    Begin
    {
    [Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US';
    $CurrUser=($env:USERNAME).ToString()
    [array]$servers=""
    if ($CurrUser -notmatch "adm") {$Cred = Get-Credential -UserName "Corp\adm-odubel" `
     -Message "Согласно политике принятой в УТК, учетная запись для доступа к серверам должна начинатся c adm-" 
     #Write-Host "sdfsfsaf=$cred.GetNetworkCredential().password"
            if ($Cred.GetNetworkCredential().password -eq "") 
            {
             Write-Host "You didn't entered password. Exiting..."
             exit 
            }
    #$servers = (Get-ADComputer -Credential $Cred -SearchBase "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc" -Filter { OperatingSystem -Like "*Windows Server*" -and dnshostname -like "kv-crmapp*" }).name    
    $servers = (Get-ADComputer -Credential $Cred -SearchBase $SearchBaseAD -Filter $ServersFilter).name
    }
    else 
    {
    #$servers = (Get-ADComputer -SearchBase "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc" -Filter { OperatingSystem -Like "*Windows Server*" -and dnshostname -like "kv-crmapp*" }).name    
    $servers = (Get-ADComputer -SearchBase $SearchBaseAD -Filter $ServersFilter).name
    }
    #$servers = (Get-ADComputer -SearchBase $SearchBaseAD -Filter $ServersFilter).name
    #Get-ADComputer -Filter "Name -like ""$PartialName""" | select -ExpandProperty Name
    #$servers = (Get-ADComputer -SearchBase "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc" -Filter ($ServersFilter)).name
    $servers+="kv-ho-shk2-n058" #.corp.ukrtelecom.loc"
    $infoObject = ""  
    $PSObject   = ""
    $xxx        = 0
    }
    Process
    {
    Invoke-Command -ComputerName $servers -ScriptBlock {
    $CPUInfo              = Get-WmiObject Win32_Processor            #Get CPU Information
	$OSInfo               = Get-WmiObject Win32_OperatingSystem      #Get OS Information
	$CompInfo             = Get-WmiObject -class Win32_ComputerSystem
    #Get Memory Information. The data will be shown in a table as MB, rounded to the nearest second decimal.
	$OSTotalVirtualMemory = [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
	$OSTotalVisibleMemory = [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
	$PhysicalMemory       = Get-WmiObject CIM_PhysicalMemory | Measure-Object -Property capacity -Sum | % { [Math]::Round(($_.sum / 1GB), 2) }
    $VolumeSize           = (Get-CimInstance Win32_LogicalDisk -Filter drivetype=3) | % { [Math]::Round(($PSItem.Size / 1GB), 2)}
    $VolumeName           = (Get-CimInstance Win32_LogicalDisk -Filter drivetype=3).Name
    
    $infoObject = New-Object PSObject
    if (($CPUInfo.Name).count -ge 2) {$CPUInfoName=$CPUInfo.Name[0]}
        else { $CPUInfoName=$CPUInfo.Name } 
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "ServerName"              -value $CompInfo.Name
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor"               -value $CPUInfoName
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer"            -value $CompInfo.Manufacturer
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "PhysicalCores"           -value  $CompInfo.NumberOfProcessors
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "LogicalCores"            -value  $CompInfo.NumberOfLogicalProcessors
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Name"                 -value $OSInfo.Caption
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Version"              -value $OSInfo.Version
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalPhysical_Memory_GB" -value $PhysicalMemory
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVirtual_Memory_MB"  -value $OSTotalVirtualMemory
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Model"                   -value $CPUInfo.Caption
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "PhysicalCores"           -value $CPUInfo.NumberOfCores
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L2CacheSize"         -value $CPUInfo.L2CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L3CacheSize"         -value $CPUInfo.L3CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Sockets"                 -value $CPUInfo.SocketDesignation
		
        $xxx=$VolumeSize.Count
        While ($xxx -ge 1)
        {
        $NameVol=$VolumeName[$xxx-1][0]
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "VolumeName_$NameVol" -Value $VolumeSize[$xxx-1]
        $xxx-=1; 
        }
        $infoObject #Output to the screen for a visual feedback.
	} | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName| sort $CompInfo.Name |`
 Export-Csv -path c:\temp\Server_Inventory_$((Get-Date).ToString('MM-dd-yyyy')).csv -NoTypeInformation -Encoding UTF8 #Export the results in csv file.
     }
    End
    {
    }
}
Get-RemoteHardwareSoftwareInfo