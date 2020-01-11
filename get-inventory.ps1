<#
.Synopsis
   Данный скрипт позволяет опросить сервера в AD и получить их физические и логические параметры
.DESCRIPTION
   Скрипт в качестве входных параметров принимает OU в которой будет происходить поиск, а также фильтр для включения и/или исключения перечня серверов для опроса
    их характеристкик. Значения, которые возвращает скрипт: 
    ServerName	- DNS имя сервера
    Processor - модель процессора, например, Intel(R) Core(TM) i5-2410M CPU @ 2.30GHz или Intel(R) Xeon(R) CPU E5-2697 v3 @ 2.60GHz
	Manufacturer - производитель сервера, например Hewlett-Packard, VMware, Inc.
	PhysicalCores - количество физических процессоров
	LogicalCores - количество ядер у процессора	
    OS_Name	- название операционной системы, например, Майкрософт Windows 10 Корпоративная, Microsoft Windows Server 2012 R2 Standard
    OS_Version	- версия операционной системы, например 10.0.17134, 06.03.9600
    TotalPhysical_Memory_GB	- количество физической памяти установленной в системе
    TotalVirtual_Memory_MB - количество виртуальной памяти установленной в системе
    VolumeName_D	VolumeName_C - названия дисков, установленных в ОС	
    IPAddr_3	IPSubnet_3	
    IPAddr_2	IPSubnet_2	
    IPAddr_1	IPSubnet_1 - для каждого IP адреса найденного при опросе, выдается его значение и подсеть


.EXAMPLE
   Пример использования этого командлета
.EXAMPLE
   Еще один пример использования этого командлета
.INPUTS
   Входные данные в этот командлет (при наличии)
.OUTPUTS
   Вся выходная информация записывается в сcsv файл c:\temp\Server_Inventory_дата в формате 'dd-MM-yyyy'
.NOTES
   В Укртелекоме удаленный доступ к серверам разрешен только под учетными записями, которые начинаются с adm- скрипт это проверяет, и если учетная запись пользователя 
   который запустил скрипт не содержит adm-... то запрашиваются учетные данные под которыми будет происходить опрос серверов. 
   Сервера должны находится в как и компьютер, который их опрашивает. Иначе опрос не произойдет. Это ограничение (когда опрашивающий и опрашиваемые компьютеры находятся 
   в разных доменах, можно обойти, но данная задача не решается этим скриптом, т.к. параметры доступа должны настраиваться вне этого скрипта.  
   Если пользователь не является членом группы доменных администраторов, то он должен входить в группу локальных администраторов каждого компьютера, который необходимо 
   опросить. 
.COMPONENT
   Компонент, к которому принадлежит этот командлет
.ROLE
   Роль, к которой принадлежит этот командлет
.FUNCTIONALITY
   Опросить удаленные компьютеры, получить информацию о hardware & OS установленных на этих компьютерах. Изменения на удаленные компьютеры не вносятся. 
#>
function Get-RemoteHardwareSoftwareInfo
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.microsoft.com/',
                  ConfirmImpact='Low')] #только опрашиваем, поэтому влияние отсутствует (минимально).
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Путь к OU В котором будет происходить поиск серверов для опроса 
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position = 0,
                   ParameterSetName='Search will be in specified OU in AD')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        #[ValidateCount(0,5)]
        #[ValidateSet("sun", "moon", "earth")]
        [String]
        #$SearchBaseAD= "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc",
        $SearchBaseAD= 'OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc',

        # Маска для поиска серверов, также можно добавить сервера, которые необходимо исключить из опроса
        [Parameter(ParameterSetName='Servers Filter Set')]
        Position = 1,
		#$ServersFilter = "{ OperatingSystem -Like `"*Windows Server*`" -and dnshostname -like `"kv-crm*`"}"
        $ServersFilter = "OperatingSystem`
            -like '*Windows Server*'` 
            -and (dnshostname -like 'kv-crm*'`
            -and  dnshostname -notlike 'kv-crmadm*'`
            -and  dnshostname -notlike 'kv-crmtst*'` 
            -and  dnshostname -notlike 'kv-crmprp*')",
        # Маска для поиска серверов, также можно добавить сервера, которые необходимо исключить из опроса
        [Parameter(ParameterSetName='Servers Filter Set')]
        $OutputCsvFile="c:\temp\Server_Inventory_$((Get-Date).ToString('dd-MM-yyyy')).csv"
    )

    Begin
    {
    #[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US';
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
    try { $servers = (Get-ADComputer -Credential $Cred -SearchBase $SearchBaseAD -Filter $ServersFilter).name }
    catch  {
            Write-Host "Can't contact AD to get list of servers in OU" -ForegroundColor Yellow
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit
            }
    }
    else 
    {
    try { $servers = (Get-ADComputer -SearchBase $SearchBaseAD -Filter $ServersFilter).name }
    catch   {
            Write-Host "Can't contact AD to get list of servers in OU" -ForegroundColor Yellow
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit
            }
    #$servers = (Get-ADComputer -SearchBase "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc" -Filter { OperatingSystem -Like "*Windows Server*" -and dnshostname -like "kv-crmapp*" }).name    
    }
    #$servers = (Get-ADComputer -SearchBase $SearchBaseAD -Filter $ServersFilter).name
    #Get-ADComputer -Filter "Name -like ""$PartialName""" | select -ExpandProperty Name
    #$servers = (Get-ADComputer -SearchBase "OU=CRMBilling,OU=Servers,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc" -Filter ($ServersFilter)).name
    #$servers+="kv-ho-shk2-n058" #.corp.ukrtelecom.loc"
    $servers+="HO-SHK2-N084" #Adding computers just for script test
    $servers+="HO-SHK2-N033" #Adding computers just for script test

    $infoObject	= ""  
    $PSObject	= ""
    $xxx		= 0
    }
    
	Process
    {
    Invoke-Command -ComputerName $servers -ScriptBlock {
            $CPUInfo				= Get-WmiObject -class Win32_Processor            #Get CPU Information
	        $OSInfo					= Get-WmiObject -class Win32_OperatingSystem      #Get OS Information
	        $CompInfo				= Get-WmiObject -class Win32_ComputerSystem
            #Get Memory Information. The data will be shown in a table as MB, rounded to the nearest second decimal.
	        $OSTotalVirtualMemory	= [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
	        $OSTotalVisibleMemory	= [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
	        $PhysicalMemory			= Get-WmiObject CIM_PhysicalMemory | Measure-Object -Property capacity -Sum | % { [Math]::Round(($_.sum / 1GB), 2) }
            $VolumeTemp				= Get-CimInstance Win32_LogicalDisk -Filter drivetype=3
            $IPAddressName			= Get-NetIPAddress  -AddressFamily IPv4 | where { $PSItem.InterfaceAlias -notmatch 'Loopback'} | Select IPAddress
            $IPSubNetName			= (Get-WmiObject Win32_NetworkAdapterConfiguration | Where IPEnabled | Select IPSubnet).IPSubnet
			#$nwINFO				= Get-WmiObject Win32_NetworkAdapterConfiguration
    $infoObject = New-Object PSObject
    if (($CPUInfo.Name).count -ge 2) {$CPUInfoName=$CPUInfo.Name[0]}
        else { $CPUInfoName=$CPUInfo.Name } 
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "ServerName"					-value $CompInfo.Name
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Processor"					-value $CPUInfoName
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer"				-value $CompInfo.Manufacturer
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "PhysicalCores"				-value $CompInfo.NumberOfProcessors
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "LogicalCores"				-value $CompInfo.NumberOfLogicalProcessors
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Name"					-value $OSInfo.Caption
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS_Version"					-value $OSInfo.Version
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalPhysical_Memory_GB"	-value $PhysicalMemory
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVirtual_Memory_MB"		-value $OSTotalVirtualMemory
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Model"						-value $CPUInfo.Caption
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "PhysicalCores"				-value $CPUInfo.NumberOfCores
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L2CacheSize"			-value $CPUInfo.L2CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L3CacheSize"			-value $CPUInfo.L3CacheSize
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Sockets"					-value $CPUInfo.SocketDesignation
		
        $VolumeSize	= $VolumeTemp | % { [Math]::Round(($PSItem.Size / 1GB), 2)}
        $VolumeName	= ($VolumeTemp).Name

        $xxx=$VolumeName.Count
        While ($xxx -ge 1)
        {
        $NameVol=$VolumeName[$xxx-1][0]
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "VolumeName_$NameVol"	-Value $VolumeSize[$xxx-1]
        #Test
        #Add-Member -inputObject $infoObject -memberType NoteProperty -name "VolumeName_D" -Value $VolumeSize[$xxx-1]
        $xxx-=1; 
        }
        
        [String[]]$IPAddr=($IPAddressName).IPAddress
        #Test
        #$IPAddr+="172.20.1.0"
        #$IPaddr+="172.20.1.1"
        #$IPAddr+="172.20.1.2"
        $xxx=$IPAddr.Count
        if ($xxx -gt 1) {
        While ($xxx -ge 1) {
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "IPAddr_$xxx"	-Value $IPAddr[$xxx-1]
        # !! Надо проверить дополнительно, на адресах, у которых маска не /24 !!
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "IPSubnet_$xxx"	-Value $IPSubNetName[0]
        $xxx-=1;           }
                        }
        else {
        #$IPAddr=($IPAddressName).IPAddress
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "IPAddr_$xxx" 	-Value $IPAddr 
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "IPSubnet_$xxx"	-Value $IPSubNetName[0]
        }   
        $infoObject #Output to the screen for a visual feedback.
	} | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | sort servername | `
 Export-Csv -path $OutputCsvFile -NoTypeInformation -Encoding UTF8 #Export the results in csv file.
     }
    End
    {
    }
}
Get-RemoteHardwareSoftwareInfo