Function Install-VMDisasterRecovery {

    Param
    (
        [Parameter(Mandatory, Position=1)]
        [String]$ComputerName,
        [Parameter(Mandatory,Position=2)]
        [String]$SourceFiles
    )

    if (!(Test-WSMan $ComputerName -Authentication Kerberos -ErrorAction SilentlyContinue)) { 

        Write-Host "Cannot connect to server $ComputerName using PS Remoting. Exiting..." -ForegroundColor Red
        return
        
    }

    $osver = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName | Select-Object Version

    if ($osver -notmatch '10.0|6.1|6.3') {

        Write-Host "Operating system of $ComputerName is not supported. Exiting..." -ForegroundColor Red
        return

    }
    
    #ToDo: Use the text blocks in the script file/module instead of seperate files
    
    $glue_script = 'DRGlueScript.ps1'
    
    $sch_task1216 = 'DRGlueScript1216.xml'

    $sch_task08 = 'DRGlueScript08.xml'    
    
    $dr_dir = 'C:\DR'

    $session = New-PSSession -ComputerName $ComputerName

    # Create the DR directory if it does not exist

    Write-Progress -Activity "Installing Disaster Recovery Glue Script..." -Status "Creating DR directory..." -PercentComplete 25

    Invoke-Command -Session $session -ScriptBlock {

        if (!(Test-Path $args[0])) { 
                        
            New-Item $args[0] -ItemType Directory | Out-Null
                  
        }   
        
        $acl = Get-ACL $args[0]

        $acl.SetAccessRuleProtection($true,$true)

        $acl.Access | Foreach-Object { if ($_.IdentityReference.Value -like '*\Users') { $acl.RemoveAccessRule($_) }} | Out-Null

        Set-ACL -Path $args[0] -AclObject $acl  

    } -ArgumentList @($dr_dir)

    # Copy the script and XML file to the target machine

    Write-Progress -Activity "Installing Disaster Recovery Glue Script..." -Status "Copying files..." -PercentComplete 50

    try {

        Copy-Item (Join-Path $src_files $glue_script) -ToSession $session -Destination $dr_dir

        Copy-Item (Join-Path $src_files $sch_task1216) -ToSession $session -Destination $dr_dir

        Copy-Item (Join-Path $src_files $sch_task08) -ToSession $session -Destination $dr_dir

        # Register the scheduled task using the XML file    

        Write-Progress -Activity "Installing Disaster Recovery Glue Script..." -Status "Registering scheduled task..." -PercentComplete 75

        Invoke-Command -Session $session -ScriptBlock { 

            $os_ver = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version

            # OS is 2008R2 which does not have PowerShell cmdlets for scheduled tasks, use schtasks.exe instead
            if ($os_ver -like "6.1.*") {

                Start-Process schtasks.exe -ArgumentList @('/Create', '/XML', $args[0],'/tn "DR Glue Script"') -Wait

            }  else {

                if (Get-ScheduledTask -TaskName "DR Glue Script" -ErrorAction SilentlyContinue) {

                    Unregister-ScheduledTask -TaskName "DR Glue Script" -Confirm:$false

                }

                $xml = Get-Content $args[1] | Out-String

                Register-ScheduledTask -TaskName "DR Glue Script" -Xml $xml | Out-Null

            }     

            Write-Progress -Activity "Installing Disaster Recovery Glue Script..." -Status "Cleaning up..." -PercentComplete 95
            # Delete the XML files used to register the scheduled task

            Remove-Item $args[0]
            Remove-Item $args[1]

            
        } -ArgumentList @((Join-Path $dr_dir $sch_task08),(Join-Path $dr_dir $sch_task1216))

    } catch {
        
        Write-Host "Failed to register scheduled task on $ComputerName"
        Write-Error "Failed to register scheduled task on $ComputerName"

    }

    # Session cleanup 
    
    Remove-PSSession -Session $session

}

Function Check-VMDRConfig {

    Param
    (
        [String]$vCenterServerName,
        [String]$ToEmail,
        [String]$FromEmail,
        [String]$SmtpServer

    )

    Import-Module VMware.PowerCLI

    Write-Host "Connecting to vCenter..." -ForegroundColor Yellow

    try {

        Connect-VIserver $vCenterServerName

    } catch {

        Write-Host "Failure connecting to vCenter" -ForegroundColor Red
        Write-Error "Failure connecting to vCenter"
        return
    }
    


    [string]$notconfigured = Get-VM | Where-Object ExtensionData.Config.ExtraConfig.Key -notcontains 'hbr_filter.gid' | 
                                        Select-Object Name | Sort-Object Name | ConvertTo-Html


    Send-MailMessage -Subject "vSphere Servers Not Configured for DR Replication" `
                     -SmtpServer $SmtpServer `
                     -From $FromEmail `
                     -To $ToEmail `
                     -BodyAsHtml `
                     -Body $notconfigured

}

function Export-SourceVMConfigs {

Param
(
    [String]$vCenterName

)

Import-Module VMware.PowerCLI

$XMLConfig = '.\VMConfigs.xml'

Connect-VIServer -Server $vCenterName | Out-Null

# Find virtual machines which are being replicated using vSphere replication
$ReplicatedVMs = Get-VM | Get-AdvancedSetting -Name hbr_filter.gid | Select-Object -ExpandProperty Entity

$VMInfo = Get-VM $ReplicatedVMs | Foreach-Object { 

    $GuestInfo = Get-VMGuest $_.Name

    $IPv4Address = $GuestInfo.IPAddress

    $EfiAdvSetting = $_ | Get-AdvancedSetting -Name firmware

    if ($EfiAdvSetting.Value -eq 'efi') {

        $EfiEnabled = $true

    } else {
        
        $EfiEnabled = $false

    }
    
    $obj = New-Object PSCustomObject -Property @{
                                                    Name = $_.Name
                                                    IPAddress = $IPv4Address
                                                    OSVersion = $GuestInfo.ConfiguredGuestId
                                                    NumCpu = $_.NumCpu
                                                    CoresPerSocket = $_.CoresPerSocket
                                                    MemoryMB = $_.MemoryMB
                                                    EfiEnabled = $EfiEnabled  
                                                }

    return $obj
}

$VMInfo | Export-Clixml -Path $XMLConfig

Disconnect-VIServer -Confirm:$false
Remove-PSDrive -Name * -PSProvider VimInventory
Remove-Module VMware.*

}

Function Import-SourceVMsToDRSite {

    [cmdletbinding()]
    Param 
    (
     [Parameter(Mandatory)]
     [String]$vCenterName,
     [Parameter(Mandatory)]     
     [String]$vSANDataStore,
     # Example: VxRail-Virtual-SAN-Datastore-********-*******
     [Parameter(Mandatory)]
     [String]$ResourcePool,
     [Parameter(Mandatory)]
     [String]$VMNetworkName,
     [Parameter(Mandatory)]
     [String]$DRDefaultGateway,
     [Parameter(Mandatory)]
     [String]$DRDNSServers,
     [Parameter(Mandatory)]
     [String]$VMXMLConfig,
     # Currently must be /24, logic is terrible
     [Parameter(Mandatory)]     
     [String]$DRSubnet
    )

    Write-Progress -Activity 'Importing Virtual Machines...' -CurrentOperation 'Importing PowerCLI Module...'

    Import-Module VMware.PowerCLI

    ## Variables for reconfiguring virtual machines at your DR site
    $VMXMLConfig = '.\VMConfigs.xml'

    Write-Progress -Activity 'Importing Virtual Machines...' -CurrentOperation 'Connecting to DR vCenter'

    Connect-VIServer $vCenterName | Out-Null

    $VMInfo = Import-Clixml -Path $VMXMLConfig

    Write-Progress -Activity 'Importing Virtual Machines...' -CurrentOperation 'Creating virtual machines'

    $VMInfo | Foreach-Object {

        Write-Progress -Activity 'Importing Virtual Machines...' -CurrentOperation ('Creating virtual machine: ' + $_.Name)
 
        $DSPath = '[' + $vSANDataStore + '] ' + $_.Name 

        # Find the vmdks on the vSAN datastore
        $VirtualDisks = Get-Harddisk -Datastore $vSANDataStore -DatastorePath $DSPath | Where-Object Filename -notlike "*hbrdisk*"


        $NewVM = New-VM -Name $_.Name `
                        -ResourcePool $ResourcePool `
                        -DiskPath $VirtualDisks.Filename `
                        -Portgroup $VMNetworkName `
                        -NumCpu $_.NumCpu `
                        -MemoryMB $_.MemoryMB `
                        -CoresPerSocket $_.CoresPerSocket `
                        -GuestId $_.OSVersion   
         
        # Configure the system for EFI boot and Secure Boot if needed
        if ($_.EfiEnabled) {

            $NewVM | New-AdvancedSetting -Name firmware -Value 'efi' -Confirm:$false | Out-Null

            $NewVM | New-AdvancedSetting -Name uefi.secureboot.enabled -Value 'TRUE' -Confirm:$false | Out-Null
        }
    
        Write-Progress -Activity 'Importing Virtual Machines...' -CurrentOperation ('Configuring network settings for VM: ' + $_.Name)

        $NewIPAddress = $_.IPAddress -replace '\d?\d?\d\.\d?\d?\d\.\d?\d?\d\.', ($DRSubnet -split '\.')[1..3]

        # Configures the OVF environment transport to use VMware tools
        # https://code.vmware.com/forums/2530/vsphere-powercli#575077
        $ovfenvspec = New-Object VMware.Vim.VirtualMachineConfigSpec

        $ovfenvspec.VAppConfig = New-Object VMware.Vim.VmConfigSpec

        $ovfenvspec.VAppConfig.OvfEnvironmentTransport = @('com.vmware.guestInfo')
    
        $ovfenvspec.VAppConfig.Property = New-Object VMware.Vim.VAppPropertySpec[] (5)
    
        # Configures the OVF environment with network data
        # https://communities.vmware.com/thread/471448 

        # Configures IPv4 Address
        $ovfenvspec.VAppConfig.Property[0] = New-Object VMware.Vim.VAppPropertySpec
        $ovfenvspec.VAppConfig.Property[0].Operation = 'add'
        $ovfenvspec.VAppConfig.Property[0].info = New-Object VMware.Vim.VAppPropertyInfo
        $ovfenvspec.VAppConfig.Property[0].info.key = 0
        $ovfenvspec.VAppConfig.Property[0].info.Id = 'ip:0'
        $ovfenvspec.VAppConfig.Property[0].info.Label = 'ip:0'
        $ovfenvspec.VAppConfig.Property[0].info.Category = 'IPInfo'    
        $ovfenvspec.VAppConfig.Property[0].info.Type = 'string'
        $ovfenvspec.VAppConfig.Property[0].info.UserConfigurable = $true
        $ovfenvspec.VAppConfig.Property[0].info.DefaultValue = $NewIPAddress
        $ovfenvspec.VAppConfig.Property[0].info.DefaultValue = $NewIPAddress 

        #Configures subnet mask
        $ovfenvspec.VAppConfig.Property[1] = New-Object VMware.Vim.VAppPropertySpec
        $ovfenvspec.VAppConfig.Property[1].Operation = 'add'
        $ovfenvspec.VAppConfig.Property[1].info = New-Object VMware.Vim.VAppPropertyInfo
        $ovfenvspec.VAppConfig.Property[1].info.key = 1
        $ovfenvspec.VAppConfig.Property[1].info.Id = 'subnetMask:0'
        $ovfenvspec.VAppConfig.Property[1].info.Category = 'IPInfo'
        $ovfenvspec.VAppConfig.Property[1].info.Label = 'subnetMask:0'
        $ovfenvspec.VAppConfig.Property[1].info.Type = 'string'
        $ovfenvspec.VAppConfig.Property[1].info.UserConfigurable = $true
        $ovfenvspec.VAppConfig.Property[1].info.DefaultValue = '255.255.255.0'
        $ovfenvspec.VAppConfig.Property[1].info.DefaultValue = '255.255.255.0' 

        # Configures default gateway

        $ovfenvspec.VAppConfig.Property[2] = New-Object VMware.Vim.VAppPropertySpec
        $ovfenvspec.VAppConfig.Property[2].Operation = 'add'
        $ovfenvspec.VAppConfig.Property[2].info = New-Object VMware.Vim.VAppPropertyInfo
        $ovfenvspec.VAppConfig.Property[2].info.key = 2
        $ovfenvspec.VAppConfig.Property[2].info.Id = 'gateways:0'
        $ovfenvspec.VAppConfig.Property[2].info.Category = 'IPInfo'
        $ovfenvspec.VAppConfig.Property[2].info.Label = 'gateways:0'
        $ovfenvspec.VAppConfig.Property[2].info.Type = 'string'
        $ovfenvspec.VAppConfig.Property[2].info.UserConfigurable = $true
        $ovfenvspec.VAppConfig.Property[2].info.DefaultValue = $CBDefaultGateway
        $ovfenvspec.VAppConfig.Property[2].info.DefaultValue = $CBDefaultGateway

        # Configures DNS servers
        $ovfenvspec.VAppConfig.Property[3] = New-Object VMware.Vim.VAppPropertySpec
        $ovfenvspec.VAppConfig.Property[3].Operation = 'add'
        $ovfenvspec.VAppConfig.Property[3].info = New-Object VMware.Vim.VAppPropertyInfo
        $ovfenvspec.VAppConfig.Property[3].info.key = 3
        $ovfenvspec.VAppConfig.Property[3].info.Id = 'dnsServers:0'
        $ovfenvspec.VAppConfig.Property[3].info.Category = 'IPInfo'
        $ovfenvspec.VAppConfig.Property[3].info.Label = 'dnsServers:0'
        $ovfenvspec.VAppConfig.Property[3].info.Type = 'string'
        $ovfenvspec.VAppConfig.Property[3].info.UserConfigurable = $true
        $ovfenvspec.VAppConfig.Property[3].info.DefaultValue = $CBDNSServers
        $ovfenvspec.VAppConfig.Property[3].info.DefaultValue = $CBDNSServers


        $NewVM.ExtensionData.ReconfigVM($ovfenvspec)

    }

    Write-Progress -Activity 'Cleaning up environment'

    Disconnect-VIServer -Confirm:$false
    Remove-PSDrive -Name * -PSProvider VimInventory
    Remove-Module VMware.*


}

Function Start-ImportedVMsatDRSite {

    Param
    (
      [String]$vCenterName


    )

    Import-Module VMware.PowerCLI

    $VMXMLConfig = '.\VMConfigs.xml'

    Connect-VIServer $vCenterName

    $VMs = Import-Clixml $VMXMLConfig # You may want to filter what machines get imported here on properties

    <#

      
      Write-Host ("WARNING: You are about to start "  + [string]$VMs.Count  + " virtual machines on the DR vCenter.") -ForegroundColor Red
      Write-Host "This will interupt network connectivity to the production systems once dynamic DNS is updated" -ForegroundColor Red
      Write-Host "It will also require a full sync of the systems via vSphere Replication" -ForegroundColor Red
      Write-Host "Are you sure you want to start the virtual machines?" -ForegroundColor Red    
    #>


    $validresponses = @('yes', 'no')

    while ($WarningResponse -notin $validresponses) {

        $WarningResponse = Read-Host "Please enter yes or no"

    }

    if ($WarningResponse -eq 'no') {

        return

    }

    Write-Host "Starting Imported Virtual Machines!" -ForegroundColor Green


    Start-VM $VMs.Name -RunAsync


}

$GlueScript = @'
$input_file = 'ovfenv.txt'

# Write VMware Tools guest network information to a file

Start-Process 'C:\Program Files\VMware\VMware Tools\vmtoolsd.exe' -ArgumentList @('--cmd', '"info-get guestinfo.ovfEnv"') -RedirectStandardOutput $input_file -Wait

# Read XML from file

[xml]$config = Get-Content $input_file

# Perform configuration only if there is guest information in the config file

if ($config) { 

    # Assign guest information to variables

    $config.Environment.PropertySection.Property | ForEach-Object { 
        
        if ($_.key -eq 'ip:0') { $ip = $_.value } 

        if ($_.key -eq 'gateways:0') { $gateway = $_.value } 

        if ($_.key -eq 'dnsServers:0') { $dns_servers = $_.value } 

    }

    # Determine if we are on Server 2012R2+ or Server 2008R2 which requires us to use netsh instead of PowerShell to configure network adapters

    $os_ver = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version

    # Configure network adapter with IP address, subnet mask and default gateway retrieved from vmtoolsd

    if ($os_ver -like '6.1.*') {
    # OS is Server 2008R2

        # Find Ethernet network adapters

        $connection_name = Get-CimInstance Win32_NetworkAdapter -Filter "AdapterType = 'Ethernet 802.3'" | Select-Object -ExpandProperty NetConnectionID

        $connection_name = '"' + $connection_name + '"'

        Start-Process 'netsh.exe' -ArgumentList @( "interface ip set address name=$connection_name static addr=$ip mask=255.255.255.0 gateway=$gateway" )

        Start-Process 'netsh.exe' -ArgumentList @( "interface ip set dns $connection_name static $dns_servers")

    } else {
    # OS is Server2012R2+
        
        Get-NetIPAddress -InterfaceAlias Ethernet0 | Remove-NetIPAddress -Confirm:$false

        New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress $ip -PrefixLength 24

        Get-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias Ethernet0 | Remove-NetRoute -Confirm:$false

        New-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias Ethernet0 -NextHop $gateway

        Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses $dns_servers
    }    
}

Remove-Item $input_file -Force -ErrorAction SilentlyContinue
'@


$GlueScriptTask08 = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>201717-11-21T10:27:01.0859606</Date>
    <Author>NT AUTHORITY\SYSTEM</Author>
    <URI>\DR Glue Script</URI>
    <SecurityDescriptor></SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>false</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions>
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-F DRGlueScript.ps1</Arguments>
      <WorkingDirectory>C:\DR</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
'@

$GlueScriptTask1216 = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2017-11-21T10:27:01.0859606</Date>
    <Author>DOMAIN\user</Author>
    <URI>\DR Glue Script</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <BootTrigger />
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-F DRGlueScript.ps1</Arguments>
      <WorkingDirectory>C:\DR</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
'@


<# Example XML of VM config file
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCustomObject</T>
      <T>System.Object</T>
    </TN>
    <MS>
      <I32 N="NumCpu">2</I32>
      <S N="Name">SERVERNAME</S>
      <S N="OSVersion">windows9Server64Guest</S>
      <I32 N="CoresPerSocket">1</I32>
      <S N="IPAddress">10.10.10.10</S>
      <B N="EfiEnabled">true</B>
      <D N="MemoryMB">4096</D>
    </MS>
  </Obj>
</Objs>
#>