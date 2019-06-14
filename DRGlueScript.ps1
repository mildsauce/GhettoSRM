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