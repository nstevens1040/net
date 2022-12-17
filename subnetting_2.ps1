if([Security.Principal.WindowsPrincipal]::New([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    write-host "ipconfig /release" -ForegroundColor Yellow -NoNewline
    (0..(24 - "ipconfig /release".Length)).ForEach({ write-host " " -NoNewline})
    $release = cmd /c "ipconfig /release 2>&1"
    write-host "done!" -ForegroundColor Green
    write-host "ipconfig /renew" -ForegroundColor Yellow -NoNewline
    (0..(24 - "ipconfig /renew".Length)).ForEach({ write-host " " -NoNewline})
    $renew = cmd /c "ipconfig /renew 2>&1"
    write-host "done!" -ForegroundColor Green
    write-host "ipconfig /flushdns" -ForegroundColor Yellow -NoNewline
    (0..(24 - "ipconfig /flushdns".Length)).ForEach({ write-host " " -NoNewline})
    $flusdns = cmd /c "ipconfig /flushdns 2>&1"
    write-host "done!" -ForegroundColor Green
    write-host "ipconfig /registerdns" -ForegroundColor Yellow -NoNewline
    (0..(24 - "ipconfig /registerdns".Length)).ForEach({ write-host " " -NoNewline})
    $registerdns = cmd /c "ipconfig /registerdns 2>&1"
    write-host "done!" -ForegroundColor Green
    Add-Type -TypeDefinition "namespace MyNetwork`n{`n    using System;`n    using System.Collections.Generic;`n    public class Info`n    {`n        public string IPAddress { get; set; }`n        public string DNSResult { get; set; }`n        public string MACAddress { get; set; }`n        public Info()`n        {`n        }`n    }`n}"
    # retrieve this device's ipv4 address, the current default gateway, this subnet's prefix length, and calculate the number of possible hosts
    Get-NetIPConfiguration -ifIndex (Get-NetIPInterface | sort InterfaceMetric | ? {
        $_.ConnectionState -eq 'Connected' -and `
        $_.AddressFamily -eq 'IPv4' -and `
        $_.InterfaceAlias -notmatch 'loopback'
    } | % ifIndex) | select IPv4Address,IPv4DefaultGateway |% {
        $ipv4 = $_ | % ipv4Address |% ipAddress
        $gateway = $_ |% IPv4DefaultGateway |% nexthop
        $cidr = $_ | % ipv4Address |% PrefixLength
        $possible_hosts = [math]::Pow(2,(32 - $cidr)) - 2
    }
    
    [System.Net.Dns]::GetHostByAddress($ipv4)
    # create a list of key value pairs where keys are the decimal octets in this device's ip address and values are their corresponding binary representation
    $d = [System.Collections.Generic.List[System.Collections.Generic.Dictionary[[int32],[string]]]]::new()
    $ipv4.Split('.').ForEach({
        $dict = [System.Collections.Generic.Dictionary[[int32],[string]]]::new()
        $dict.Add(
            [int32]::Parse($_),
            [Int32]::Parse(
                [convert]::ToString([int32]::Parse($_),2)
            ).ToString("00000000")
        )
        $d.Add($dict)
    })
    # create a list of key value pairs where keys are this network's subnet mask decimal octets and values are their corresponding binary representation
    $bin_str = [String]::Empty
    for($i = 0; $i -lt 32; $i++)
    {
        if($i -lt $cidr)
        {
            $bin_str = "$($bin_str)1"
        } else {
            $bin_str = "$($bin_str)0"
        }
    }
    $mask = [System.Collections.Generic.List[System.Collections.Generic.Dictionary[[Int32],[string]]]]::New()
    [regex]::new("([0-9]{8})").Matches($bin_str) |% Value |% {
        $m = [System.Collections.Generic.Dictionary[[Int32],[string]]]::New()
        $m.Add([Convert]::ToInt32($_,2),$_)
        $mask.Add($m)
    }
    # perform bitwise AND operation between the local IP and the subnet mask to calculate the first ip address in the subnet
    $first_ip_octets = @()
    for($i = 0; $i -lt $d.Count; $i++)
    {
        $first_ip_octets+= [Convert]::ToInt32("$($d[$i][$d[$i].Keys])",2) -band [Convert]::ToInt32("$($mask[$i][$mask[$i].Keys])",2)
    }
    $ip_range_start = $first_ip_octets -join '.'
    
    # create a list of key value pairs where keys are the decimal octets in this subnet's first ip address and values are their corresponding binary representation
    $f = [System.Collections.Generic.List[System.Collections.Generic.Dictionary[[int32],[string]]]]::new()
    $first_ip_octets.ForEach({
        $dict = [System.Collections.Generic.Dictionary[[int32],[string]]]::new()
        $dict.Add(
            [int32]::Parse($_),
            [Int32]::Parse(
                [convert]::ToString([int32]::Parse($_),2)
            ).ToString("00000000")
        )
        $f.Add($dict)
    })
    # take the binary representation of the subnet mask, switch the 1s to 0s and the 0s to 1s
    $inv_str = ""
    $bin_str.ToCharArray().Foreach({
        switch($_)
        {
            1 { $inv_str = "$($inv_str)0" }
            0 { $inv_str = "$($inv_str)1" }
        }
    })
    # create a list of key value pairs where the keys are the subnet mask's inverse's decimal octets and the values are their corresponding binary representation
    $mask_inverse = [System.Collections.Generic.List[System.Collections.Generic.Dictionary[[Int32],[string]]]]::New()
    [regex]::new("([0-9]{8})").Matches($inv_str) |% Value |% {
        $m = [System.Collections.Generic.Dictionary[[Int32],[string]]]::New()
        $m.Add([Convert]::ToInt32($_,2),$_)
        $mask_inverse.Add($m)
    }
    # calculate the last ip address in the subnet by performing a bitwise OR operation between the first IP address and the binary inverse of the subnet mask
    $last_ip_octets = @()
    for($i = 0; $i -lt $f.Count; $i++)
    {
        $last_ip_octets+= [Convert]::ToInt32("$($f[$i][$f[$i].Keys])",2) -bor [Convert]::ToInt32("$($mask_inverse[$i][$mask_inverse[$i].Keys])",2)
    }
    $ip_range_end = $last_ip_octets -join '.'
    Clear-host
    [console]::SetCursorPosition(
        [console]::CursorLeft,
        8
    )
    write-host "this device ipv4:" -ForegroundColor Green -NoNewline
    (0..(50 - "this device ipv4:".Length)).ForEach({ write-host " " -NoNewline})
    Write-Host $ipv4 -ForegroundColor Yellow
    write-host "this network's default gateway:" -ForegroundColor Green -NoNewline
    (0..(50 - "this network's default gateway:".Length)).ForEach({ write-host " " -NoNewline})
    Write-Host $gateway -ForegroundColor Yellow
    write-host "this subnet's prefix length:" -ForegroundColor Green -NoNewline
    (0..(50 - "this subnet's prefix length:".Length)).ForEach({ write-host " " -NoNewline})
    Write-Host $cidr -ForegroundColor Yellow
    write-host "this subnet's number of possible ip addresses:" -ForegroundColor Green -NoNewline
    (0..(50 - "this subnet's number of possible ip addresses:".Length)).ForEach({ write-host " " -NoNewline})
    Write-Host $possible_hosts -ForegroundColor Yellow
    write-host "this subnet's first ip address:" -ForegroundColor Green -NoNewline
    (0..(50 - "this subnet's first ip address:".Length)).ForEach({ write-host " " -NoNewline})
    Write-Host $ip_range_start -ForegroundColor Yellow
    write-host "this subnet's last ip address:" -ForegroundColor Green -NoNewline
    (0..(50 - "this subnet's last ip address:".Length)).ForEach({ write-host " " -NoNewline})
    Write-Host $ip_range_end -ForegroundColor Yellow
    
    # create a list of all of the assignable IP addresses between the first and the last
    $host_net_bool = @()
    for($i = 0; $i -lt $last_ip_octets.Count; $i++)
    {
        $host_net_bool += $last_ip_octets[$i] -eq $first_ip_octets[$i]
    }
    $assignable_ip_addresses = [System.Collections.Generic.List[string]]::new()
    switch($host_net_bool.Where({!$_}).Count)
    {
        1 {
            $start_host_4th = $first_ip_octets[-1] + 1
            $last_host_4th = $last_ip_octets[-1]
            $network = [string]::Join('.',$first_ip_octets[0..2])
            for($i = $start_host_4th; $i -lt $last_host_4th; $i++)
            {
                $assignable_ip_addresses.Add("$($network).$($i)")
            }
        }
        2 {
            $start_host_3rd = $first_ip_octets[-2]
            $start_host_4th = $first_ip_octets[-1] + 1
            $last_host_3rd = $last_ip_octets[-2]
            $last_host_4th= $last_ip_octets[-1]
            $network = [string]::Join('.',$first_ip_octets[0..1])
            for($i = $start_host_3rd; $i -lt $last_host_3rd; $i++)
            {
                for($a = $start_host_4th; $a -lt $last_host_4th; $a++)
                {
                    $assignable_ip_addresses.Add("$($network).$($i).$($a)")
                }
            }
        }
        3 {
            $start_host_2nd = $first_ip_octets[-3]
            $start_host_3rd = $first_ip_octets[-2]
            $start_host_4th = $first_ip_octets[-1] + 1
            $last_host_2nd = $last_ip_octets[-3]
            $last_host_3rd = $last_ip_octets[-2]
            $last_host_4th= $last_ip_octets[-1]
            $network = $first_ip_octets[0]
            for($i = $start_host_2nd; $i -lt $last_host_2nd; $i++)
            {
                for($a = $start_host_3rd; $a -lt $last_host_3rd; $a++)
                {
                    for($z = $start_host_4th; $z -lt $last_host_4th; $z++)
                    {
                        $assignable_ip_addresses.Add("$($network).$($i).$($a).$($z)")
                    }
                }
            }
        }
    }
    
    $net_info = [System.Collections.Generic.List[MyNetwork.Info]]::new()
    for($i = 0; $i -lt $assignable_ip_addresses.Count; $i++)
    {
        $ip = $assignable_ip_addresses[$i]
        $device = [MyNetwork.Info]@{IPAddress=$ip}
        if((Test-Connection -ComputerName $ip -Count 1 -Quiet -ea 0))
        {
            $dns_ = $null
            try
            {
                $dns_ =  [System.Net.Dns]::GetHostByAddress($ip)
            }
            catch
            {
                try
                {
                    $dns_ =  [System.Net.Dns]::GetHostByAddress($ip)
                }
                catch
                {
                    $device.DNSResult = "In use without hostname"
                }
            }
            if(![string]::IsNullOrEmpty($dns_.HostName))
            {
                $device.DNSResult = $dns_.HostName
            }
        } else {
            $device.DNSResult = "IP is unassigned"
        }
        $net_info.Add($device)
        if($i -gt 0)
        {
            Write-Progress -PercentComplete ($i / $assignable_ip_addresses.Count *100) -Status "$(($i / $assignable_ip_addresses.Count *100).ToString("00.00"))%" -Activity "pinging $($ip)"
        }
    }
    
    @($net_info).Where({$_.IPAddress -eq $ipv4})[0].MACAddress = @(Get-NetAdapter -ifAlias @(Get-NetIPInterface | sort InterfaceMetric | ? {
        $_.ConnectionState -eq 'Connected' -and `
        $_.AddressFamily -eq 'IPv4' -and `
        $_.InterfaceAlias -notmatch 'loopback'
    })[0].InterfaceAlias)[0].MACAddress
    $mac_reg = [regex]::new("([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})")
    $arp = @(cmd /c "arp -a 2>&1").Where({[regex]::new("^\s+[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.+dynamic").Match($_).Success})
    for($i = 0; $i -lt $net_info.Count; $i++)
    {
        $mac = $mac_reg.Match($arp.Where({$_ -match " $($net_info[$i].IPAddress) "})[0]).Groups[1].Value
        if(![string]::IsNullOrEmpty($mac))
        {
            if($net_info[$i].DNSResult -eq "IP is unassigned")
            {
                $net_info[$i].DNSResult = "In use without hostname"
            }
            $net_info[$i].MACAddress = $mac
        }
    }
    $html_start = "<!DOCTYPE html>`n<html>`n    <head>`n        <meta name=`"viewport`" content=`"width=device-width,initial-scale=1`">`n        <title>IP Addresses</title>`n                <style type=`"text/css`">`n            body, html {`n                width: 100%;`n                height: 100%;`n                font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;`n            }`n            .main {`n                width: 50%;`n                margin: auto;`n            }`n            table {`n                width: 90%;`n                margin: auto;`n            }`n            .name {`n                border-top: 1px solid black;`n                border-right: 1px solid black;`n                border-left: 1px solid black;`n                font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;`n                font-weight: bold;`n            }`n            .value {`n                border-top: 1px solid black;`n                border-right: 1px solid black;`n                font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;`n            }`n            .valueleft {`n                border-top: 1px solid black;`n                border-left: 1px solid black;`n                border-right: 1px solid black;`n                font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;`n            }`n            .ntop {`n                border-top-left-radius: 0.5em;`n            }`n            .vtop {`n                border-top-right-radius: 0.5em;`n            }`n            .nbottom {`n                border-bottom-left-radius: 0.5em;`n                border-bottom: 1px solid black;`n            }`n            .vbottom {`n                border-bottom-right-radius: 0.5em;`n                border-bottom: 1px solid black;`n            }`n            td,th {`n                padding: 5px;`n                white-space: nowrap;`n            }`n            .midbottom {`n                border-bottom: 1px solid black;`n            }`n        </style>`n    </head>`n    <body>`n        <div class=`"main`">`n            <table>`n                <tr>`n                    <td class=`"name ntop`">localhost</td>`n                    <td class=`"value vtop`">$($ipv4)</td>`n                </tr>`n                <tr>`n                    <td class=`"name`">default gateway</td>`n                    <td class=`"value`">$($gateway)</td>`n                </tr>`n                <tr>`n                    <td class=`"name`">subnet prefix length</td>`n                    <td class=`"value`">$($cidr)</td>`n                </tr>`n                <tr>`n                    <td class=`"name`">number of assignable ip addresses</td>`n                    <td class=`"value`">$($possible_hosts)</td>`n                </tr>`n                <tr>`n                    <td class=`"name`">first IP address</td>`n                    <td class=`"value`">$($ip_range_start)</td>`n                </tr>`n                <tr>`n                    <td class=`"name nbottom`">last IP address</td>`n                    <td class=`"value vbottom`">$($ip_range_end)</td>`n                </tr>`n            </table>`n            <table>`n                <tr>`n                    <th>IP address</th>`n                    <th>Hostname</th>`n                    <th>MAC address</th>`n                </tr>`n"
    $html_end = "            </table>`n        </div>`n    </body>`n</html>`n"
    $html_table_rows = @()
    for($i = 0; $i -lt $net_info.Count; $i++)
    {
        $row = $net_info[$i]
        $handled = $false
        if($i -eq 0)
        {
            $html_table_rows += "                <tr>`n                    <td class=`"valueleft ntop`">$($row.IPAddress)</td>`n                    <td class=`"value`">$($row.DNSResult)</td>`n                    <td class=`"value vtop`">$($row.MACAddress)</td>`n                </tr>`n"
            $handled = $true
        }
        if($i -eq ($net_info.Cont - 1))
        {
            $html_table_rows += "                <tr>`n                    <td class=`"valueleft nbottom`">$($row.IPAddress)</td>`n                    <td class=`"value midbottom`">$($row.DNSResult)</td>`n                    <td class=`"value vbottom`">$($row.MACAddress)</td>`n                </tr>`n"
            $handled = $true
        }
        if(!$handled)
        {
            $html_table_rows += "                <tr>`n                    <td class=`"valueleft`">$($row.IPAddress)</td>`n                    <td class=`"value`">$($row.DNSResult)</td>`n                    <td class=`"value`">$($row.MACAddress)</td>`n                </tr>`n"
        }
    }
    $html_table = $html_start + [string]::Join([string]::Empty,$html_table_rows) + $html_end
    [io.File]::WriteAllBytes(
        "$($ENV:USERPROFILE)\Desktop\$([Math]::Round(([datetime]::UtcNow - [datetime]::Parse("1970-01-01")).TotalSeconds))_subnet_info.html",
        [System.Text.Encoding]::UTF8.GetBytes($html_table)
    )
#    $net_info | Export-Csv "$($ENV:USERPROFILE)\Desktop\$([Math]::Round(([datetime]::UtcNow - [datetime]::Parse("1970-01-01")).TotalSeconds))_subnet_info.csv"
} else {
    $null = ([System.Diagnostics.Process]@{
        StartInfo = [System.Diagnostics.ProcessStartinfo]@{
            FileName  = "$($PSHOME)\PowerShell.exe";
            Arguments = " -NoExit -Command Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex (irm 'https://net.nanick.org/subnetting.ps1')";
            Verb      = "RunAs"
        }
    }).Start()
    @(Get-WmiObject win32_process).Where({$_.ProcessId -eq $PID})[0].Terminate()
 }
 
