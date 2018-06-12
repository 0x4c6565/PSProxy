$Script:InternetSettingsKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

function Toggle-Proxy
{
    [bool]$ProxyEnabled = (Get-ItemProperty -Path $Script:InternetSettingsKey -Name "ProxyEnable").ProxyEnable
    Set-ProxyEnabled -Enabled ($ProxyEnabled -ne $true)
}

function Set-ProxyEnabled
{
    Param
    (
        [bool]$Enabled
    )
    
    Set-ItemProperty -Path $Script:InternetSettingsKey -Name "ProxyEnable" -Value ([int]$Enabled)
}

function Set-ProxyOverideEnabled
{
    Param
    (
        [bool]$Enabled
    )

    $ProxyOverrideExists = ((Get-ItemProperty -Path $Script:InternetSettingsKey).ProxyOverride -eq "<local>")

    if ($Enabled)
    {
        if ($ProxyOverrideExists -eq $false)
        {
            Set-ItemProperty -Path $Script:InternetSettingsKey -Name "ProxyOverride" -Value "<local>"
        }
    }
    else
    {
        if ($ProxyOverrideExists)
        {
            Remove-ItemProperty -Path $Script:InternetSettingsKey -Name "ProxyOverride"
        }
    }
}

function Set-ProxyServer
{
    Param
    (
        [string]$HTTPProxyServer,
        [int]$HTTPProxyPort,
        [string]$HTTPSProxyServer,
        [int]$HTTPSProxyPort,
        [string]$FTPProxyServer,
        [int]$FTPProxyPort,
        [string]$SocksProxyServer,
        [int]$SocksProxyPort,
        [Nullable[bool]]$BypassLocalAddresses
    )
    
    $ProxyServerObject = Parse-ProxyDirectives
    
    if ([string]::IsNullOrEmpty($HTTPProxyServer) -eq $false)
    {
        Validate-PortNumber -Port $HTTPProxyPort
        $ProxyServerObject.http = @{Server=$HTTPProxyServer;Port=$HTTPProxyPort}
    }
    
    if ([string]::IsNullOrEmpty($HTTPSProxyServer) -eq $false)
    {
        Validate-PortNumber -Port $HTTPSProxyPort
        $ProxyServerObject.https = @{Server=$HTTPSProxyServer;Port=$HTTPSProxyPort}
    }
    
    if ([string]::IsNullOrEmpty($FTPProxyServer) -eq $false)
    {
        Validate-PortNumber -Port $FTPProxyPort
        $ProxyServerObject.ftp = @{Server=$FTPProxyServer;Port=$FTPProxyPort}
    }
    
    if ([string]::IsNullOrEmpty($SocksProxyServer) -eq $false)
    {
        Validate-PortNumber -Port $SocksProxyPort
        $ProxyServerObject.socks = @{Server=$SocksProxyServer;Port=$SocksProxyPort}
    }
    
    Set-ProxyDirectives -ProxyServerObject $ProxyServerObject

    if ($BypassLocalAddresses -ne $null)
    {
        Set-ProxyOverideEnabled -Enabled $BypassLocalAddresses
    }
}

function Set-ProxyDirectives
{
    Param
    (
        $ProxyServerObject
    )

    if ($ProxyServerObject.Keys.Count -ge 1)
    {
        $ProxyDirectiveArray = @()
        foreach ($Type in $ProxyServerObject.Keys)
        {
            $ProxyDirectiveArray += "$($Type)=$($ProxyServerObject.$Type.Server):$($ProxyServerObject.$Type.Port)"
        }
    
        Set-ItemProperty -Path $Script:InternetSettingsKey -Name "ProxyServer" -Value ($ProxyDirectiveArray -join ";")
    }
}

function Parse-ProxyDirectives
{    
    $ProxyServerObject = @{}
    
    if ((Get-ItemProperty -Path $Script:InternetSettingsKey).ProxyServer -eq $null)
    {
        return $ProxyServerObject
    }

    $ProxyServer = (Get-ItemProperty -Path $Script:InternetSettingsKey -Name "ProxyServer").ProxyServer
    
    foreach ($Directive in $ProxyServer -split ";")
    {
        $ParsedDirective = Parse-ProxyDirective -Directive $Directive
        $ProxyServerObject.$($ParsedDirective.Type) = @{Server=$ParsedDirective.Server;Port=$ParsedDirective.Port}
    }
    
    return $ProxyServerObject
}

function Parse-ProxyDirective
{
    Param
    (
        [string]$Directive
    )
    
    $Match = [regex]::Match($Directive, "^(?<type>\w+)=(?<server>[\w\.]+):(?<port>\d+)$")
    if ($Match.Success -ne $true)
    {
        throw "Malformed proxy directive [$Directive]"
    }
    
    return New-Object -TypeName PSObject -Property @{
        Type=$Match.Groups["type"].Value
        Server=$Match.Groups["server"].Value
        Port=$Match.Groups["port"].Value
    }
}

function Validate-PortNumber([int]$Port)
{    
    if ($Port -lt 1 -or $Port -gt 65535)
    {
        throw "Invalid port number"
    }
}

Export-ModuleMember -Function "Set-ProxyEnabled"
Export-ModuleMember -Function "Set-ProxyServer"
Export-ModuleMember -Function "Toggle-Proxy"
