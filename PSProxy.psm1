function Toggle-Proxy
{
    [bool]$ProxyEnabled = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable").ProxyEnable
    Set-ProxyEnabled -Enabled ($ProxyEnabled -ne $true)
}

function Set-ProxyEnabled
{
    Param
    (
        [bool]$Enabled
    )
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value ([int]$Enabled)
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
        [int]$SocksProxyPort
    )
    
    $ProxyServerObject = Parse-ProxyDirectives
    
    if ([string]::IsNullOrEmpty($HTTPProxyServer) -eq $false)
    {
        $ProxyServerObject.http = @{Server=$HTTPProxyServer;Port=$HTTPProxyPort}
    }
    
    if ([string]::IsNullOrEmpty($HTTPSProxyServer) -eq $false)
    {
        $ProxyServerObject.https = @{Server=$HTTPSProxyServer;Port=$HTTPSProxyPort}
    }
    
    if ([string]::IsNullOrEmpty($FTPProxyServer) -eq $false)
    {
        $ProxyServerObject.ftp = @{Server=$FTPProxyServer;Port=$FTPProxyPort}
    }
    
    if ([string]::IsNullOrEmpty($SocksProxyServer) -eq $false)
    {
        $ProxyServerObject.socks = @{Server=$SocksProxyServer;Port=$SocksProxyPort}
    }
    
    Set-ProxyDirectives -ProxyServerObject $ProxyServerObject
}

function Set-ProxyDirectives
{
    Param
    (
        $ProxyServerObject
    )
    
    $ProxyDirectiveArray = @()
    foreach ($Type in $ProxyServerObject.Keys)
    {
        $ProxyDirectiveArray += "$($Type)=$($ProxyServerObject.$Type.Server):$($ProxyServerObject.$Type.Port)"
    }
    
    Write-Host $ProxyDirectiveArray
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -Value ($ProxyDirectiveArray -join ";")
}

function Parse-ProxyDirectives
{    
    $ProxyServerObject = @{}
    $ProxyServer = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer").ProxyServer
    
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

Export-ModuleMember -Function "Set-ProxyEnabled"
Export-ModuleMember -Function "Set-ProxyServer"
Export-ModuleMember -Function "Toggle-Proxy"
