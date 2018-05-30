# PSProxy
A simple powershell module for managing Windows proxy server settings

## Usage

Turn proxy on/off
```
Set-ProxyEnabled [-Enabled <bool>]
```

Toggle proxy on/off
```
Toggle-Proxy
```

Set proxy server
```
Set-ProxyServer [-HTTPProxyServer <address>] [-HTTPProxyPort <port>] [-HTTPSProxyServer <address>] [-HTTPSProxyPort <port>] [-FTPProxyServer <address>] [-FTPProxyPort <port>] [-SocksProxyServer <address>] [-SocksProxyPort <port>] [-BypassLocalAddresses <bool>]
```
