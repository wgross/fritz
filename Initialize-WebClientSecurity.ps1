using namespace System.Net

<#
.SYNOPSIS
    Make a download with webclient using the DefaultNetworkCredentials to authenticate at proxy.
    Afterwards all new webclient based cmdlets can pass the proxy.

.DESCRIPTION
    Make a download with webclient using the DefaultNetworkCredentials to authenticate at proxy.
    Afterwards all new webclient based cmdlets can pass the proxy.

.EXAMPLE
    Just call to install credentials

    Initialize-WebClientProxyCredentials.ps1

.LINK
    http://blog.stangroome.com/2013/08/02/powershell-update-help-and-an-authenticating-proxy/
#>
[CmdletBinding()]
param(
    [Parameter(DontShow)]
    [switch]$SkipCertificateCheck,

    [Parameter()]
    [switch]$AcceptAllCertificates,

    [Parameter()]
    [switch]$SetDefaultCredentials
)
begin {

    if(-not(Test-Path Variable:\TrustAllCertsPolicyType)) {
        $typeDefinition = @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy 
{
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) 
    {
        return true;
    }
}
"@ 
        Add-Type -TypeDefinition $typeDefinition -PassThru | New-Variable -Name TrustAllCertsPolicyType -Option AllScope,Constant -Scope Global -Description "Certificate validation strategy which accepts any certificate" 
    }

}
process {
    $wc = [WebClient]::new()

    if($SetDefaultCredentials.IsPresent) {
        
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        
        "Default network credentials for proxy authentication installed." | Write-Host -ForegroundColor Green 
    }

    if($SkipCertificateCheck.IsPresent) {
        
        [ServicePointManager]::ServerCertificateValidationCallback = { $true }
        
        "Skipping certificate check" | Write-Host -ForegroundColor Green 
    }

    if($AcceptAllCertificates.IsPresent) {

        [ServicePointManager]::CertificatePolicy = [TrustAllCertsPolicy]::new()
    
        "Policy to accept all certificates is installed" | Write-Host -ForegroundColor Green
    }
    
    # validate settings
    $wc.DownloadString('https://www.heise.de') | Out-Null
}