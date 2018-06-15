using namespace System.Net
using namespace System.Security.Cryptography.X509Certificates

Import-Module passwordVault -ErrorAction SilentlyContinue

#region Accept the self-signed certificate of the fritz box

# fritz box ssl certificates are self signed. .Net rejects these by default
class TrustAllCertsPolicy : ICertificatePolicy {
    [bool] CheckValidationResult([ServicePoint] $srvPoint, [X509Certificate] $certificate, [WebRequest] $request, [int] $certificateProblem) {
        return $true
    }
}

function Disable-SslCertificateCheck {
    <#
    .SYNOPSIS
        Registers a certificate policy which accepts any SSL certificate
    #>
    process {   
        [ServicePointManager]::CertificatePolicy = [TrustAllCertsPolicy]::new()
        "fritz: disabled check of SSL certificates in this process" | Write-Verbose
    }
}

if([ServicePointManager]::CertificatePolicy.GetType().FullName -eq "System.Net.DefaultCertPolicy") {
    "fritz: disabling check of SSL certificates in this process" | Write-Host -ForegroundColor DarkYellow
    Disable-SslCertificateCheck
} elseif([ServicePointManager]::CertificatePolicy.GetType().Name -eq "TrustAllCertsPolicy") {
    "fritz: TrustAllCertsPolicy was found" | Write-Host -ForegroundColor Green
} else {
    "fritz: a non-default CertificatePolicy was found: $([ServicePointManager]::CertificatePolicy.GetType().FullName). Fritz may not work properly" | Write-Host -ForegroundColor Red
}

#endregion

# (Select-Tr64Service|choose|Select-Tr64ServiceAction|choose|Get-Tr64ServiceActionDescription).OuterXml

#region Inspect device configuration

function Get-Tr64Description {
    param(
        [Parameter()]
        [string]$Tr64DescUri = "http://fritz.box:49000/tr64desc.xml"
    )
    process {
        $global:cachedTr64Description = $null
        Invoke-RestMethod -Method Get -Uri $Tr64DescUri | Write-Output
    }
}

function cachedTr64Description {
    if($global:cachedTr64Description) {
        return $global:cachedTr64Description
    }

    "Retrieving TR64 Description"|Write-Verbose

    return ($global:cachedTr64Description = Get-Tr64description)
}

class Tr64Service {
    $ServiceType
    $ServiceId
    $ControlURL
    $EventSubURL
    $SCPDURL
}

function Select-Tr64Service {
    <#
    .SYNOPSIS
        Retrieves a list of services available from the root device
        The values of the XmlElements are mapped to properties of a data class for easier processing

    .EXAMPLE
        Select-Tr64Service

        Retrieves a list of services available from the root device

    .EXAMPLE
        Get-Tr64Description | Select-Tr64Service 

        Retrieves a list of services available from the root device

    .EXAMPLE
        Get-Tr64Description | Select-Tr64Service | Out-GridView -PassThru

        Retrieves a list of services and selects a subset interactively 
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$Tr64Xml = (cachedTr64Description)
    )
    process {
        $Tr64Xml.root.device.serviceList.service | ForEach-Object -Process {
            $tmp = [Tr64Service]::new()
            $tmp.ControlURL = $_.controlURL
            $tmp.EventSubURL = $_.eventSubURL
            $tmp.SCPDURL = $_.SCPDURL
            $tmp.ServiceId = $_.serviceId
            $tmp.ServiceType = $_.serviceType
            $tmp | Write-Output
        }
    }
}

function Select-Tr64DeviceInfo {
    <#
    .SYNOPSIS
        Retrieves the Tr64 device properties like manufacturer, model name etc
    .DESCRIPTION
        These are taken from /root/device/
    .EXAMPLE
        Get-Tr64Description|Select-Tr64DeviceInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$Tr64Xml = (cachedTr64Description)
    )
    process {
        $Tr64Xml.root.device | Write-Output
    }
}

class Tr64ServiceAction {
    $ServiceType
    $SCPDURL
    $ActionName
}

function Select-Tr64ServiceAction {
    <#
    .SYNOPSIS
        Retrieves the action names from a SCPDURL of a TR64 service description
        The values of the XmlElements are mapped to properties of a data class for easier processing

    .EXAMPLE
         Select-Tr64Service | Select-Tr64ServiceAction
         Retrieves a list of all action names available for all services of the fritz box global services

    .EXAMPLE
         Select-Tr64DeviceServiceList -DeviceType urn:dslforum-org:device:LANDevice:1 | Select-Tr64ServiceAction
         Retrieves a list of all action names avaliable for all services for device urn:dslforum-org:device:LANDevice:1
    #> 
    [OutputType([Tr64ServiceAction])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$ServiceType,
        
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$SCPDURL
    )
    process {

        "Retrieving SCP document for service $ServiceType" | Write-Verbose

        $responseXml = Invoke-RestMethod -Method Get -Uri "http://fritz.box:49000$SCPDURL" 
        $responseXml.scpd.actionList.action | ForEach-Object -Process {
            $tmp = [Tr64ServiceAction]::new()
            $tmp.ActionName = $_.name
            $tmp.SCPDURL = $SCPDURL
            $tmp.ServiceType = $ServiceType
            $tmp | Write-Output
        }
    }
}

function Select-Tr64DeviceList {
    <#
    .SYNOPSIS
        Retrieves the list of logical sub devices from a Tr64 description.
    .DESCRIPTION
        These are taken from /root/device/deviceList/device.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$Tr64Xml = (cachedTr64Description)
    )
    process {
        $Tr64Xml.root.device.deviceList.device | Write-Output
    }
}

function Select-Tr64DeviceServiceList {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$Tr64Xml = (cachedTr64Description),

        [Parameter(Mandatory)]
        [ArgumentCompleter({Get-Tr64description | Select-Tr64DeviceList | Select-Object -ExpandProperty deviceType | Where-Object -FilterScript { $_.Contains($args[2]) }})]
        [string]$DeviceType
    )
    process {
        
        "Fitering by device type $DeviceType" | Write-Verbose

        $Tr64Xml.root.device.deviceList.device | Where-Object -FilterScript {  

            $_.deviceType -eq $DeviceType

        } | ForEach-Object -Process {
            
            $_.serviceList.service | ForEach-Object -Process {

                $tmp = [Tr64Service]::new()
                $tmp.ControlURL = $_.controlURL
                $tmp.EventSubURL = $_.eventSubURL
                $tmp.SCPDURL = $_.SCPDURL
                $tmp.ServiceId = $_.serviceId
                $tmp.ServiceType = $_.serviceType
                $tmp | Write-Output
            }
        }
    }
}

function Get-Tr64ServiceActionDescription {
    <#
    .SYNOPSIS
        Retrieves a part of a the XML description of a services type describing only the 
        given action.
    
    .EXAMPLE
         (Select-Tr64Service | Select-Tr64ServiceAction | where ActionName -eq "GetDeviceLog"  | Get-Tr64ServiceActionDescription).OuterXml
         Retrieves the description of the GetDeviceLog action and shows ist in the shell
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        $ServiceType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SCPDURL,

        [Parameter(ValueFromPipelineByPropertyName)]
        $ActionName
    )
    process {
        $responseXml = Invoke-RestMethod -Method Get -Uri "http://fritz.box:49000$SCPDURL"
        $responseXml.scpd.actionList.action | Where-Object -FilterScript {
            $_.name -eq $ActionName
        } | Write-Output
    }
}

#endregion 

#region Prepare authenticated connections

function New-FritzBoxCredentials {
    param(
        [Parameter()]
        $UserName = "dslf-config"
    )
    $global:cachedFritzboxCredentials = [pscredential]::new("dslf-config",(Read-Host -Prompt "Fritzbox password" -AsSecureString))
    $global:cachedFritzboxCredentials|Write-Output
}

function cachedFritzBoxCredentials {
    if($global:cachedFritzboxCredentials) {
        return $global:cachedFritzboxCredentials
    } elseif(Get-Module passwordVault) {
        # try to retrieve password from password valut
        $scriptUser = Get-StoredCredentials -UserName "dslf-config" -Resource "http://fritz.box/" 
        $scriptUser.RetrievePassword()
        if($scriptUser) {
            "Using credential from password vault"|Write-Verbose
            $securePassword = ConvertTo-SecureString -String $scriptUser.Password -AsPlainText -Force
            return ($global:cachedFritzboxCredentials=[pscredential]::new("dslf-config",$securePassword))
        }        
    }
    return ($global:cachedFritzboxCredentials = New-FritzBoxCredentials)
}

#endregion 

#region urn:dslforum-org:service:DeviceInfo:1 / Device maintenance 

function Get-SecurityPort {
    [CmdletBinding()]
    param (
        [Parameter()]
        $FritzBoxUri = "http://fritz.box:49000"
    )
    process {
        $parameters = @{
            ContentType = 'text/xml; charset="utf-8"'
            Headers = @{
                "SOAPACTION"= 'urn:dslforum-org:service:DeviceInfo:1#GetSecurityPort'
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:GetSecurityPort xmlns:u="urn:dslforum-org:service:DeviceInfo:1">
        </u:GetSecurityPort>' +
    </s:Body>
</s:Envelope>
"@
        }
        
        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri/upnp/control/deviceinfo" @parameters

        "Received security port from $FritzBoxUri`: $($responseXml.Envelope.Body.GetSecurityPortResponse.NewSecurityPort)" | Write-Verbose

        $responseXml.Envelope.Body.GetSecurityPortResponse.NewSecurityPort | Write-Output
    }
}

function cachedSecurityPort {    
    if($global:cachedSecurityPort) {
        return $global:cachedSecurityPort
    }
    return ($global:cachedSecurityPort = Get-SecurityPort)
}

function Get-DeviceLog {
    param (
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl =  "/upnp/control/deviceinfo",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:DeviceInfo:1",

        [Parameter()]
        [string]$ActionName = "GetDeviceLog"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#$ActionName"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:$ActionName xmlns:u="$ServiceType">
        </u:$ActionName>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters
        $responseXml.Envelope.Body.GetDeviceLogResponse.NewDeviceLog | Write-Output
    }
}

#endregion 

#region urn:dslforum-org:service:X_AVM-DE_OnTel:1 / Retrieve PhoneBooks, Call List

function Get-PhoneBookList {
    param (
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl = "/upnp/control/x_contact",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:X_AVM-DE_OnTel:1"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#GetPhoneBookList"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:GetPhoneBookList xmlns:u="$ServiceType">
        </u:GetPhoneBookList>
    </s:Body>
</s:Envelope>
"@
        }
        
        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters

        "Received phone book list (ids:$($responseXml.Envelope.Body.GetPhonebookListResponse.NewPhonebookList))"| Write-Verbose 

        $responseXml.Envelope.Body.GetPhonebookListResponse.NewPhonebookList | Write-Output
    } 
}

function Get-PhoneBook {
    param (
        [Parameter()]
        [int]$PhoneBookId = 0, 

        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl = "/upnp/control/x_contact",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:X_AVM-DE_OnTel:1"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#GetPhoneBook"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:GetPhoneBook xmlns:u="$ServiceType">
            <NewPhonebookID>$PhoneBookId</NewPhonebookID>
        </u:GetPhoneBook>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters

        "Received phone book (name:$($responseXml.Envelope.Body.GetPhonebookResponse.NewPhonebookName),url=$($responseXml.Envelope.Body.GetPhonebookResponse.NewPhonebookURL))"| Write-Verbose 
        
        $responseXml = Invoke-RestMethod -Method Get -Uri ($responseXml.Envelope.Body.GetPhonebookResponse.NewPhonebookURL)
        #$responseXml.OuterXml
        $responseXml.phonebooks.phonebook.contact | ForEach-Object -Process {
            [pscustomobject]@{
                #unknown semantic#uniqueid = $_.uniqueid
                lastName = $_.person.realName
                number = $_.telephony.number.'#text'
            }
        } | Write-Output
    }
}

function Get-PhoneBookEntry {
    # semantic of Id is unkown
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [int]$PhoneBookEntryId,
        
        [Parameter()]
        [int]$PhoneBookId = 0,
        
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter(DontShow)]
        [string]$ControlUrl = "/upnp/control/x_contact",

        [Parameter(DontShow)]
        [string]$ServiceType = "urn:dslforum-org:service:X_AVM-DE_OnTel:1",

        [Parameter(DontShow)]
        [string]$ActionName = "GetPhoneBookEntry"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#$ActionName"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:$ActionName xmlns:u="$ServiceType">
            <NewPhonebookID>$PhoneBookId</NewPhonebookID>
            <NewPhonebookEntryID>$PhoneBookEntryId</NewPhonebookEntryID>
        </u:$ActionName>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters
        
        "Received phone book '$($responseXml.Envelope.Body.GetPhonebookEntryResponse.NewPhonebookEntryData)'"| Write-Verbose 
        
        $phoneBookEntryDataXml = [xml]($responseXml.Envelope.Body.GetPhonebookEntryResponse.NewPhonebookEntryData)
        $phoneBookEntryDataXml.OuterXml | Write-Output
    }
}

enum CallListTypeValues {
    incoming = 1
    missed = 2
    outgoing = 3
    active_incoming = 9
    rejected_incoming = 10
    active_outgoing = 11
}

function Get-CallList {
    <#
    .SYNOPSIS
        Retrieves the call list from the fritz box.
        The list is filerable by the call type
    
    .EXAMPLE
        Get-CallList -Type incoming,missed
        Returns all incoming or missed calls from the call list

    .EXAMPLE
        Get-CallList
        Returns all calls from the call list

    .EXAMPLE
        Get-CallList | sort Id -Descending | select -First 1
        Retrieve the latest call
    #>
    param (
        [Parameter()]
        [CallListTypeValues[]]$Type,

        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl = "/upnp/control/x_contact",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:X_AVM-DE_OnTel:1",

        [Parameter()]
        [string]$ActionName = "GetCallList"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#$ActionName"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:$ActionName xmlns:u="$ServiceType">
        </u:$ActionName>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters
        
        "Received call list url: $($responseXml.Envelope.Body.GetCallListResponse.NewCallListURL)" | Write-Verbose
        
        $responseXml = Invoke-RestMethod -Method Get -Uri ($responseXml.Envelope.Body.GetCallListResponse.NewCallListURL)
        
        if($Type) {
            # filter calls by type
            $responseXml.root.Call | Sort-Object -Property Id -Descending | Where-Object -FilterScript {
                if($Type -contains $_.Type) {
                    $_|Write-Output
                }
            }
        } else {
            # send all calls to pipe
            $responseXml.root.Call | Sort-Object -Property Id -Descending | Write-Output
        }
    }
}

#endregion

#region urn:dslforum-org:service:X_AVM-DE_Speedtest:1

function Get-SpeedTestInfo {
    param(
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl = "/upnp/control/x_speedtest",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:X_AVM-DE_Speedtest:1",

        [Parameter()]
        [string]$ActionName = "GetInfo"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#$ActionName"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:$ActionName xmlns:u="$ServiceType">
        </u:$ActionName>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters
        $responseXml.Envelope.Body.GetInfoResponse | Write-Output
    }
}
#endregion 

#region urn:dslforum-org:service:WANCommonInterfaceConfig:1 / data throughput, common if properties
# ((Select-Tr64DeviceList|choose).serviceList.service).OuterXML
# ((Select-Tr64DeviceList|choose).serviceList.service)|Select-Tr64ServiceAction
# (((Select-Tr64DeviceList|choose).serviceList.service)|Select-Tr64ServiceAction|choose|Get-Tr64ServiceActionDescription).OuterXML

function Get-OnlineMonitor {
    <#
    .SYNOPSIS
        Retrieves data throughput per seconds as measured for the last 20 seconds.
    #>
    param(
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl = "/upnp/control/wancommonifconfig1",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:WANCommonInterfaceConfig:1",

        [Parameter()]
        [string]$ActionName = "X_AVM-DE_GetOnlineMonitor"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#$ActionName"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:$ActionName xmlns:u="$ServiceType">
            <NewSyncGroupIndex>0</NewSyncGroupIndex>
        </u:$ActionName>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters
        $responseXml.Envelope.Body.'X_AVM-DE_GetOnlineMonitorResponse'
    }
}

function Get-CommonLinkProperties {
    <#
    .SYNOPSIS
        Retrieves the current DSL link proprties like max upload download speed as the 
        Fritz box reads them from the providers link metdata.
    #>
    param(
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl = "/upnp/control/wancommonifconfig1",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:WANCommonInterfaceConfig:1",

        [Parameter()]
        [string]$ActionName = "GetCommonLinkProperties"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#$ActionName"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:$ActionName xmlns:u="$ServiceType">
        </u:$ActionName>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters
        $responseXml.Envelope.Body.GetCommonLinkPropertiesResponse | Write-Output
    }
}

#endregion 

#region urn:dslforum-org:service:WANDSLInterfaceConfig:1 / Get DSL statistics

function Get-StatisticsTotal {
    <#
    .SYNOPSIS
        Retrieves the current DSL link proprties like max upload download speed as the 
        Fritz box reads them from the providers link metdata.
    #>
    param(
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter()]
        [pscredential]$Credentials = (cachedFritzBoxCredentials),

        [Parameter()]
        [int]$SecurityPort = (cachedSecurityPort),

        [Parameter()]
        [string]$ControlUrl = "/upnp/control/wandslifconfig1",

        [Parameter()]
        [string]$ServiceType = "urn:dslforum-org:service:WANDSLInterfaceConfig:1",

        [Parameter()]
        [string]$ActionName = "GetStatisticsTotal"
    )
    process {
        $parameters = @{
            Credential = $Credentials
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= "$ServiceType#$ActionName"
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:$ActionName xmlns:u="$ServiceType">
        </u:$ActionName>
    </s:Body>
</s:Envelope>
"@
        }

        $responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort$ControlUrl" @parameters
        $responseXml.Envelope.Body.GetStatisticsTotalResponse | Write-Output
    }
}

#endregion 

#region Format a fritt report

function Get-FritzStatusReport {
    [CmdletBinding()]
    [Alias("fritzReport")]
    param()
    # last calls
    Get-CallList | Select-Object -First 5 | Format-Table -AutoSize -Property Type,Device,CalledNumber,Name
    
    $currentDownstream = (Get-OnlineMonitor|Select-Object -Expand newds_current_bps).split(",") | ForEach-Object { [int]::Parse($_)} | Measure-Object -Average | Select-Object -ExpandProperty Average 
    "Current downstream: $(($currentDownstream/100).ToString(".##")) kbit/sec"|Out-Host

    $currentUpstream = (Get-OnlineMonitor|Select-Object -Expand newus_current_bps).split(",") | ForEach-Object { [int]::Parse($_)} | Measure-Object -Average | Select-Object -ExpandProperty Average 
    "Current upstream: $(($currentUpstream/100).ToString(".##")) kbit/sec"|Out-Host    
}

#endregion 
