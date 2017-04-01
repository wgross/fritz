#region Inspect device configuration

function Get-Tr64Description {
    process {
        $global:cachedTr64Description = $null
        Invoke-RestMethod -Method Get -Uri http://fritz.box:49000/tr64desc.xml | Write-Output
    }
}

function script:cachedTr64Description {
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

function Select-Tr64ServiceList {
    <#
    .SYNOPSIS
        Retrieves a list of services available from the root device
        The values of the XmlElements are mapped to properties of a data class for easier processing

    .EXAMPLE
        Select-Tr64ServiceList 
        Retrieves a list of services available from the root device

    .EXAMPLE
        Get-Tr64Description | Select-Tr64ServiceList 
        Retrieves a list of services available from the root device
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
         Select-Tr64ServiceList | Select-Tr64ServiceAction
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

function Select-Tr64DeviceInfo {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$Tr64Xml = (cachedTr64Description)
    )
    process {
        $Tr64Xml.root.device | Write-Output
    }
}

function Select-Tr64DeviceList {
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
        Retrieves a paort of a the XML description of a services type decribing only the 
        given action.
    
    .EXAMPLE
         (Select-Tr64ServiceList | Select-Tr64ServiceAction | where ActionName -eq "GetDeviceLog"  | Get-Tr64ServiceActionDescription).OuterXml
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

function script:cachedSecurityPort {    
    if($global:cachedSecurityPort) {
        return $global:cachedSecurityPort
    }
    return ($global:cachedSecurityPort = Get-SecurityPort)
}

function script:cachedFritzBoxCredentials {
    if($global:cachedFritzboxCredentials) {
        return $global:cachedFritzboxCredentials
    }
    return ($global:cachedFritzboxCredentials = [pscredential]::new("dslf-config",(Read-Host -Prompt "Fritzbox password" -AsSecureString)))
}

#endregion 

#region Retrieve PhoneBooks

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
            Credential = [pscredential]::new("dslf-config",(ConvertTo-SecureString -String $Password -AsPlainText -Force))
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

        $responseXml.Envelope.Body.GetPhonebookListResponse.NewPhonebookList | Write-Verbose

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
            Credential = [pscredential]::new("dslf-config",(ConvertTo-SecureString -String $Password -AsPlainText -Force))
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
        $responseXml.phonebooks.phonebook.contact | ForEach-Object -Process {
            [pscustomobject]@{
                lastName = $_.person.realName
                number = $_.telephony.number.'#text'
            }
        } | Write-Output
    }
}

#endregion 

#region Retrieve list of calls

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
            Credential = (cachedFritzBoxCredentials)
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

        "Received call list url: $($responseXml.Envelope.Body.GetCallListResponse.NewCallListURL)"
        
        $responseXml = Invoke-RestMethod -Method Get -Uri ($responseXml.Envelope.Body.GetCallListResponse.NewCallListURL)
        
        if($Type) {
            # filter calls by type
            $responseXml.root.Call | Where-Object -FilterScript {
                if($Type -contains $_.Type) {
                    $_|Write-Output
                }
            }
        } else {
            # send all calls to pipe
            $responseXml.root.Call | Write-Output
        }
    }
}

#endregion

#region Device maintenance 

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
            Credential = (cachedFritzBoxCredentials)
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
