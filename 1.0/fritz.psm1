#region Inspect device configuration

function Get-Tr64Description {
    process {
        Invoke-RestMethod -Method Get -Uri http://fritz.box:49000/tr64desc.xml | Write-Output
    }
}

function Get-Tr64ServiceList {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$Tr64Xml = (Get-Tr64Description)
    )
    process {
        $Tr64Xml.root.device.serviceList.service | Write-Output
    }
}

function Get-DeviceInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [xml]$Tr64Xml
    )
    process {
        $Tr64Xml.root.device | Write-Output
    }
}

function Select-DeviceList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [xml]$Tr64Xml
    )
    process {
        $Tr64Xml.root.device.deviceList.device | Write-Output
    }
}

function Select-DeviceServiceList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [xml]$Tr64Xml,

        [Parameter(Mandatory)]
        [ArgumentCompleter({Get-Tr64description | Select-DeviceList | Select-Object -ExpandProperty deviceType | Where-Object -FilterScript { $_.Contains($args[2]) }})]
        [string]$DeviceType
    )
    process {
        
        "Fitering by device type $DeviceType" | Write-Verbose

        $Tr64Xml.root.device.deviceList.device | Where-Object -FilterScript {  

            $_.deviceType -eq $DeviceType

        } | ForEach-Object -Process {
            
            $_.serviceList.service | Write-Output
        
        }
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
        #<NewPhonebookList>0</NewPhonebookList>
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

function Get-CallList {
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
        $responseXml.root.Call | Write-Output
    }
}

#enregion

