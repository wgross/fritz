function Get-Tr64description {
    process {
        Invoke-RestMethod -Method Get -Uri http://fritz.box:49000/tr64desc.xml
    }
}

function Get-ServiceList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [xml]$Tr64Xml
    )
    process {
        $Tr64Xml.root.device.serviceList.service | Select-Object -Property serviceType,serviceId,controlUrl
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

function Get-SecurityPort {
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
        $responseXml.Envelope.Body.GetSecurityPortResponse.NewSecurityPort | Write-Output
    }
}

function Get-PhoneBook {
     param (
        [Parameter()]
        $FritzBoxUri = "https://fritz.box",

        [Parameter(Mandatory)]
        [int]$SecurityPort,

        [Parameter(Mandatory)]
        [string]$Password
    )
    process {
        $parameters = @{
            Credential = [pscredential]::new("dslf-config",(ConvertTo-SecureString -String $Password -AsPlainText -Force))
            Headers = @{
                "Content-Type" = 'text/xml; charset="utf-8"'
                "SOAPACTION"= 'urn:dslforum-org:service:X_AVM-DE_OnTel:1#GetPhoneBook'
            }
            Body = @"
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
     <s:Body>
        <u:GetPhoneBook xmlns:u="urn:dslforum-org:service:X_AVM-DE_OnTel:1">
            <NewPhonebookID>0</NewPhonebookID>
        </u:GetPhoneBook>
    </s:Body>
</s:Envelope>
"@
        }
        $global:responseXml = Invoke-RestMethod -Method Post -Uri "$FritzBoxUri`:$SecurityPort/upnp/control/x_contact" @parameters
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

#$xml = Get-Tr64description
#$xml | Get-ServiceList 
#$xml | Select-DeviceList
#Get-SecurityPort
Get-PhoneBook -SecurityPort (Get-SecurityPort) 
