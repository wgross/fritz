function Get-Tr64description {
    process {
        Invoke-RestMethod -Method Get -Uri http://fritz.box:49000/tr64desc.xml
    }
}

function Get-ServiceList {
    begin {
        $splattedParameters = @{
            Namespace = @{
                dns= "urn:delforum-org:device-1-0"
            }
        }
    }
    process {
         Select-Xml -Xml (Get-Tr64description) -XPath "//service" @splattedParameters
    }
}

Get-Tr64description
Get-ServiceList