Write-Host "First we need some inputs"
# QRADAR info (management ip and authentication token)
$consoleIP = $env:consoleIP
$token = $env:token
# Sentinel info (workspace id and workspace key)
$customerId = $env:customerID 
$sharedKey =$env:sharedKey 

# Specify the name of the record type that you'll be creating
$LogType = "QRadarOffense"

Write-Host "Setting Trust for certificate"

if ("TrustAllCertsPolicy" -as [type]) {} else {
        Add-Type "using System.Net;using System.Security.Cryptography.X509Certificates;public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {return true;}}"
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}


Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

$headers = @{}
$headers.add("Version","12.0")
$headers.add("Content-Type","application/JSON")
$Headers.add("SEC",$token)

#Get all offenses for last 24hours epoch
$startEopch = Get-Date -Date "01/01/1970"
$yesterday = (Get-Date).AddDays(-1)
$unixTime = [math]::Round((New-TimeSpan -Start $startEopch -End $yesterday).TotalMilliSeconds)

$url = "https://" + $consoleIP + "/api/siem/offenses?filter=start_time%3E" + $unixTime
$OffenseInfo = Invoke-RestMethod -Method GET -Headers $headers -Uri $url


Write-Host "QRadar part done"

$sentinelJsonString = "["

foreach ($offense in $OffenseInfo)
{
    $sentinelJsonString += "{"
    foreach ($property in $offense.psobject.Properties.name) 
    { 
        $sentinelJsonString += '"' + $property + '" : ' 
        if ($offense.$property -eq $null)
        {
            $sentinelJsonString += '""'
        }
        #Too much hastle to differentiate, better to make it all strings
        #elseif ($offense.$property.GetType().Name -eq "Int32" -or $offense.$property.GetType().Name -eq "Int64" -or $offense.$property.GetType().Name -eq "Boolean")
        #{           $sentinelJsonString += $offense.$property       }
        else
        {
            $sentinelJsonString += '"' + $offense.$property + '"'
        }
        $sentinelJsonString += ","
        
    } 
    $sentinelJsonString = $sentinelJsonString.Substring(0, $sentinelJsonString.Length-1) + "},"
}
$sentinelJsonString = $sentinelJsonString.Substring(0, $sentinelJsonString.Length-1) + "]"


Write-Host "Json string created"

# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
$TimeStampField = ""

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}


# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

# Submit the data to the API endpoint
Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($sentinelJsonString)) -logType $logType

Write-Host "Written to Azure Sentinel"