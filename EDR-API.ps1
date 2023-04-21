
#################################################################################################
# This scritpt is in test stage. Before you run it chceck and correct the source code.
# 
#                           YOU'RE USING IT AT YOUR OWN RISK.
# 
# https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/endpoint-
#        security-and-management/endpoint-detection-and-response/generated-pdfs/EDR_API_Legacy.pdf
#################################################################################################

$EDR_Address = "https://192.168.1.1"
$cred = @{
    client_id = 'O2ID.atp-customer.atp-domain.0123456789abcdef0123456789'
    client_secret = '0123456789abcdef0123456789abcdef012'
} 


#################################################################################################
#                           bypass SSL/TLS certificate checks
#################################################################################################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#################################################################################################

function ConvertTo-Base64([string]$text)
    {return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($text))}


function ConvertFrom-Base64([string]$text)
    {return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($text))}


function Get-TimeStamp()
    {return (Get-Date -Format "yyyyMMddHHmm")}


function get-EdrAccessToken(
        [string]$EDRrootAddress, 
        $credentials
){
    $credText = $credentials.client_id + ":" + $credentials.client_secret
    $encodedCred = ConvertTo-Base64($credText)
    $headers = @{
        Accept = 'application/json';
        Authorization = "Basic $encodedCred";
        'Content-Type' = 'application/x-www-form-urlencoded';
    }
    $body = 'grant_type=client_credentials&scope=customer'
    return ((Invoke-RestMethod -Uri "$EDR_Address/atpapi/oauth2/tokens" -Method Post -Headers $headers -Body $body).access_token)
}


#################################################################################################


#################################################################################################
#                                     USAGE
#################################################################################################


<#
    curl --request GET "https://192.168.1.15/atpapi/v2/policies/deny_list" \
    --header "Authorization: Bearer  {bearer token}" \
    --header "Content-Type: application/json" 
#>

$token = get-EdrAccessToken -EDRrootAddress $EDR_Address -credentials $cred


$headers = @{
    Authorization = "Bearer $token"
    'Content-Type' = 'application/json'  
}
$response = Invoke-WebRequest -Uri "$EDR_Address/atpapi/v2/policies/deny_list" -Method Get -Headers $headers

$a = ($response.Content | ConvertFrom-Json) #.result[1]

[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a.next))

$a.result | ConvertTo-Json | Out-File "$env:USERPROFILE\Documents\Windows PowerShell\temp\EDR_deny_list_policy_" + (Get-TimeStamp) + ".json"
$a.result  | 
%{
    write ""
    write ($_).id
    write ($_).target_type
    write ($_).target_value
    write ($_).comment
    }


clear 
#################################################################################################
# Create Blacklist Policies
# POST /atpapi/v2/policies/blacklist
# Blacklist policy creation operation is atomic, so either all or none are created.

<#
    curl --request POST "https://192.168.1.15/atpapi/v2/policies/deny_list" \
    --header "Authorization: Basic  {bearer token}" \
    --header "Content-Type: application/json" \
    --data '{"verb":"create","policies":[{"target_type":"ip","target_value":"1.1.1.201","comment":"Blocking malicious ip"},{"target_type":"domain","target_value":"abc.com","comment":"Blocking malicious domain"}]}'
#>


$token = get-EdrAccessToken -EDRrootAddress $EDR_Address -client_id $cred.client_id -client_secret $cred.client_secret


$headers = @{
    Authorization = "Bearer $token"
    'Content-Type' = 'application/json'  
}

$policy = Get-Content "$env:USERPROFILE\Documents\Windows PowerShell\temp\EDR_deny_list_policy_2.json" 
$body = '{"verb":"create","policies":'+$policy+'}'

$responsePOST = Invoke-WebRequest -Uri "$EDR_Address/atpapi/v2/policies/deny_list" -Method Post -Headers $headers -Body $body
$responsePOST.Content



#################################################################################################
# Delete Blacklist Policies
# DELETE /atpapi/v2/policies/deny_list/{id}
# Blacklist policy creation operation is atomic, so either all or none are created.

<#
    curl --request DELETE "https://192.168.1.15/atpapi/v2/policies/deny_list/{id}" \
    --header "Authorization: Basic  {bearer token}" \
    --header "Content-Type: application/json" 
#>
                                                            

$token = get-EdrAccessToken -EDRrootAddress $EDR_Address -client_id $cred.client_id -client_secret $cred.client_secret


$headers = @{
    Authorization = "Bearer $token"
    'Content-Type' = 'application/json'  
}

$policy_id = "3"

$responseDEL = Invoke-WebRequest -Uri "$EDR_Address/atpapi/v2/policies/deny_list/$policy_id" -Method DELETE -Headers $headers

$responseDEL.RawContent
