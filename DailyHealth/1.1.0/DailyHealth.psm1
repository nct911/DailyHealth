#requires -Modules @{ ModuleName="pkitools"; ModuleVersion="1.6" }
#requires -Modules @{ ModuleName="Microsoft.PowerShell.Utility"; ModuleVersion="3.1.0.0"}
#requires -Assembly "System.Web"
function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        Converts a PSCustomObject into a hashtable.

    .DESCRIPTION
        Walks every NoteProperty on the supplied PSCustomObject and copies it into a
        hashtable, recursing into any property whose value is itself a PSCustomObject.

        This exists so that configuration read from JSON (which deserializes into nested
        PSCustomObjects) can be splatted directly at a cmdlet. Get-DailyStatus uses it to
        turn each job's JobParameters node into a splattable parameter set.

    .PARAMETER InputObject
        The PSCustomObject to convert. Typically a node from a JSON configuration file
        produced by ConvertFrom-Json.

    .INPUTS
        System.Management.Automation.PSCustomObject

    .OUTPUTS
        System.Collections.Hashtable

    .EXAMPLE
        $Config = Get-Content .\DailyStatus.json -Raw | ConvertFrom-Json
        $Splat  = ConvertTo-Hashtable -InputObject $Config[0].JobParameters
        Test-URIList @Splat

        Converts the first job's parameter block into a hashtable and splats it.

    .NOTES
        Arrays are copied by reference and are not converted element by element, so an
        array of PSCustomObjects stays an array of PSCustomObjects. A property whose value
        is $null will throw when GetType() is called on it.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]
        $InputObject
    )
    $Hashtable = @{}
    Foreach ($Property in $InputObject.PSObject.Properties) {
        if ($Property.Value.GetType().Name -eq 'PSCustomObject') {
            $Value = ConvertTo-Hashtable -InputObject $Property.Value
        }
        else {
            $Value = $Property.Value
        }
        $Hashtable.Add($Property.Name, $Value)
    }
    return $Hashtable
}
function Invoke-WebRequestDH {
    <#
    .SYNOPSIS
        Issues an HTTP/HTTPS GET and returns the raw request and response objects.

    .DESCRIPTION
        A thin wrapper over System.Net.HttpWebRequest, used where Invoke-WebRequest is not
        suitable because the caller needs the live HttpWebRequest object afterwards: the SSL
        checks read the negotiated ServicePoint.Certificate off it, which Invoke-WebRequest
        does not expose.

        The request is forced to TLS 1.2 for the duration of the call and the previous
        ServicePointManager.SecurityProtocol value is restored in a finally block, so the
        setting does not leak into the rest of the session. Expect100Continue and the Nagle
        algorithm are disabled and the timeout is fixed at 5000 ms. WebExceptions are
        swallowed and the exception's Response is returned instead, so a 4xx or 5xx still
        yields a usable object.

        Certificate validation is also suppressed for the duration of the call: a permissive
        ICertificatePolicy (TrustAllCertsPolicy) is compiled once per session and installed.
        Both that and SecurityProtocol are changed inside the try and restored in the
        matching finally, so no path out of the request leaves either altered. Suppressing
        validation is what lets the SSL checks read an expired, self-signed, or otherwise
        untrusted certificate instead of failing the handshake on it.

    .PARAMETER URI
        The absolute URI to request, including scheme (for example https://server.domain.tld).

    .PARAMETER Proxy
        Optional proxy host name or IP address. Both Proxy and ProxyPort must be supplied
        for the proxy to be applied.

    .PARAMETER ProxyPort
        Optional proxy TCP port. Both Proxy and ProxyPort must be supplied for the proxy to
        be applied.

    .OUTPUTS
        PSCustomObject with these properties:
            Request  - System.Net.HttpWebRequest, after the call; ServicePoint.Certificate
                       holds the presented server certificate.
            Response - System.Net.HttpWebResponse, or the WebException's Response on failure.

    .EXAMPLE
        $Result = Invoke-WebRequestDH -URI 'https://portal.example.com'
        $Result.Request.ServicePoint.Certificate.GetExpirationDateString()

        Retrieves the certificate expiration date presented by the endpoint.

    .EXAMPLE
        $Result = Invoke-WebRequestDH -URI 'http://10.20.30.40/httpGetSet/httpGet.htm?devId=0' -Proxy 'proxy01' -ProxyPort 8080
        Get-ResponseContent -Response $Result.Response

        Requests an HVAC controller endpoint through a proxy and reads the body.

    .NOTES
        The response stream is left open. Callers that read the body should use
        Get-ResponseContent, which closes the reader, stream, and response.
    #>
    [CmdletBinding()]
    Param(
        [parameter()][string]$URI,
        [parameter()][string]$Proxy,
        [parameter()][Int16]$ProxyPort
    )
    Add-Type -AssemblyName System.Web

    if ( -not ('TrustAllCertsPolicy' -as [type])) {
    # A little p/inkvoke magic to bypasss cert checking. We need the cert, even if it's invalid
    Add-Type @"
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
    }
    $Parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    $RequestURI = [System.UriBuilder]$URI
    $RequestURI.Query = $Parameters.ToString()
    $Request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($URI)
    $Request.Method = 'Get'
    $Request.Timeout = 5000
    if ($Proxy -and $ProxyPort) {
        $WebProxy = [System.Net.WebProxy]::new($Proxy, $ProxyPort)
        $Request.Proxy = $WebProxy
    }
    $Request.ServicePoint.Expect100Continue = $false
    $Request.ServicePoint.UseNagleAlgorithm = $false
    try {
        $OriginalPolicy = [System.Net.ServicePointManager]::CertificatePolicy
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

        $SPMSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12' #$AllProtocols

        $Response = $Request.GetResponse()
    }
    Catch [System.Net.WebException] {
        $Response = $_.Exception.Response 
    }
    Finally {
        [System.Net.ServicePointManager]::SecurityProtocol = $SPMSecurityProtocol
        [System.Net.ServicePointManager]::CertificatePolicy = $OriginalPolicy
    }
    return [PSCustomObject]@{
        Request  = $Request
        Response = $Response
    }
}
function Get-ResponseContent {
    <#
    .SYNOPSIS
        Reads the body out of an HttpWebResponse and closes the underlying resources.

    .DESCRIPTION
        Opens a UTF-8 StreamReader over the response stream, reads the body to the end, then
        closes the reader, the stream, and the response. Closing all three matters because
        Invoke-WebRequestDH leaves the response open, and the HVAC polling loop would
        otherwise exhaust the connection pool.

    .PARAMETER Response
        The System.Net.HttpWebResponse to read, typically the Response property returned by
        Invoke-WebRequestDH.

    .OUTPUTS
        System.String containing the response body.

    .EXAMPLE
        $Result = Invoke-WebRequestDH -URI "http://$HVACIP/httpGetSet/httpGet.htm?devId=0&evt=vel~eventsWA~or~2"
        Get-ResponseContent -Response $Result.Response

        Reads the raw event list from an HVAC controller.

    .NOTES
        The response is consumed and closed by this call, so it can only be read once.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [psobject]
        $Response
    )
    # 1. Get the data stream from the response object
    $Stream = $Response.GetResponseStream()

    # 2. Open a StreamReader with UTF8 encoding
    $Reader = [System.IO.StreamReader]::new($Stream, [System.Text.Encoding]::UTF8)

    # 3. Read the complete response body text
    $ResponseBody = $Reader.ReadToEnd()

    # 4. Clean up and close resources to prevent memory/connection leaks
    $Reader.Close()
    $Stream.Close()
    $Response.Close()

    # Output the body
    $ResponseBody

}
function Get-DecodedCertificate {
    <#
    .SYNOPSIS
        Decodes a base64 certificate blob from an AD CS issued-certificate record.

    .DESCRIPTION
        Takes a record returned by Get-IssuedCertificate (PKITools), strips the PEM header
        and footer lines from its 'Binary Certificate' property, and imports the remaining
        base64 into an X509Certificate2 object so that Subject, NotAfter, and Thumbprint can
        be read.

    .PARAMETER Certificate
        An issued-certificate record that exposes a 'Binary Certificate' property containing
        a PEM-encoded certificate.

    .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2 on success.
        System.Boolean ($false) if the blob could not be decoded.

    .EXAMPLE
        $Issued = Get-IssuedCertificate -CAlocation (Get-CaLocationString -CAName 'CONTOSO-ISSUING-CA')
        $Cert   = Get-DecodedCertificate -Certificate $Issued[0]
        if ($Cert) { $Cert.Subject }

        Decodes the first issued certificate and prints its subject.

    .NOTES
        Returns $false rather than throwing so that a single unparseable record does not
        abort a full CA enumeration. Callers must test the return value before using it.
        Decode failures are written to the host in red and are not surfaced as errors.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
        $Certificate
    )
    $Error.Clear()
    $Return = $false
    try {
        $CertBlob = $Certificate.'Binary Certificate'.ToString()
        $asciiCert = $CertBlob.Split([System.Environment]::NewLine).Where({ $_ -notmatch "^---" }).Replace([System.Environment]::NewLine, '') -join [System.Environment]::NewLine
        $DecodedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $DecodedCertificate.Import([Convert]::FromBase64String($asciiCert))
        $Return = $DecodedCertificate
    }
    catch {
        Write-Host -ForegroundColor Red "$($Error | ConvertTo-Json)"
        $Return = $false
    }
    return $Return
}
function Get-InternalCertInfo {
    <#
    .SYNOPSIS
        Reports expiration status for certificates issued by the internal AD CS estate.

    .DESCRIPTION
        Enumerates every enterprise certification authority reachable from the current
        domain, pulls the issued-certificate list from each, decodes the certificate blobs,
        and emits one status record per certificate with days remaining until expiration.

        Failures are emitted as records rather than thrown, so a broken CA or an
        undecodable certificate is reported as a row instead of killing the job. Those
        records carry DaysToExpiration = -1 and Status = 'error'.

    .PARAMETER ExcludedTemplates
        Certificate template OIDs to omit from the report. Used to suppress high-volume,
        short-lived, or auto-enrolled templates (domain controller authentication,
        workstation authentication, and similar) that would otherwise flood the report.

    .OUTPUTS
        PSCustomObject stream with these properties:
            DaysToExpiration - Float; days until NotAfter, or -1 on error.
            Status           - success (> 90 days), warning (1-90 days), error (< 1 day).
            IssuingAuthority - CA name that issued the certificate.
            Domain           - CN pulled out of the subject.
            Subject          - Full certificate subject, or the error text on failure.
            Expiration       - NotAfter date.
            Hash             - Certificate thumbprint.
            Oid              - Certificate template OID.

    .EXAMPLE
        Get-InternalCertInfo | Where-Object Status -ne 'success' | Format-Table Domain, DaysToExpiration, IssuingAuthority

        Lists every internally issued certificate inside the 90-day warning window.

    .EXAMPLE
        Get-InternalCertInfo -ExcludedTemplates '1.3.6.1.4.1.311.21.8.1234567.1234567.1234567.1234567.1234567.170.1.32'

        Suppresses a single noisy template.

    .NOTES
        Requires the PKITools module and rights to read the CA databases. Normally reached
        through Get-CertExpiration -Internal rather than called directly.

        The first catch block emits a record but does not return, so execution continues
        into the CA loop with $CertificateAuthorities unset; the enclosing if guard handles
        that case.
    #>
    param (
        [Parameter()]
        [string[]]
        $ExcludedTemplates
    )
    $Today = Get-Date
    try {
        $CertificateAuthorities = Get-CertificatAuthority
    }
    catch {
        [PSCustomObject]@{
            DaysToExpiration = [float](-1)
            IssuingAuthority = ''
            Domain           = 'Could not get certificate authorities'
            Subject          = "$($Error)"
            Expiration       = ''
            Hash             = ''
            Oid              = ''
        }
    }
    if ($CertificateAuthorities) {
        Foreach ($CertificateAuthority in $CertificateAuthorities) {
            try {
                $CALocation = Get-CaLocationString -CAName $CertificateAuthority.Name
                if ($IssuedCertificates) { Clear-Variable -Name 'IssuedCertificates' }
                $IssuedCertificates = Get-IssuedCertificate -CAlocation $CALocation -ErrorAction Stop | Where-Object { $ExcludedTemplates -notcontains $_.'Certificate Template' }
            }
            catch {
                [PSCustomObject]@{
                    DaysToExpiration = [float](-1)
                    Status           = 'error'
                    IssuingAuthority = $CertificateAuthority.Name
                    Domain           = 'Could not get Issued Certificates'
                    Subject          = "$($Error)"
                    Expiration       = ''
                    Hash             = ''
                    Oid              = ''
                }
            }
            Foreach ($EncodedCertificate in $IssuedCertificates) {
                try {
                    $Certificate = Get-DecodedCertificate -Certificate $EncodedCertificate
                    if ($Certificate.Subject) {
                        [PSCustomObject]@{
                            DaysToExpiration = [float]((Get-Date $Certificate.NotAfter) - $Today).TotalDays.ToString('##.##')
                            Status           = switch ([float]((Get-Date $Certificate.NotAfter) - $Today).TotalDays.ToString('##.##')) {
                                { $_ -gt 90 } { 'success'; break }
                                { ($_ -le 90) -and ($_ -ge 1) } { 'warning'; break }
                                { $_ -lt 1 } { 'error'  ; break }
                                default { 'warning'; break }
                            }
                            IssuingAuthority = $CertificateAuthority.Name
                            Domain           = $Certificate.Subject.Split(',').Where({ $_ -like '*CN=*' }).Split('=')[1]
                            Subject          = $Certificate.Subject
                            Expiration       = $Certificate.NotAfter
                            Hash             = $Certificate.Thumbprint
                            Oid              = $EncodedCertificate.'Certificate Template'
                        }
                    }
                }
                catch {
                    [PSCustomObject]@{
                        DaysToExpiration = [float](-1)
                        Status           = 'error'
                        IssuingAuthority = $CertificateAuthority.Name
                        Domain           = ''
                        Subject          = "Could not decode certificate for $($EncodedCertificate.'Issued Common Name')"
                        Expiration       = ''
                        Hash             = ''
                        Oid              = ''
                    }
                }
            }
        }
    }    
} 
function Get-CertExpiration {
    <#
    .SYNOPSIS
        Reports certificate expiration status for public endpoints, internal CAs, or both.

    .DESCRIPTION
        Two independent collection paths, either or both of which can run in one call:

          - DomainList: for each name, tests TCP 443 first, then opens a TLS session with
            Invoke-WebRequestDH and reads the certificate the server actually presents.
            Hosts that fail the port test are reported as 'Host Appears Down' rather than
            skipped.

          - Internal: delegates to Get-InternalCertInfo to enumerate certificates issued by
            the internal AD CS hierarchy.

        Both paths share one Status vocabulary so a caller can treat them identically.

    .PARAMETER DomainList
        Host names to probe over TLS on port 443. Supply bare host names, not URLs; the
        https:// scheme is added internally.

    .PARAMETER Internal
        Also enumerate internally issued certificates from every reachable enterprise CA.

    .PARAMETER ExcludedTemplates
        Certificate template OIDs to suppress from the internal report. Defaults to an empty
        set, so nothing is filtered and every issued certificate is reported. Supply the
        OIDs of the high-volume auto-enrolled templates in the environment being checked -
        domain controller authentication, workstation authentication and the like - or the
        report will be dominated by certificates nobody needs to act on. Ignored unless
        -Internal is specified.

    .OUTPUTS
        PSCustomObject collection with Domain, Subject, DaysToExpiration, Status,
        Expiration, Hash, and IssuingAuthority. Internal records additionally carry Oid.

    .EXAMPLE
        Get-CertExpiration -DomainList 'portal.MyGroup.org','www.Example.com'

        Checks two public endpoints.

    .EXAMPLE
        Get-CertExpiration -DomainList $Config.PublicSites -Internal |
            Where-Object DaysToExpiration -lt 45 |
            Sort-Object DaysToExpiration

        Full sweep, narrowed to certificates that need attention inside 45 days.

    .NOTES
        Status thresholds are identical on both paths: success above 90 days, warning from
        1 to 90 days, error below 1 day.

        External checks report DaysToExpiration as a whole-day integer; internal checks
        report a float.

        Certificate validation is bypassed inside Invoke-WebRequestDH, so an already expired
        or untrusted certificate - the case this check exists to catch - is read and reported
        with its real dates rather than failing the handshake. A false 'Unable to retrieve
        SSL certificate' is now down to the 5000 ms timeout in that function, which is
        comfortable for most endpoints but can still catch a badly loaded one.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $DomainList,
        [Parameter()]
        [switch]
        $Internal,
        [Parameter()]
        [string[]]
        $ExcludedTemplates = @( )
    )

    if ($DomainList) {
        $InternetCertInfo = New-Object System.Collections.ArrayList
        Foreach ( $Domain in $DomainList ) {
            if ((Test-NetConnection $Domain -Port 443).TcpTestSucceeded) {
                $Request = $null
                $URI = "https://$Domain"
                $Request = (Invoke-WebRequestDH -URI $URI).Request
                if ($Request.servicePoint.Certificate) {
                    $Response = [PSCustomObject]@{
                        DaysToExpiration = ((Get-Date ($Request.servicePoint.Certificate.GetExpirationDateString())) - (Get-Date)).Days
                        Status           = switch (((Get-Date ($Request.servicePoint.Certificate.GetExpirationDateString())) - (Get-Date)).Days) {
                            { $_ -gt 90 } { 'success'; break }
                            { ($_ -le 90) -and ($_ -ge 1) } { 'warning'; break }
                            { $_ -lt 1 } { 'error'  ; break }
                            default { 'warning'; break }
                        }
                        IssuingAuthority = $Request.servicePoint.Certificate.Issuer 
                        Domain           = $Domain
                        Subject          = $Request.servicePoint.Certificate.Subject
                        Expiration       = Get-Date ($Request.servicePoint.Certificate.GetExpirationDateString())
                        Hash             = $Request.servicePoint.Certificate.GetCertHashString()
                    }
                }
                else {
                    $Response = [PSCustomObject]@{
                        DaysToExpiration = 0
                        Status           = 'Warning'
                        IssuingAuthority = 'Unable to retrieve SSL certificate'
                        Domain           = $Domain
                        Subject          = 'Unable to retrieve SSL certificate'
                        Expiration       = 0
                        Hash             = 'N/A'
                    }
                }
            }
            else {
                $Response = [PSCustomObject]@{
                    DaysToExpiration = 0
                    Status           = 'Warning'
                    IssuingAuthority = 'Host Appears Down'
                    Domain           = $Domain
                    Subject          = 'Host Appears Down'
                    Expiration       = 0
                    Hash             = 'N/A'
                }
            }
            $InternetCertInfo.Add($Response) | Out-Null
        }    
    }

    if ($Internal) {
        $InternalCertInfo = Get-InternalCertInfo -ExcludedTemplates $ExcludedTemplates
    }
    
    Return ($InternetCertInfo + $InternalCertInfo)
}
function Test-URIList {
    <#
    .SYNOPSIS
        Tests a list of URIs from a remote host, optionally through a list of proxies.

    .DESCRIPTION
        Runs the probe loop from whichever host should be doing the reaching. Name a remote
        computer and the loop is dispatched there over PowerShell remoting, so the test
        measures reachability from that host's network position; omit ComputerName, or name
        the local machine, and it runs in the current session instead.

        Every URI is tested once per proxy in ProxyList, which makes it possible to confirm
        that each egress path independently reaches each endpoint.

        A URI is 'success' when the request returns HTTP 200, and, if ExpectedResult was
        supplied, when the response content matches it exactly. Anything else, including a
        thrown exception, is 'error'.

    .PARAMETER ComputerName
        Optional host to run the probes from; it must be reachable over PowerShell remoting.
        Omit it, or pass the local machine's name, to run the probes in the current session.

    .PARAMETER URIList
        Absolute URIs to request. Every URI is tested against every entry in ProxyList.

    .PARAMETER Headers
        Optional header hashtable applied to every request. Used for API keys and
        content-type negotiation.

    .PARAMETER Body
        Optional request body. Only added to the request when non-empty, so GET probes are
        unaffected.

    .PARAMETER Method
        HTTP method for every request. Defaults to Get.

    .PARAMETER ExpectedResult
        Optional exact-match string compared against the response content. When omitted, any
        HTTP 200 counts as success. The comparison is a full-string equality test, not a
        substring match, so it suits fixed health-probe payloads.

    .PARAMETER ProxyList
        Proxies to route through. The literal string 'None' means a direct request, and is
        the default, so omitting this parameter tests each URI once directly.

    .PARAMETER Credential
        Optional credential for the remoting session. Not used for the HTTP requests
        themselves, and ignored when the probes run in the current session.

    .OUTPUTS
        System.Collections.ArrayList of PSCustomObject with Status, URI, and Proxy. Emitted
        with Write-Output -NoEnumerate so a single result still arrives as a collection.

        If dispatching the probe loop fails, the list holds one record in that same shape
        with Status = 'error', URI = 'Error checking URI', and the exception message in
        Proxy, so consumers can read every path uniformly.

    .EXAMPLE
        Test-URIList -ComputerName 'CONTOSO-APP01' -URIList 'https://ExampleTech.com/relay/health'

        Single direct probe from the named application server.

    .EXAMPLE
        Test-URIList -ComputerName 'Initech-App11' `
                     -URIList 'https://api.internal/status','https://cad.internal/status' `
                     -ProxyList 'None','http://proxy01:8080' `
                     -ExpectedResult 'OK'

        Tests two endpoints both directly and through the proxy, requiring a body of 'OK'.

    .NOTES
        The probe loop takes its inputs as parameters rather than reading them from the
        caller's scope, which is what lets the same block run unchanged either over remoting
        or directly in this session. ArgumentList order matches the scriptblock's param
        block positionally, so the two must be kept in step if either gains a parameter.

        A dispatch failure - an unreachable host, a refused session, a bad credential -
        yields one row rather than the per-URI matrix, so a result set that is shorter than
        URIList times ProxyList means the probes never ran.
    #>
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $false)]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [string[]]
        $URIList,

        [Parameter(Mandatory = $false)]
        [Object]
        $Headers = @{},

        [Parameter(Mandatory = $false)]
        [string]
        $Body = '',

        [Parameter(Mandatory = $false)]
        [string]
        $Method = 'Get',

        [Parameter(Mandatory = $false)]
        [string]
        $ExpectedResult,

        [Parameter(Mandatory = $false)]
        [string[]]
        $ProxyList = @('None'),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $Credential
    )
    $URIResults = New-Object System.Collections.ArrayList
    try {
        $ScriptBlock  = [System.Management.Automation.ScriptBlock] {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string[]]
                $URIList,

                [Parameter(Mandatory = $false)]
                [Object]
                $Headers = @{},

                [Parameter(Mandatory = $false)]
                [string]
                $Body = '',

                [Parameter(Mandatory = $false)]
                [string]
                $Method = 'Get',

                [Parameter(Mandatory = $false)]
                [string]
                $ExpectedResult,

                [Parameter(Mandatory = $false)]
                [string[]]
                $ProxyList = @('None')
            )
            foreach ($Proxy in $ProxyList) {
                Foreach ($URI in $URIList) {
                    $error.Clear()
                    Try {

                        $RequestParameters = @{
                            Uri     = $URI
                            Method  = $Method
                            Headers = $Headers
                        }
                        if ($Body) {
                            $RequestParameters.Add('Body', $Body)
                        }
                        if ($Proxy -ne 'None') {
                            $RequestParameters.Add('Proxy', $Proxy)
                        }
                        $Response = Invoke-WebRequest -UseBasicParsing @RequestParameters
                        if ( ($null -ne $Response) -and ( 200 -eq $Response.StatusCode )) {
                            if ($ExpectedResult) {
                                if ($ExpectedResult -eq $Response.Content) {
                                    $Status = 'success'
                                }
                                else {
                                    $Status = 'error'
                                }
                            }
                            else {
                                $Status = 'success'
                            }
                        }
                        else {
                            $Status = 'error'
                        }
                    }
                    catch {
                        Write-Host "$($error[0])"
                        $Status = 'error'
                    }
                    $CurrentResult = [PSCustomObject]@{
                        Status = $Status
                        URI    = $URI
                        Proxy  = $Proxy
                    }
                    $CurrentResult
                }
            }
        }
        if ($ComputerName -and ($ComputerName -ne $Env:COMPUTERNAME)) {
            $ICMParams = @{
                ComputerName = $ComputerName
                ScriptBlock  = $ScriptBlock
                ArgumentList = @($URIList, $Headers, $Body, $Method, $ExpectedResult, $ProxyList)
            }
            if ($Credential) { $ICMParams.Add('Credential', $Credential) }
            $RemoteResults = Invoke-Command @ICMParams
        }
        else {
            $RemoteResults = $ScriptBlock.Invoke($URIList, $Headers, $Body, $Method, $ExpectedResult, $ProxyList)
        }
        $RemoteResults.ForEach({
                $URIResults.Add([PSCustomObject]@{
                        Status = $_.Status
                        URI    = $_.URI
                        Proxy  = $_.Proxy
                    }) | Out-Null
            })
    }
    catch {
        $URIResults.Add([PSCustomObject]@{
                Status = 'error'
                URI    = 'Error checking URI'
                Proxy  = $error[0].exception.message
        }) | Out-Null
    }
    Write-Output -NoEnumerate $URIResults
}
function Test-DNSServerRemote {
    <#
    .SYNOPSIS
        Resolves a set of host names against a set of DNS servers from a remote host.

    .DESCRIPTION
        Runs Resolve-DnsName inside Invoke-Command so that resolution is exercised from the
        target host's network position. Every host name is queried against every DNS server,
        producing a full matrix of results, which is what catches a single resolver in a
        site that has drifted out of sync.

        Queries are type A, DnsOnly (no NetBIOS or LLMNR fallback), and QuickTimeout. A
        lookup is 'success' only when the resolver returns an address; an empty answer and a
        thrown query both report 'error'.

    .PARAMETER ComputerName
        The host to run the lookups from. Must be reachable over PowerShell remoting.

    .PARAMETER DNSServer
        DNS server addresses to query. Every server is tested against every host name.

    .PARAMETER HostName
        Host names to resolve. Pick records that prove the resolver is answering for the
        zones that matter.

    .PARAMETER Credential
        Optional credential for the remoting session.

    .OUTPUTS
        System.Collections.ArrayList of PSCustomObject with Status, DNSServer, and HostName.
        On a remoting failure, a single record carrying only DNSTest = 'error' is returned.

    .EXAMPLE
        Test-DNSServerRemote -ComputerName 'Initech-LAB01' `
                             -DNSServer '10.10.1.10','10.10.2.10' `
                             -HostName 'cad.Initech.com','relay.initech.com'

        Confirms both site resolvers answer for both records.

    .NOTES
        Get-DailyStatus casts the DNSServer values before invoking this function, because
        the JSON configuration carries them as objects with an IP property rather than as
        bare strings.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName,

        [Parameter()]
        [ipaddress[]]
        $DNSServer,

        [Parameter()]
        [string[]]
        $HostName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential

    )
    $Status = 'Error'
    $DNSResults = New-Object System.Collections.ArrayList
    $Error.Clear()
    $Command = @{
        ComputerName = $ComputerName
        ScriptBlock  = [System.Management.Automation.ScriptBlock] {
            Foreach ($Server in $Using:DNSServer) {
                Foreach ($CurrentHostName in $using:HostName) {
                    try {
                        $DNSRecord = Resolve-DnsName -Type A -Server $Server.ToString() -Name $CurrentHostName -DnsOnly -QuickTimeout
                        if ($DNSRecord.IPAddress) {
                            $Status = 'success'
                        }
                        else {
                            $Status = 'error'
                        }
                    }
                    catch {
                        $Status = 'error'
                    }
                    [PSCustomObject]@{
                        'Status'    = $Status
                        'DNSServer' = $Server.ToString()
                        'HostName'  = $CurrentHostName
                    }
                    Remove-Variable -Name 'Status'
                }
            }
        }
    }
    if ($Credential) {
        $Command.Add('Credential', $Credential)
    }
    try {
        $RemoteResults = Invoke-Command @Command
        $RemoteResults.ForEach({
                $DNSResults.Add([PSCustomObject]@{
                        'Status'   = $_.Status
                        DNSServer  = $_.DNSServer
                        'HostName' = $_.HostName
                    }) | Out-Null
            })
    }
    catch {
        Write-Host "Error was $($Error | ConvertTo-Json | Out-String)"
        $DNSResults.Add([PSCustomObject]@{
                DNSTest = 'error'
            }) | Out-Null
    }
    return $DNSResults
}
function Get-AllVBRJobs {
    <#
    .SYNOPSIS
        Collects the last result of every backup job from one or more Veeam B and R servers.

    .DESCRIPTION
        Queries each Veeam Backup and Replication server for three job families and
        normalizes them into a single result shape:

            Get-VBRJob                  - virtual machine backup and replication jobs
            Get-VBRComputerBackupJob    - agent backup jobs
            Get-VBRComputerBackupCopyJob - agent backup copy jobs

        Each server is queried in its own background job so that a slow or unresponsive VBR
        server does not serialize the whole collection, and the results are drained as the
        jobs complete.

        Because the Veeam cmdlets must run where the console is installed, the work happens
        inside Invoke-Command against the VBR server itself.

    .PARAMETER VBRServer
        One or more Veeam Backup and Replication server names to query.

    .PARAMETER Credential
        Optional credential for the remoting session to the VBR servers.

    .PARAMETER JobTimeOut
        Seconds a single server's background job may run before it is reported as timed out.
        Defaults to 300. Measured from the job's PSBeginTime, so it bounds total elapsed
        time rather than idle time.

    .OUTPUTS
        System.Collections.ArrayList of PSCustomObject with Status, VBRServer, and JobName.
        Status carries the Veeam result verb (Success, Warning, Failed, None), which
        Get-Severity normalizes. A server that does not deliver
        rows produces one synthesized record instead, with the server name in VBRServer and
        the reason in JobName: 'Timed Out' or the failing exception at Status 'error', or
        'Job Returned no results' at Status 'warning'.

    .EXAMPLE
        Get-AllVBRJobs -VBRServer 'VEEAM01','VEEAM02' | Where-Object Status -ne 'Success'

        Lists every job on either server whose last run was not clean.

    .EXAMPLE
        Get-AllVBRJobs -VBRServer 'VEEAM01' -JobTimeOut 600

        Allows ten minutes for a server with a large job inventory.

    .NOTES
        All three terminal states are handled and none of them can leave a job in $JobList:
        
        Completed projects its rows, or synthesizes one warning record when it returned
        none.
        
        Failed synthesizes an error record.
        
        Timeout  stops and force-removes the job.
        
        Every synthesized record names the server, so a caller can tell which one is in
        trouble rather than seeing a bare count.

        An empty result set is a warning here rather than an error, on the reasoning that a
        VBR server with nothing to report is unusual but not proof of failure. Get-DailyStatus
        treats an empty set as an error, so the two functions disagree on that one case by
        design.

        The catch block covers dispatch of the whole set, so its single record reports the
        entire VBRServer array and does not identify which server failed.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $VBRServer,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,
        [Parameter()]
        [int]
        $JobTimeOut = 300
    )
    $Results = New-Object System.Collections.ArrayList
    $JobList = New-Object System.Collections.ArrayList
    try {
        foreach ($CurrentVBRServer in $VBRServer) {
            $JobList.Add([PSCustomObject]@{
                    JobDescription = $CurrentVBRServer
                    Job            = Start-Job {
                        $CurrentVBRServer = $Using:CurrentVBRServer
                        $Command = @{
                            ComputerName = $CurrentVBRServer
                            ScriptBlock  = [System.Management.Automation.ScriptBlock] {
                                Get-VBRJob | ForEach-Object {
                                    [PSCustomObject]@{
                                        Status    = $_.GetLastResult().ToString().Trim()
                                        VBRServer = $Using:CurrentVBRServer
                                        JobName   = $_.Name
                                    }
                                }

                                Get-VBRComputerBackupJob | ForEach-Object {
                                    [PSCustomObject]@{
                                        Status    = [Veeam.Backup.Core.CBackupJob]::FindLastSession($_.Id).Result.ToString().Trim()
                                        VBRServer = $Using:CurrentVBRServer
                                        JobName   = $_.Name
                                    }
                                }

                                Get-VBRComputerBackupCopyJob | ForEach-Object {
                                    [PSCustomObject]@{
                                        Status    = $_.LastResult.ToString().Trim()
                                        VBRServer = $Using:CurrentVBRServer
                                        JobName   = $_.Name
                                    }
                                }
                            }
                        }
                        if ($Using:Credential) {
                            $Command.Add('Credential', $Using:Credential)
                        }

                        Invoke-Command @Command
                    }
                }) | Out-Null
        }
        #region Collect Results
        While ($JobList.Count -gt 0) {
            #$CompletedJobList = $JobList.Where({ $_.Job.State -eq 'Completed' })
            Foreach ($CurrentJob in @($JobList)) {
                if ($CurrentJob.Job.State -eq 'Completed') {
                    $CompletedJobResults = Receive-Job -Job $CurrentJob.Job
                    if ($CompletedJobResults) {
                        $CompletedJobResults.Foreach({
                                $Results.Add([PSCustomObject]@{
                                        Status    = $_.Status
                                        VBRServer = $_.VBRServer
                                        JobName   = $_.JobName
                                    }) | Out-NUll
                            })
                    }
                    else {
                        $Results.Add([PSCustomObject]@{
                                Status    = 'warning'
                                VBRServer = $CurrentJob.JobDescription
                                JobName   = 'Job Returned no results'
                            }) | Out-NUll
                    }
                    Remove-Job -Confirm:$false -Force -Job $CurrentJob.Job
                    $JobList.Remove($CurrentJob)
                }
                elseif ($CurrentJob.Job.State -eq 'Failed') {
                    $Results.Add([PSCustomObject]@{
                            Status    = 'error'
                            VBRServer = $CurrentJob.JobDescription
                            JobName   = $CurrentJob.Job.ChildJobs[0].JobStateInfo.Reason.Message
                        }) | Out-NUll
                    Remove-Job -Confirm:$false -Force -Job $CurrentJob.Job
                    $JobList.Remove($CurrentJob)
                }
                elseif (((Get-Date) - $CurrentJob.Job.PSBeginTime).TotalSeconds -gt $JobTimeOut) {
                    $Results.Add([PSCustomObject]@{
                            Status    = 'error'
                            VBRServer = $CurrentJob.JobDescription
                            JobName   = 'Timed Out'
                        }) | Out-Null
                    Stop-Job -Confirm:$false -Job $CurrentJob.Job
                    Remove-Job -Confirm:$false -Force -Job $CurrentJob.Job
                    $JobList.Remove($CurrentJob)
                }
            }
            Start-Sleep -Seconds 1
        }
        #endregion
    }
    catch {
        $Results.Add([PSCustomObject]@{
                Status    = 'error'
                VBRServer = $VBRServer
                JobName   = 'Could not collect Veeam job status'
            }) | Out-Null
    }
    Return $Results
}
Function Get-TriggeredVMWareAlarms {
    <#
    .SYNOPSIS
        Returns currently triggered alarms from one or more vCenter servers.

    .DESCRIPTION
        Connects to each vCenter, reads the TriggeredAlarmState collection off the
        Datacenters root folder, and resolves each entry's alarm definition and entity into
        readable names via Get-View. Acknowledgement state is included so alarms an operator
        has already picked up can be filtered out by the caller.

        Multiple-server mode is enabled for the session before connecting. The disconnect
        and the restore of the previous toolkit setting both run after the try/catch and are
        individually guarded, so a failure part way through leaves neither a live session nor
        a changed PowerCLI configuration behind.

        A vCenter with no triggered alarms emits one record with Alarm = 'none' and
        Status = 'info', which keeps the site visible in the report rather than absent.

    .PARAMETER VIServer
        One or more vCenter server names to query.

    .PARAMETER Credential
        Optional credential for Connect-VIServer. Omit to use pass-through Windows
        authentication.

    .OUTPUTS
        PSCustomObject stream with VC, Alarm, Entity, EntityType, Status, Time,
        Acknowledged, AckBy, and AckTime. Status carries the vSphere overall status colour
        (green, yellow, red), which Get-Severity normalizes.

    .EXAMPLE
        Get-TriggeredVMWareAlarms -VIServer 'vcenter01.initech.com' |
            Where-Object { $_.Acknowledged -ne $true }

        Shows only alarms nobody has acknowledged yet.

    .NOTES
        Requires VMware PowerCLI. The cleanup disconnects only the sessions that actually
        connected, so a run against a mix of reachable and unreachable vCenters leaves
        nothing open and writes nothing extra to the error stream.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $VIServer,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )
    try {
        $SavedConfiguration = Get-VIToolkitConfiguration -Scope Session
        Set-VIToolkitConfiguration -Scope Session -DefaultVIServerMode Multiple -Confirm:$false | Out-Null
        $ConnectionParameters = @{
            Server = $VIServer
        }
        if ($Credential) {
            $ConnectionParameters.Add('Credential', $Credential)
        }
        if (Connect-VIServer @ConnectionParameters) {
            foreach ( $Server in $VIServer) {
                $rootFolder = Get-Folder -Server $Server "Datacenters"
                if ($rootFolder.ExtensionData.TriggeredAlarmState) {
                    foreach ($TriggeredAlarm in $rootFolder.ExtensionData.TriggeredAlarmState) {
                        [PSCustomObject]@{
                            VC           = $Server
                            Alarm        = (Get-View -Server $Server $TriggeredAlarm.Alarm).Info.Name
                            Entity       = (Get-View -Server $Server $TriggeredAlarm.Entity).Name
                            EntityType   = (Get-View -Server $Server $TriggeredAlarm.Entity).GetType().Name
                            Status       = $TriggeredAlarm.OverallStatus
                            Time         = $TriggeredAlarm.Time
                            Acknowledged = $TriggeredAlarm.Acknowledged
                            AckBy        = $TriggeredAlarm.AcknowledgedByUser
                            AckTime      = $TriggeredAlarm.AcknowledgedTime
                        }
                    }
                }
                else {
                    [PSCustomObject]@{
                        VC           = $Server
                        Alarm        = 'none'
                        Entity       = ''
                        EntityType   = ''
                        Status       = 'info'
                        Time         = ''
                        Acknowledged = ''
                        AckBy        = ''
                        AckTime      = ''
                    }
                }
            }
        }
        else {
            [PSCustomObject]@{
                VC           = $Server
                Alarm        = $Error
                Entity       = ''
                EntityType   = ''
                Status       = 'Error'
                Time         = ''
                Acknowledged = ''
                AckBy        = ''
                AckTime      = ''
            }
        }
    }
    catch {
        [PSCustomObject]@{
            VC           = $Server
            Alarm        = $Error
            Entity       = ''
            EntityType   = ''
            Status       = 'Error'
            Time         = ''
            Acknowledged = ''
            AckBy        = ''
            AckTime      = ''
        }
    }
    if ($global:DefaultVIServers -and ($global:DefaultVIServers.IsConnected -contains $true)) {
        Disconnect-VIServer -Server @($global:DefaultVIServers).Where({ $_.IsConnected })  -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } 
    if ($SavedConfiguration) {
        Set-VIToolkitConfiguration -Scope Session -DefaultVIServerMode $SavedConfiguration.DefaultVIServerMode  -Confirm:$false | Out-Null
    }
}
function Get-UCSHealth {
    <#
    .SYNOPSIS
        Returns outstanding faults from a Cisco UCS Manager domain.

    .DESCRIPTION
        Connects to UCS Manager using a saved session file and its matching encryption key,
        enumerates all current faults, and projects the fault severity onto a Status
        property that Get-Severity can normalize.

        A domain with no faults returns one informational placeholder record so the domain
        still appears in the report.

        Multiple-default-UCS support is turned on for the call and the prior setting is
        restored afterwards, so the caller's PowerTool configuration is left as found.

    .PARAMETER SessionPath
        Path to the saved UCS session file created by Export-UcsPSSession.

    .PARAMETER KeyPath
        Path to the CLIXML key file used to decrypt the credentials inside the session file.

    .OUTPUTS
        PSCustomObject collection with Ucs, Status, Code, Descr, and Dn. Status carries the
        UCS severity (critical, major, minor, warning, info) for Get-Severity to map.

    .EXAMPLE
        Get-UCSHealth -SessionPath 'C:\Scripts\Config\ucs.session' -KeyPath 'C:\Scripts\Config\ucs.key'

        Returns all outstanding faults for the saved domain.

    .NOTES
        Requires the Cisco.UCS.Common and Cisco.UCSManager modules, which are imported
        inside the function.

        The session and key files are per-account: the key can only be decrypted by the
        identity that exported it, so scheduled-task runs need files exported under the
        service account.

        Connection failures are returned as a single Status = 'Error' record carrying the
        error text in Descr, rather than thrown. The disconnect is wrapped in its own
        try/catch that intentionally swallows errors, since there may be no live session.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $SessionPath,
        [Parameter(Mandatory = $true)]
        [string]
        $KeyPath
    )
    try {
        $Error.Clear()
        Import-Module Cisco.UCS.Common
        Import-Module Cisco.UCSManager
        $Key = Import-Clixml -Path $KeyPath
        $SupportMultipleDefaultUCS = (Get-UcsPowerToolConfiguration).SupportMultipleDefaultUcs
        Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $true -Force | Out-Null
        Connect-Ucs -Path $SessionPath -Key $Key | Out-Null
        $Faults = Get-UcsFault | Select-Object Ucs, @{N = 'Status'; E = { $_.Severity } }, Code, Descr, Dn
        if ($Faults) {
            $Result = $Faults
        }
        else {
            $Result = @([PSCustomObject]@{
                    Ucs    = 'N/A'
                    Status = 'Info'
                    Code   = 'NA0000'
                    Descr  = "No Faults Found"
                    Dn     = 'No Faults Found'
                })

        }
    }
    catch {
        $Result = @([PSCustomObject]@{
                Ucs    = 'N/A'
                Status = 'Error'
                Code   = 'NA0000'
                Descr  = "Could not connect to saved UCS Session $SessionPath. The Error was `n$($Error | out-string)"
                Dn     = 'Local Error'
            })
    }
    try {
        Set-UcsPowerToolConfiguration -SupportMultipleDefaultUcs $SupportMultipleDefaultUCS -Force | Out-Null
        Disconnect-Ucs | Out-Null
    }
    catch {
        #Nop here. Need to swallow errors because we may not be connected.
    }
    return $Result
}
function Get-AGOEventStatus {
    <#
    .SYNOPSIS
        Reduces a set of ArcGIS Online service events to a single status string.

    .DESCRIPTION
        Examines each event attached to an ArcGIS Online service. If every event is marked
        resolved, the service is reported as functioning normally; a single unresolved event
        flips the whole service to an issue state.

    .PARAMETER Events
        The events collection from one service node of the ArcGIS Online status feed.

    .OUTPUTS
        System.String. Either 'Functioning Normally' or 'Is Experiencing Issues', both of
        which Get-Severity recognizes.

    .EXAMPLE
        Get-AGOEventStatus -Events $Service.events

        Collapses one service's event list to a status string.

    .NOTES
        Defined at module scope but also serialized and shipped into the remote session by
        Get-AGOStatus, since the remote scriptblock cannot see module-scoped functions.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Object[]]
        $Events
    )
    $Status = 'Functioning Normally'
    foreach ($CurrentEvent in $Events) {
        if ($CurrentEvent.resolved -ne 'True') {
            $Status = 'Is Experiencing Issues'
        }
    }
    return $Status
}
function Get-AGOStatus {
    <#
    .SYNOPSIS
        Retrieves per-service status from the ArcGIS Online status feed.

    .DESCRIPTION
        Fetches the ArcGIS Online status JSON and emits one record per service, with the
        event list collapsed to a status string by Get-AGOEventStatus.

        The call can be made locally or from a remote host. Running it remotely matters when
        the only egress path to the internet is from a specific server; when ComputerName is
        supplied the request is made from there, otherwise the scriptblock is invoked in the
        current session.

        Because a remote scriptblock cannot see module-scoped functions, Get-AGOEventStatus
        is captured as source text and recreated inside the session before it is called.

    .PARAMETER ComputerName
        Optional host to run the status fetch from. Omit to run locally.

    .PARAMETER AGOStatusURL
        URI of the ArcGIS Online status JSON feed.

    .PARAMETER Credential
        Optional credential for the remoting session. Only used when ComputerName is set.

    .OUTPUTS
        PSCustomObject stream with 'Service Name', 'Status', and 'Event Details'.

    .EXAMPLE
        Get-AGOStatus -AGOStatusURL 'https://status.arcgis.com/api/v1/status.json'

        Fetches status directly from the current machine.

    .EXAMPLE
        Get-AGOStatus -ComputerName 'CONTOSO-APP01' -AGOStatusURL $Config.AGOStatusURL

        Fetches through the host that holds the internet egress path.

    .NOTES
        Fetch or parse failures produce a single record whose 'Service Name' and 'Status'
        both read 'Error Retrieving Status', with the exception text in 'Event Details'.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName,
        [Parameter()]
        [string]
        $AGOStatusURL,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    $AGOEventStatusDef = "function Get-AGOEventStatus { $(Get-Content -Raw Function:\Get-AGOEventStatus) }"
    $StatusCode = [ScriptBlock] {
        [CmdletBinding()]
        param (
            [Parameter()]
            [string]
            $AGOStatusURL,
            [Parameter()]
            [string]
            $AGOStatusFunction
        )
        . ([ScriptBlock]::Create($AGOStatusFunction))
        $JSResponse = Invoke-RestMethod -Uri $AGOStatusURL
        try {
            $error.Clear()
            $Status = foreach ($Service in $JSResponse.services) {
                [PSCustomObject]@{
                    'Service Name'  = $Service.Name
                    'Status'        = Get-AGOEventStatus $Service.events
                    'Event Details' = $Service.events.event
                }
            }
        }
        catch {
            $Status = @([PSCustomObject]@{
                    'Service Name'  = 'Error Retrieving Status'
                    'Status'        = 'Error Retrieving Status'
                    'Event Details' = @($($error[0] | Out-String))
                })
        }
        return $Status
    }

    if ($ComputerName) {
        $RunParameters = @{
            ComputerName = $ComputerName
            ScriptBlock  = $StatusCode
            ArgumentList = $AGOStatusURL, $AGOEventStatusDef
        }
        if ($Credential) {
            $RunParameters.Add('Credential', $Credential)
        }
        $StatusResult = Invoke-Command @RunParameters
    }
    else {
        $StatusResult = $StatusCode.Invoke($AGOStatusURL, $AGOEventStatusDef)
    }
    return ($StatusResult | Select-Object 'Service Name', 'Status', 'Event Details')
}
function New-SWISQuery {
    <#
    .SYNOPSIS
        Runs a SWQL query against a SolarWinds Information Service endpoint.

    .DESCRIPTION
        Opens a SWIS connection to the Orion server and executes the supplied SWQL query.
        Authentication is either an explicit Orion credential or the current Windows
        identity when -Trusted is used.

        Acts as the single connection point for the Get-SWIS* reporting functions so that
        connection handling lives in one place.

    .PARAMETER ComputerName
        Accepted for signature consistency with the other collectors in this module. The
        query is executed against SWISServer, not against this host.

    .PARAMETER SWISServer
        Host name of the Orion server exposing the SWIS endpoint.

    .PARAMETER SWISQuery
        The SWQL query text to execute.

    .PARAMETER Credential
        Orion credential to authenticate with. Mutually exclusive in practice with -Trusted.

    .PARAMETER Trusted
        Authenticate as the current Windows identity instead of supplying a credential.

    .OUTPUTS
        The query result rows, or $false when the query returns nothing.

    .EXAMPLE
        New-SWISQuery -SWISServer 'orion01' -Trusted -SWISQuery 'SELECT Caption FROM Orion.Nodes WHERE Status = 2'

        Returns the down nodes using the caller's Windows identity.

    .NOTES
        Requires the SwisPowerShell module. Returns $false rather than an empty collection
        on no results, so test the return value before enumerating it.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [string]
        $SWISServer,
        [Parameter(Mandatory = $true)]
        [string]
        $SWISQuery,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,
        [Parameter()]
        [switch]
        $Trusted
    )

    $result = $false

    $ConnectionParameters = @{
        Hostname = $SWISServer
    }

    if ($Credential) {
        $ConnectionParameters.Add('Credential', $Credential)
    }
    if ($Trusted) {
        $ConnectionParameters.Add('Trusted', $true)
    }

    $SwisConnection = Connect-Swis @ConnectionParameters
    $SwisDataQuery = @{
        SwisConnection = $SwisConnection
        Query          = $SwisQuery
        Parameters     = @{}
    }
    $SwisData = Get-SwisData  @SwisDataQuery
    if ($SwisData) {
        $Result = $SwisData
    }
    return $Result
}
function Get-SWISNodesDown {
    <#
    .SYNOPSIS
        Returns nodes currently in a down state in SolarWinds Orion.

    .DESCRIPTION
        Queries Orion.Nodes for every node whose Status is 2 (down) and returns the node
        caption along with a deep link into the Orion node details page.

        When nothing is down, a single informational record is returned so the check still
        reports something rather than disappearing.

    .PARAMETER ComputerName
        Accepted for signature consistency with the other collectors. Not used for the query.

    .PARAMETER SWISServer
        Host name of the Orion server. Also used to build the https links in the output.

    .PARAMETER Credential
        Orion credential to authenticate with.

    .PARAMETER Trusted
        Authenticate as the current Windows identity instead of supplying a credential.

    .OUTPUTS
        PSCustomObject stream with Node, Status, and 'Node Details'.

    .EXAMPLE
        Get-SWISNodesDown -SWISServer 'orion01' -Trusted

        Lists every down node with a link to its Orion details page.

    .NOTES
        Query failures return one record with Status = 'Error' rather than throwing.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [string]
        $SWISServer,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,
        [Parameter()]
        [switch]
        $Trusted
    )

    
    $SWISQuery = @'
SELECT
  [Nodes].Caption AS [Node]
, 'https://{0}' + [Nodes].DetailsURL AS [NodeDetailsLink]
, [Nodes].Status AS [Status]

, CASE 
    WHEN ToString([Nodes].Status) = '2' THEN 'DOWN'
  END AS [Operational Status]

FROM Orion.Nodes [Nodes]

WHERE [Nodes].Status = 2
'@ -f $SWISServer
    $Error.Clear()
    try {
        $SWISData = New-SWISQuery -SWISServer:$SWISServer -Credential:$Credential -Trusted:$Trusted -SWISQuery $SWISQuery
        if ($SWISData) {
            Foreach ($Row in $SWISData) {
                [PSCustomObject]@{
                    Node           = $Row.Node
                    Status         = $Row.'Operational Status'
                    'Node Details' = $Row.NodeDetailsLink
                }
            }
        }
        else {
            [PSCustomObject]@{
                Node           = 'No Nodes down'
                Status         = 'Info'
                'Node Details' = 'https://{0}' -f $SWISServer
            }
        }
    }
    catch {
        [PSCustomObject]@{
            Node           = 'Error Retrieving down nodes'
            Status         = 'Error'
            'Node Details' = 'https://{0}' -f $SWISServer
        }
    }

}
function Get-SWISInterfacesDown {
    <#
    .SYNOPSIS
        Returns every interface currently down in SolarWinds Orion.

    .DESCRIPTION
        Joins Orion.Nodes to the active alert tables to find interfaces whose status is down
        and that have a matching active 'Interface down' alert, ordered most recent first.
        Joining to the alert table rather than reading interface status alone means
        administratively shut interfaces and stale entries without an active alert stay out
        of the report.

        Output carries deep links to both the node and the interface details pages.

        When nothing is down, a single informational record is returned so the check still
        reports something.

    .PARAMETER ComputerName
        Accepted for signature consistency with the other collectors. Not used for the query.

    .PARAMETER SWISServer
        Host name of the Orion server. Also used to build the https links in the output.

    .PARAMETER Credential
        Orion credential to authenticate with.

    .PARAMETER Trusted
        Authenticate as the current Windows identity instead of supplying a credential.

    .OUTPUTS
        PSCustomObject stream with Node, Status, 'Node Details', Interface, and
        'Interface Details'. Interface is rendered as "Node - Interface" so it reads
        unambiguously in a report where the same interface alias appears on many devices.

    .EXAMPLE
        Get-SWISInterfacesDown -SWISServer 'orion01' -Trusted

        Lists every interface-down event, newest first.

    .EXAMPLE
        Get-SWISInterfacesDown -SWISServer 'orion01' -Trusted | Select-Object -First 10

        Caps the list at the ten most recent, which is what the query itself used to do.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [string]
        $SWISServer,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,
        [Parameter()]
        [switch]
        $Trusted
    )
    $SWISQuery = @'
SELECT

 [Nodes].Caption AS [Node]
, 'https://{0}' + [Nodes].DetailsURL AS [NodeDetailsLink]
, [Nodes].Status AS [Status]
, [Nodes].Interfaces.Alias AS [Interface]
, 'https://{0}' + [Nodes].Interfaces.DetailsUrl AS [InterfaceDetailsLink]

, CASE 
WHEN ToString([Nodes].Interfaces.AdminStatus) = '1' THEN 'UP'
WHEN ToString([Nodes].Interfaces.AdminStatus) = '4' THEN 'SHUTDOWN'
ELSE 'DOWN'
END AS [Administrative Status]

, CASE
WHEN ToString([Nodes].Interfaces.OperStatus) = '1' THEN 'UP'
ELSE 'DOWN'
END AS [Operational Status]

, ToLocal([Alerts].TriggeredDateTime) AS [Down Time]
, [Alerts].TriggeredMessage AS [RFO]

FROM Orion.Nodes [Nodes]
JOIN Orion.AlertObjects AS [Objects] ON [Objects].RelatedNodeId = [Nodes].NodeId AND [Objects].EntityUri = [Nodes].Interfaces.Uri
JOIN Orion.AlertActive AS [Alerts] ON [Alerts].AlertObjectId = [Objects].AlertObjectId

WHERE [Nodes].Interfaces.Status = 2
AND [Alerts].TriggeredMessage LIKE '%Interface%down%'

ORDER BY [Alerts].TriggeredDateTime DESC
'@ -f $SWISServer

    try {
        $SWISData = New-SWISQuery -SWISServer:$SWISServer -Credential:$Credential -Trusted:$Trusted -SWISQuery $SWISQuery
        if ($SWISData) {
            Foreach ($Row in $SWISData) {
                [PSCustomObject]@{
                    Node                = $Row.Node
                    Status              = $Row.'Operational Status'
                    'Node Details'      = $Row.NodeDetailsLink
                    Interface           = "{0} - {1}" -f $Row.Node, $Row.Interface
                    'Interface Details' = $Row.InterfaceDetailsLink
                }
            }
        }
        else {
            [PSCustomObject]@{
                Node                = 'No Interfaces down'
                Status              = 'Info'
                'Node Details'      = 'https://{0}' -f $SWISServer
                Interface           = 'None'
                'Interface Details' = 'https://{0}' -f $SWISServer
            }
        }
    }
    catch {
        [PSCustomObject]@{
            Node                = 'Error Retrieving down nodes'
            Status              = 'Failed'
            'Node Details'      = 'https://{0}' -f $SWISServer
            Interface           = 'None'
            'Interface Details' = 'https://{0}' -f $SWISServer
        }
    }
}
function Get-SWISAlerts {
    <#
    .SYNOPSIS
        Returns all currently active alerts from SolarWinds Orion.

    .DESCRIPTION
        Reads Orion.AlertActive joined to the alert object and alert configuration tables,
        translating the numeric severity into the module's status vocabulary and computing
        how long each alert has been active in hours and minutes.

        Deep links are built for the alert, the triggering object, and the related node, so
        an operator can jump straight from the report to the right Orion page.

        When nothing is active, a single informational record is returned so the check still
        reports something.

    .PARAMETER ComputerName
        Accepted for signature consistency with the other collectors. Not used for the query.

    .PARAMETER SWISServer
        Host name of the Orion server. Also used to build the https links in the output.

    .PARAMETER Credential
        Orion credential to authenticate with.

    .PARAMETER Trusted
        Authenticate as the current Windows identity instead of supplying a credential.

    .OUTPUTS
        PSCustomObject stream with Status, Alert, 'Alert Details', Object,
        'Entity Details', Message, Node, 'Node Details', 'Triggered Date',
        'Last Triggered On', and ActiveTime.

    .EXAMPLE
        Get-SWISAlerts -SWISServer 'orion01' -Trusted | Where-Object Status -eq 'error'

        Shows only critical and serious active alerts.

    .NOTES
        Severity mapping:
            0 info
            1 warning
            2 and 3 error
            4 Notice
            
        Note that 'Notice' is not one of the four values Get-Severity recognizes, so those rows fall through to
        'info' in the rollup.

        Active time is computed against GETUTCDATE, so it is correct regardless of the
        reporting host's time zone.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [string]
        $SWISServer,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,
        [Parameter()]
        [switch]
        $Trusted
    )
    $SWISQuery = @'
SELECT
    ac.Name AS [Alert],
    CASE ac.Severity
        WHEN 0 THEN 'info'
        WHEN 1 THEN 'warning'
        WHEN 2 THEN 'error'
        WHEN 3 THEN 'error'
        WHEN 4 THEN 'Notice'
        ELSE CONCAT('Unknown Severity: ', Severity)
    END AS [Status],
    ac.AlertMessage AS [Message],
    '/Orion/NetPerfMon/ActiveAlertDetails.aspx?NetObject=AAT:' + ToString(ao.AlertObjectID) AS [AlertDetailsURL],
    ao.EntityDetailsUrl,
    ao.EntityCaption AS [Object],
    aa.TriggeredDateTime as [Triggered Date],
    ao.LastTriggeredDateTime AS [Last Triggered On], 
    ao.RelatedNodeCaption AS [Node], 
    ao.RelatedNodeDetailsUrl AS [NodeDetailsURL],
    CASE
        WHEN aa.TriggeredDateTime IS NULL THEN NULL
    ELSE (TOSTRING(FLOOR(MINUTEDIFF(aa.TriggeredDateTime,GETUTCDATE())/60.0)) + 'h ' + TOSTRING(MINUTEDIFF(aa.TriggeredDateTime,GETUTCDATE())%60) + 'm')
    END AS [ACTIVE TIME]

FROM Orion.AlertActive AS aa 
LEFT OUTER JOIN Orion.AlertObjects AS ao ON aa.AlertObjectID = ao.AlertObjectID
LEFT OUTER JOIN Orion.AlertConfigurations AS ac ON ao.AlertID = ac.AlertID
ORDER BY  aa.TriggeredDateTime
'@
    try {
        $SWISData = New-SWISQuery -SWISServer:$SWISServer -Credential:$Credential -Trusted:$Trusted -SWISQuery $SWISQuery
        if ($SWISData) {
            Foreach ($Row in $SWISData) {
                [PSCustomObject]@{
                    Status              = $Row.Status
                    Alert               = $Row.Alert
                    'Alert Details'     = 'https://{0}{1}' -f $SWISServer, $Row.AlertDetailsURL
                    Object              = $Row.Object
                    'Entity Details'    = 'https://{0}{1}' -f $SWISServer, $Row.EntityDetailsURL
                    Message             = $Row.Message
                    Node                = $Row.Node
                    'Node Details'      = 'https://{0}{1}' -f $SWISServer, $Row.NodeDetailsURL
                    'Triggered Date'    = $Row.'Triggered Date'
                    'Last Triggered On' = $Row.'Last Triggered On'
                    ActiveTime          = $Row.'ACTIVE TIME'
                }
            }
        }
        else {
            [PSCustomObject]@{
                Status              = 'Info'
                Alert               = 'No Alerts ACtive'
                'Alert Details'     = ''
                Object              = ''
                'Entity Details'    = ''
                Message             = ''
                Node                = ''
                'Node Details'      = ''
                'Triggered Date'    = ''
                'Last Triggered On' = ''
                ActiveTime          = ''
            }
        }
    }
    catch {
        [PSCustomObject]@{
            Status              = 'Error'
            Alert               = 'Error Retrieving Alerts'
            'Alert Details'     = ''
            Object              = ''
            'Entity Details'    = ''
            Message             = ''
            Node                = ''
            'Node Details'      = ''
            'Triggered Date'    = ''
            'Last Triggered On' = ''
            ActiveTime          = ''
        }
    }
}
function New-HVACResponse {
    <#
    .SYNOPSIS
        Builds a single HVAC status record in the module's standard shape.

    .DESCRIPTION
        Constructs the PSCustomObject that every HVAC code path emits, so that real alarms,
        communication failures, and the no-events case all share one schema and can be
        rendered by the same consumer without special-casing.

    .PARAMETER Status
        Status value for the record, in the module's severity vocabulary. Defaults to
        'warning'.

    .PARAMETER Category
        Alarm category, resolved from the controller's report label.

    .PARAMETER ReportURI
        Deep link into the controller's monitor page for this report.

    .PARAMETER EventText
        The event label as presented by the controller.

    .PARAMETER Attribute
        The point attribute value returned by the controller. Its meaning is not yet
        confirmed; it is not the point status.

    .PARAMETER Description
        The point description, or the failure detail on an error record.

    .OUTPUTS
        PSCustomObject with Status, Category, 'Report URI', Event, Attribute, and
        Description.

    .EXAMPLE
        New-HVACResponse -Status 'error' -Category 'Communications' -EventText 'Failure' -Description 'Failed to retrieve event list'

        Builds the record used when a controller cannot be reached.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Status = 'warning',
        [Parameter()]
        [string]
        $Category = '',
        [Parameter()]
        [string]
        $ReportURI = '',
        [Parameter()]
        [string]
        $EventText = '',
        [Parameter()]
        [string]
        $Attribute = '',
        [Parameter()]
        [string]
        $Description = ''
    )
    [PSCustomObject]@{
        Status       = $Status
        Category     = $Category
        'Report URI' = $ReportUri
        Event        = $EventText
        Attribute    = $Attribute
        Description  = $Description
    }
}
function ConvertFrom-EventResponse {
    <#
    .SYNOPSIS
        Turns an HVAC controller's key/value response into readable status records.

    .DESCRIPTION
        The controller answers the detail query with a flat body of key="value" pairs, where
        the keys encode what they describe and which point or report they belong to:

            pl<PointId>   point label, used as the event text
            pd<PointId>   point description
            pa<PointId>   point attribute
            rl<A>~<B>     report label, used as the category

        This function parses the body into a lookup table, then walks the event objects
        produced by ConvertFrom-EventList and pulls each one's four values out of the
        lookup, building a deep link back into the controller's monitor page.

    .PARAMETER Response
        The raw response body from the detail query.

    .PARAMETER EventObjects
        The parsed event collection from ConvertFrom-EventList, which supplies the point and
        report identifiers used to index into the lookup.

    .PARAMETER BaseHost
        Scheme and host of the controller, for example http://10.20.30.40, used to build the
        report links.

    .OUTPUTS
        PSCustomObject stream in the New-HVACResponse shape, one record per event.

    .EXAMPLE
        $Info     = ConvertFrom-EventList -IP '10.20.30.40' -EventList $RawList
        $Body     = Get-ResponseContent -Response (Invoke-WebRequestDH -URI $Info.URI).Response
        ConvertFrom-EventResponse -Response $Body -EventObjects $Info.EventObjects -BaseHost "http://$HVACIP"

        Full detail pass for one controller.

    .NOTES
        Records emitted here inherit the New-HVACResponse default Status of 'warning',
        because the controller does not expose a per-event severity in this response. An
        event that is present at all is treated as something worth showing.

        Categories are looked up by outer report id, while the link is built from the inner
        report id; the two are not interchangeable.
    #>
    param(
        [Parameter(Mandatory)] [string]$Response,
        [Parameter(Mandatory)] [array]$EventObjects,
        [Parameter(Mandatory)] [string]$BaseHost
    )

    # Parse the raw response into a lookup table: key -> value
    $lookup = @{}
    foreach ($match in [regex]::Matches($Response, '(\w+~?\d*~?\d*)="([^"]*)"')) {
        $lookup[$match.Groups[1].Value] = $match.Groups[2].Value
    }

    foreach ($e in $EventObjects) {
        $plKey = "pl$($e.PointId)"
        $pdKey = "pd$($e.PointId)"
        $paKey = "pa$($e.PointId)"
        $categoryKey = "rl$($e.OuterReportId)~$($e.OuterReportSubId)"

        $eventText = $lookup[$plKey]
        $descText = $lookup[$pdKey]
        $attrValue = $lookup[$paKey]   # purpose not yet confirmed - not status
        $categoryText = $lookup[$categoryKey]

        $reportUri = "$BaseHost/monitor.htm?devId=0&reportId=val~num~$($e.InnerReportId)&mmIdx=val~num~$($e.InnerReportSubId)"

        $HVACResponse = @{
            Category    = $categoryText
            ReportURI   = $reportUri
            EventText   = $eventText
            Attribute   = $attrValue
            Description = $descText
        }
        New-HVACResponse @HVACResponse
    }
}
function ConvertFrom-EventList {
    <#
    .SYNOPSIS
        Parses an HVAC controller event list and builds the detail-query URI for it.

    .DESCRIPTION
        The controller returns its active events as a pipe-delimited list of nested tuples
        in the form (A,B:(C,D:E,F)):

            A, B  outer report id and sub-id, which resolve to the alarm category
            C, D  inner report id and sub-id, which address the monitor page for the event
            E     point id, which addresses the label, description, and attribute values
            F     parsed but not currently used

        It splits that list, extracts the identifiers, and assembles the single long query
        URI that asks the controller for every label, description, attribute, and report
        name in one round trip rather than one request per field.

    .PARAMETER IP
        IP address of the controller the event list came from. Used to build the host part
        of the detail-query URI.

    .PARAMETER EventList
        The raw pipe-delimited event string returned by the controller's event query.

    .OUTPUTS
        PSCustomObject with:
            URI          - the assembled detail-query URI.
            EventObjects - the parsed events, each carrying OuterReportId,
                           OuterReportSubId, InnerReportId, InnerReportSubId, PointId,
                           ExtraValue, and RawEvent.

    .EXAMPLE
        $Info = ConvertFrom-EventList -IP '10.20.30.40' -EventList '(1,0:(3,2:114,1))|(1,0:(3,2:115,1))'
        $Info.EventObjects.Count

        Parses a two-event list and reports how many events were recognized.

    .NOTES
        Events that do not match the expected tuple shape produce a warning and are dropped
        from the collection.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [IPAddress]
        $IP,
        [Parameter()]
        [string]
        $EventList
    )
    $HVACIP = $IP.ToString()
    $baseUri = "http://$HVACIP/httpGetSet/httpGet.htm?devId=0&"
    $events = $EventList -split '\|'
    $eventObjects = foreach ($evt in $events) {
        # (A,B:(C,D:E,F))
        if ($evt -match '^\((\d+),(\d+):\((\d+),(\d+):(\d+),(\d+)\)\)$') {
            [PSCustomObject]@{
                OuterReportId    = $Matches[1]  # A - top-level report id
                OuterReportSubId = $Matches[2]  # B - top-level report sub-id
                InnerReportId    = $Matches[3]  # C - nested report id
                InnerReportSubId = $Matches[4]  # D - nested report sub-id
                PointId          = $Matches[5]  # E - point id
                ExtraValue       = $Matches[6]  # F - parsed but unused in URI (purpose TBD)
                RawEvent         = $evt
            }
        }
        else {
            Write-Warning "Could not parse event: $evt"
        }
    }
    # Build the URI from the parsed collection
    $pointPart = ""
    $reportPart = ""
    foreach ($e in $eventObjects) {
        $pointPart += "pl$($e.PointId)=vel~fdm~pnt~label~$($e.PointId)&pd$($e.PointId)=vel~fdm~pnt~desc~$($e.PointId)&pa$($e.PointId)=vel~fdm~pnt~attr~$($e.PointId)&rl$($e.InnerReportId)~$($e.InnerReportSubId)=vel~fdm~rprt~label~$($e.InnerReportId)~$($e.InnerReportSubId)&"
        $reportPart += "rl$($e.OuterReportId)~$($e.OuterReportSubId)=vel~fdm~rprt~label~$($e.OuterReportId)~$($e.OuterReportSubId)&"
    }
    $uri = $baseUri + $pointPart + $reportPart
    return [PSCustomObject]@{
        URI          = $uri
        EventObjects = $eventObjects
    }
}
function Get-HVACAlerts {
    <#
    .SYNOPSIS
        Returns active alarms from a building HVAC controller.

    .DESCRIPTION
        Two-stage poll of a controller's unauthenticated HTTP interface:

          1. Request the active event list, which comes back as a compact tuple string.
          2. Parse that list, build a single detail query for every referenced point and
             report, and resolve the identifiers into readable labels, categories, and
             descriptions.

        Every outcome is expressed in the same record shape. A controller that cannot be
        reached produces a 'Communications' error record, a controller with no active events
        produces an informational record, and real events produce one record each. Nothing
        throws, so one unreachable controller does not take down the daily report.

    .PARAMETER IP
        IP address of the HVAC controller.

    .OUTPUTS
        PSCustomObject stream with Status, Category, 'Report URI', Event, Attribute, and
        Description.

    .EXAMPLE
        Get-HVACAlerts -IP '10.20.30.40'

        Polls one controller and returns its active alarms.

    .EXAMPLE
        $Config.HVACControllers | ForEach-Object { Get-HVACAlerts -IP $_ } | Where-Object Status -ne 'None'

        Polls every configured controller and keeps only the sites reporting something.

    .NOTES
        Requests are plain HTTP with no authentication.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ipaddress]
        $IP
    )
    $HVACIP = $IP.IPAddressToString
    $EventSourceURI = "http://$HVACIP/httpGetSet/httpGet.htm?devId=0&evt=vel~eventsWA~or~2"
    try {
        $EventList = (Get-ResponseContent -Response (Invoke-WebRequestDH -URI $EventSourceURI).response).Split('=')[1].Replace('"', '')
    }
    catch {
        $EventList = $null
        $results = New-HVACResponse -Status 'error' -Category 'Communications' -EventText 'Failure' -Description 'Failed to retrieve event list'   
    }
    if ($EventList) {
        $EventInformation = ConvertFrom-EventList -IP $IP -EventList $EventList
        try {
            $Response = Get-ResponseContent -Response (Invoke-WebRequestDH -URI $EventInformation.uri).Response
            $results = ConvertFrom-EventResponse -Response $Response -EventObjects $EventInformation.EventObjects -BaseHost "http://$HVACIP"
        }
        catch {
            $results = New-HVACResponse -Status 'error' -Category 'Communications' -EventText 'Failure' -Description 'Could not retrieve event details.'   
        }
    }
    else {
        $results = New-HVACResponse -Status 'None' -Category 'Communications' -EventText 'Informational' -Description 'No active Events'
    }
    $results
}

function Get-Severity {
    <#
    .SYNOPSIS
        Normalizes a vendor status string into the module's four-value severity vocabulary.

    .DESCRIPTION
        Every collector in this module returns whatever status verb its source system uses:
        Veeam says Success and Failed, vSphere says green and red, UCS says critical and
        minor, ArcGIS Online says 'Is Experiencing Issues'. This function maps all of them
        onto one of four uniform values which can be used for classification and display
        wherever the resulting data may be used.

        Mapping:
            success - Succeeded, Success, green, Functioning Normally
            warning - Warning, yellow, minor, Is Experiencing Issues
            error   - Failed, red, critical, major, DOWN, Error
            info    - anything else

    .PARAMETER Status
        The status string from a collector.

    .OUTPUTS
        System.String. One of success, warning, error, or info.

    .EXAMPLE
        Get-Severity -Status 'critical'

        Returns 'error'.

    .NOTES
        The comparison is wildcard based with the candidate list on the left, so the incoming
        status acts as the pattern. Anything unrecognized falls through to 'info', which
        means a new or misspelled vendor status is reported as informational rather than as
        a problem.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Status
    )
    $Severity = switch -WildCard ($Status) {
        { 'Succeeded', 'Success', 'green', 'Functioning Normally' -like $_ } {
            'success'
            break
        }
        { 'Warning', 'yellow', 'minor', 'warning', 'Is Experiencing Issues' -like $_ } {
            'warning'
            break
        }
        { 'Failed', 'red', 'critical', 'major', 'DOWN', 'Error' -like $_ } {
            'error'
            break
        }
        default { 'info' }
    }
    return $Severity
}
function Get-JobSummary {
    <#
    .SYNOPSIS
        Counts a job's result rows by normalized severity.

    .DESCRIPTION
        Runs every row of a job's results through Get-Severity, groups by the result, and
        returns the four counts that summarize the set.

    .PARAMETER JobResults
        The result rows returned by one collector.

    .OUTPUTS
        PSCustomObject with Info, Success, Warning, and Error counts.

    .EXAMPLE
        $Results = Get-AllVBRJobs -VBRServer 'VEEAM01'
        Get-JobSummary -JobResults $Results

        Returns the backup job counts broken out by severity.

    .NOTES
        Rows whose source status is not recognized by Get-Severity land in the Info bucket.
    #>
    param(
        # Input Job Object
        [Parameter(Mandatory = $true)]
        [Object]
        $JobResults
    )
    $JobSummary = $JobResults | select-Object  *, @{N = 'Severity'; E = { Get-Severity $_.Status } } | Group-Object Severity
    return [PSCustomObject]@{
        Info    = $JobSummary.Where({ $_.Name -like 'info' })[0].Count    
        Success = $JobSummary.Where({ $_.Name -like 'success' })[0].Count    
        Warning = $JobSummary.Where({ $_.Name -like 'warning' })[0].Count    
        Error   = $JobSummary.Where({ $_.Name -like 'error' })[0].Count    
    }
}
function Get-JobOverallHealth {
    <#
    .SYNOPSIS
        Reduces a job summary to a single overall health value.

    .DESCRIPTION
        Applies worst-case-wins precedence to a summary produced by Get-JobSummary: any
        error makes the whole job an error, otherwise any warning makes it a warning,
        otherwise any success makes it a success, and a job with nothing but informational
        rows stays informational.

    .PARAMETER JobSummary
        The summary object returned by Get-JobSummary.

    .OUTPUTS
        System.String. One of error, warning, success, or info.

    .EXAMPLE
        Get-JobOverallHealth -JobSummary (Get-JobSummary -JobResults $Results)

        Collapses a result set to one health value.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [object]
        $JobSummary
    )

    $OverallHealth = 'info'
    if ($JobSummary.Error -gt 0 ) {
        $OverallHealth = 'error'
    }
    elseif ($JobSummary.Warning -gt 0) {
        $OverallHealth = 'warning'
    }
    elseif ($JobSummary.Success -gt 0) {
        $OverallHealth = 'success'
    }
    return $OverallHealth
}
function Write-JobDetails {
    <#
    .SYNOPSIS
        Writes a colourized one-line description of a job as it is dispatched.

    .DESCRIPTION
        Progress output for interactive runs, printing the job number, type, and description
        as each job is handed off. Used by Get-DailyStatus so a long collection run shows
        which checks have been submitted.

    .PARAMETER Job
        A job configuration entry carrying JobNumber, Type, and Description.

    .OUTPUTS
        None. Writes to the host.

    .EXAMPLE
        Write-JobDetails -Job $StatusConfig[0]

        Prints the first configured job's details.

    .NOTES
        Writes to the host stream by design, for the colouring. That output cannot be
        captured or redirected, so it is invisible in a scheduled-task transcript.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSObject]
        $Job       
    )
    Write-Host -NoNewline -ForegroundColor Gray "Running Job number "
    Write-Host -NoNewline -ForegroundColor Green $Job.JobNumber
    Write-Host -NoNewline -ForegroundColor Gray " with type "
    Write-Host -NoNewline -ForegroundColor Yellow $Job.Type
    Write-Host -NoNewline -ForegroundColor Gray " and description "
    Write-Host            -ForegroundColor Cyan $Job.Description
}
Function Get-DailyStatus() {
    <#
    .SYNOPSIS
        Runs the full configured daily health check and returns summarized results.

    .DESCRIPTION
        The orchestrator for the module. Walks a configuration collection, dispatches each
        entry to the matching collector as a PowerShell background job, then drains the jobs
        as they finish and attaches a per-job severity summary and overall health value.

        Everything runs concurrently, so the total run time is roughly the slowest single
        check rather than the sum of all of them, bounded by JobTimeOut. Results are returned
        sorted by JobNumber with a zero-based Index added, so the results can be rendered in
        the order the configuration declares regardless of the order in which they
        completed.

        Supported job types, taken from each entry's Type property:

            URL    Test-URIList
            DNS    Test-DNSServerRemote
            VMWare Get-TriggeredVMWareAlarms
            VEEAM  Get-AllVBRJobs
            SSL    Get-CertExpiration
            UCS    Get-UCSHealth
            AGO    Get-AGOStatus
            SWI    Get-SWISInterfacesDown
            SWN    Get-SWISNodesDown
            SWA    Get-SWISAlerts
            HVAC   Get-HVACAlerts

        A Type that matches none of these dispatches a job that returns a single error record
        naming the unrecognized type, which rolls up as an error for that entry.

    .PARAMETER StatusConfig
        The job configuration collection, normally read from JSON. Each entry supplies:
            JobNumber      - sort order for the report.
            Type           - one of the type codes above, matched case-insensitively.
            Description    - Short description of the job included in the report.
            JobParameters  - The parameters for the current job entry. These should match the
                             function signature of the function for the specified Type.

    .PARAMETER JobTimeOut
        Seconds a single check may run before it is abandoned and reported as an error.
        Defaults to 300. Measured from the background job's PSBeginTime, so it bounds total
        elapsed time rather than idle time. Set it above the slowest legitimate check; a
        full internal CA sweep or a large Veeam inventory can take several minutes.

    .PARAMETER Credential
        Optional credential added to every job's parameters. Use when the scheduled-task
        identity cannot reach the targets directly.

    .OUTPUTS
        PSCustomObject collection, one entry per configured job:
            Description   - the job's label.
            JobNumber     - as configured.
            Results       - the collector's raw rows.
            Summary       - Info, Success, Warning, and Error counts.
            OverallHealth - single worst-case status for the job.
            Index         - zero-based position after sorting by JobNumber.

        Summary is a PSCustomObject of those four counts on every path, including the
        synthesized ones, so consumers can read it uniformly. Results holds whatever the
        collector returned, a one-element synthesized collection on a timeout, or null when
        the check returned nothing at all.

    .EXAMPLE
        $Config = Get-Content .\DailyStatus.json -Raw | ConvertFrom-Json
        Get-DailyStatus -StatusConfig $Config

        Runs every configured check using the current identity.

    .EXAMPLE
        $Config = Get-Content .\DailyStatus.json -Raw | ConvertFrom-Json
        Get-DailyStatus -StatusConfig $Config -Credential $SvcCred -JobTimeOut 600 |
            Where-Object OverallHealth -in 'warning','error'

        Runs the full sweep with a ten-minute ceiling per check and keeps only the ones that
        need attention.

    .NOTES
        The DNS branch rewrites its DNSServer values before dispatch, because the JSON
        configuration carries them as objects with an IP property rather than as bare
        addresses.

        Every branch imports the module inside its background job, since a background job
        starts a fresh runspace that does not inherit the caller's loaded modules.

        A check that returns nothing is given a synthesized summary of one error, so an
        empty result set reads as a failure rather than as nothing to say. Every collector
        here emits at least a placeholder row on its quiet path, so that holds in normal
        operation; a collector added later that can legitimately return nothing would need
        its own handling.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Object]
        $StatusConfig,
        [Parameter()]
        [int]
        $JobTimeOut = 300,
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )
    $error.clear()
    Try {
        #region Run Jobs
        $JobList = New-Object System.Collections.ArrayList
        Foreach ( $Job in $StatusConfig ) {
            $JobParameters = ConvertTo-Hashtable $Job.JobParameters
            if ($Credential) {
                $JobParameters.Add('Credential', $Credential)
            }
            Write-JobDetails -Job $Job
            $JobList.Add([PSCustomObject]@{
                    JobDescription = $Job.Description
                    JobNumber      = $Job.JobNumber
                    Job            = switch ($Job.Type.ToUpper()) {
                        "URL" {
                            Start-Job {
                                Import-Module DailyHealth
                                Test-URIList @Using:JobParameters
                            }
                            break
                        }
                        "DNS" {
                            Start-Job {
                                Import-Module DailyHealth
                                $JobParameters = $Using:JobParameters
                                $JobParameters.DNSServer = $JobParameters.DNSServer.Foreach({ [ipaddress]$_.IP })
                                Test-DNSServerRemote @JobParameters
                            }
                            break
                        }
                        "VMWare" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-TriggeredVMWareAlarms @Using:JobParameters
                            }
                            break
                        }
                        "VEEAM" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-AllVBRJobs @Using:JobParameters
                            }
                            break
                        }
                        "SSL" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-CertExpiration @Using:JobParameters | Select-Object Domain, Subject, DaysToExpiration, Status, Expiration
                            }
                            break
                        }
                        "UCS" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-UCSHealth @Using:JobParameters
                            }
                            break
                        }
                        "AGO" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-AGOStatus @Using:JobParameters
                            }
                            break
                        }
                        "SWI" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-SWISInterfacesDown @Using:JobParameters
                            }
                            break
                        }
                        "SWN" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-SWISNodesDown @Using:JobParameters
                            }
                            break
                        }
                        "SWA" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-SWISAlerts @Using:JobParameters
                            }
                            break
                        }
                        "HVAC" {
                            Start-Job {
                                Import-Module DailyHealth
                                Get-HVACAlerts @Using:JobParameters
                            }
                            break
                        }
                        default {
                            $JobType = $Job.Type.ToUpper()
                            Start-Job {
                                @([PSCustomObject]@{
                                        Status      = 'Error'
                                        Description = 'Unrecognized Job type {0}' -f $Using:JobType
                                    })
                            }
                        }
                    }
                }) | Out-Null
        }
        Write-Verbose "All jobs submitted, waiting for completion"
        #endregion

        $error.clear()
        #region Collect Results
        $Results = New-Object System.Collections.ArrayList
        While ($JobList.Count -gt 0) {
            Foreach ($CurrentJob in @($JobList)) {
                if (($CurrentJob.Job.State -eq 'Completed') -or ($CurrentJob.Job.State -eq 'Failed')) {
                    $CompletedJobResults = Receive-Job -Job $CurrentJob.Job
                    $JobSummary = if ($null -eq $CompletedJobResults) { [PSCustomObject]@{Info = 0; Success = 0; Warning = 0; Error = 1 } } else { Get-JobSummary -JobResults $CompletedJobResults }
                    $Results.Add([PSCustomObject]@{
                            Description   = $CurrentJob.JobDescription
                            JobNumber     = $CurrentJob.JobNumber
                            Results       = $CompletedJobResults
                            Summary       = $Jobsummary
                            OverallHealth = Get-JobOverallHealth -JobSummary $JobSummary
                        }) | Out-Null
                    Remove-Job $CurrentJob.Job
                    $JobList.Remove($CurrentJob)
                }
                elseif (((Get-Date) - $CurrentJob.Job.PSBeginTime).TotalSeconds -gt $JobTimeOut) {
                    $Results.Add([PSCustomObject]@{
                            Description   = $CurrentJob.JobDescription
                            JobNumber     = $CurrentJob.JobNumber
                            Results       = @(@{
                                Status      = 'error'
                                Description = 'Overall job timed out'
                            })
                            Summary       = [PSCustomObject]@{Info = 0; Success = 0; Warning = 0; Error = 1 }
                            OverallHealth = 'error'
                        }) | Out-Null
                    Stop-Job -Confirm:$false -Job $CurrentJob.Job
                    Remove-Job -Confirm:$false -Force -Job $CurrentJob.Job
                    $JobList.Remove($CurrentJob)
                }
            }
            Start-Sleep -Seconds 1
        }
        $ArrayIndex = 0
        return $($Results | Sort-Object JobNumber | ForEach-Object { $_ | Select-Object *, @{N = 'Index'; E = { $ArrayIndex } }; $ArrayIndex += 1 })
        #endregion
    }
    catch {
        Write-Error $($Error | ConvertTo-Json | Out-String)
    }
}
