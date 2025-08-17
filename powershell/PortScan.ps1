<# 
.SYNOPSIS
  Slow, randomized TCP port scan with optional banner capture and service guessing.
  Aimed at IBM stacks (z/OS, z/VM, IBM i) but usable anywhere.

.EXAMPLE
  .\PortScan.ps1 -Target 192.0.2.50 -OutputPath .\scan.csv -BannerCapture

.EXAMPLE
  .\PortScan.ps1 -Target mf.example.com -ExtraPorts 3000,3023 -DelayMinMs 400 -DelayMaxMs 1600

.PARAMETER Target
  Hostname or IP to scan.

.PARAMETER OutputPath
  CSV file to write results. Defaults to ".\portscan-<host>-<timestamp>.csv".

.PARAMETER BannerCapture
  If set, attempt basic banner grabs on select protocols after connecting.

.PARAMETER TimeoutMs
  Per-port TCP connect timeout (default 2500 ms).

.PARAMETER DelayMinMs
  Minimum delay between probes (default 600 ms).

.PARAMETER DelayMaxMs
  Maximum delay between probes (default 2200 ms).

.PARAMETER ExtraPorts
  Extra TCP ports to include (comma-separated or int[]).
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$Target,

  [string]$OutputPath,

  [switch]$BannerCapture,

  [int]$TimeoutMs = 2500,

  [int]$DelayMinMs = 600,

  [int]$DelayMaxMs = 2200,

  [int[]]$ExtraPorts = @()
)

# --- Port catalog: common + legacy with mainframe bias (z/OS, z/VM, IBM i) ---
# Notes:
#  - TN3270/TN3270E: 23 (plaintext), 992 (TLS)
#  - DRDA (DB2/IBM i): 446
#  - IBM MQ: 1414
#  - JES/NJE, LPD, r* services are legacy but still seen
#  - IBM i management/services cluster: 8470–8476 (Host Servers)
#  - IMS Connect typical default: 4099 (site-specific)
#  - Many HTTP(S)/REST front-ends exist for CICS/IMS and z/OSMF (80/443/9443/10443/12443)
$BasePorts = @(
    7, 9, 13, 19,           # echo/discard/daytime/chargen (legacy)
    20, 21, 22, 23,          # FTP-data, FTP, SSH, Telnet/TN3270
    25, 37, 43, 49,          # SMTP, time, whois, TACACS (rare)
    53, 69, 79, 80,          # DNS (TCP), TFTP (rare TCP), finger, HTTP
    88, 110, 111, 113,       # Kerberos, POP3, portmap, ident
    119, 123, 135,           # NNTP, NTP (TCP uncommon), MS RPC (sometimes present on proxies)
    143, 161, 162, 389,      # IMAP, SNMP (TCP uncommon), SNMP-trap, LDAP
    443, 444, 445, 446,      # HTTPS, SNPP/alt, SMB (rare on MF), DRDA (DB2/IBM i)
    500, 512, 513, 514, 515, # isakmp (rare TCP), rexec, rlogin, rsh, LPD (JES/print)
    587, 631, 636, 698,      # SMTP submit, IPP, LDAPS, OLSR (rare)
    873, 888, 902, 990,      # rsync, cddbp (legacy), VMware (rare), FTPS
    992, 993, 995, 1099,     # TN3270E/TelnetS, IMAPS, POP3S, Java RMI
    1241, 1311, 1414, 1433,  # Nessus (rare); HP (rare); IBM MQ; SQL Server (rare gateway)
    1521, 175, 1900, 2049,   # Oracle (rare), NJE (legacy/varies), SSDP (rare TCP), NFS (rare TCP)
    2080, 2375, 2376, 2401,  # HTTP-alt, Docker (rare TCP exposure), Docker TLS, CVS (legacy)
    3000, 3023, 3070, 3306,  # common app ports; 3023 sometimes TN3270 alt; DBs
    3389, 3500, 3700, 3776,  # RDP (proxies/jump), IBM i Ops? (varies), app, 3776 (IBM i SNA/TelnetGW)
    3900, 3901, 3902, 3903,  # Often site apps or IMS/CICS listener ranges
    3914, 3939, 3990, 4000,  # SMTP lmtp; misc; IBM 3990 (legacy), app
    4099, 4443, 5000, 5432,  # IMS Connect (typical default); HTTPS-alt; app; Postgres
    5500, 5600, 5671, 5672,   # JBoss/Oracle EM; app; AMQP TLS; AMQP
    6000, 6007, 6080, 6100,   # X11; NetView; app; app
    6200, 62078, 6667, 7001,  # app; iTunes (rare), IRC; WebLogic
    7228, 7300, 7443, 7777,   # IBM PDU/TSM (varies), Rexec (AIX); HTTPS-alt; app
    7800, 8000, 8010, 8080,   # CICS/IMS frontends (varies); HTTP-alt(s)
    8081, 8443, 8800, 8888,   # HTTP-alt(s); HTTPS-alt; app; app
    9000, 9030, 9043, 9080,   # app; z/OSMF early; HTTPS; HTTP (z/OSMF/CICS)
    9100, 9200, 9443, 9643,   # raw print; Elasticsearch; HTTPS (z/OSMF/CICS); zSecure (varies)
    10000, 10443, 12443, 14143, # admin; HTTPS (common alts); HTTPS alt; MQ alt
    16000, 17500, 18080, 20000,  # app; app; HTTP-alt; app
    20880, 21500, 28080, 30000,  # app; app; HTTP-alt; app
    32764, 32768, 49152, 65535   # legacy/backdoor curios; ephemeral range edges
)

# IBM i Host Server group (commonly seen)
$IBMiHostServer = 8470..8476

# Combine, dedupe, and add extras
$PortSet = @($BasePorts + $IBMiHostServer + $ExtraPorts) | Sort-Object -Unique

# Randomize order for lower-noise scanning
$Shuffled = Get-Random -InputObject $PortSet -Count $PortSet.Count

# Service name hints (static)
$ServiceHints = @{
  7='echo'; 9='discard'; 13='daytime'; 19='chargen';
  20='ftp-data'; 21='ftp'; 22='ssh'; 23='tn3270/telnet';
  25='smtp'; 37='time'; 43='whois'; 49='tacacs';
  53='dns'; 69='tftp'; 79='finger'; 80='http';
  88='kerberos'; 110='pop3'; 111='portmap'; 113='ident';
  119='nntp'; 123='ntp'; 135='msrpc';
  143='imap'; 161='snmp-tcp'; 162='snmptrap-tcp'; 389='ldap';
  443='https'; 444='snpp/alt'; 446='drda (DB2/IBM i)';
  500='isakmp'; 512='rexec'; 513='rlogin'; 514='rsh'; 515='lpd (JES/print)';
  587='smtp-submission'; 631='ipp'; 636='ldaps';
  873='rsync'; 990='ftps'; 992='tn3270e/telnets';
  993='imaps'; 995='pop3s'; 1099='java-rmi';
  1414='ibm mq'; 1433='mssql'; 1521='oracle';
  175='nje (legacy)'; 2049='nfs (tcp)'; 2080='http-alt';
  2375='docker-api'; 2376='docker-api-tls'; 2401='cvs';
  3023='tn3270 alt'; 3306='mysql'; 3389='rdp';
  3700='app/ims/cics (varies)'; 3776='ibm i sna gateway';
  3900='ims/cics (varies)'; 3914='lmtp'; 4099='ims connect (typical)';
  4443='https-alt'; 5000='http-alt'; 5432='postgres';
  5671='amqp-tls'; 5672='amqp'; 6007='netview';
  7001='weblogic'; 7228='ibm tivoli/tsm (varies)';
  7443='https-alt'; 7777='app'; 7800='app';
  8080='http-alt'; 8081='http-alt'; 8443='https-alt';
  8888='http-alt'; 9000='app'; 9043='https (websphere/zosmf)';
  9080='http (websphere/zosmf)'; 9100='raw-print';
  9200='elasticsearch'; 9443='https (zosmf/cics)'; 9643='https (zSecure/varies)';
  10000='admin'; 10443='https-alt'; 12443='https-alt';
  14143='mq-alt'; 18080='http-alt';
}
8470..8476 | ForEach-Object { $ServiceHints["$_"] = 'ibm i host server' }

function Invoke-Delay {
  param([int]$MinMs,[int]$MaxMs)
  if ($MinMs -lt 0 -or $MaxMs -lt 0 -or $MaxMs -lt $MinMs) { return }
  $rand = Get-Random -Minimum $MinMs -Maximum ($MaxMs + 1)
  Start-Sleep -Milliseconds $rand
}

function Test-TcpPort {
  param(
    [string]$Host,
    [int]$Port,
    [int]$TimeoutMs
  )
  $client = [System.Net.Sockets.TcpClient]::new()
  $ar = $client.BeginConnect($Host, $Port, $null, $null)
  try {
    if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
      $client.Close()
      return @{ Status='filtered/timeout'; Client=$null }
    }
    $client.EndConnect($ar)
    return @{ Status='open'; Client=$client }
  } catch {
    $client.Close()
    # Distinguish quickly between closed vs other
    if ($_.Exception.InnerException -and $_.Exception.InnerException.Message -match 'actively refused') {
      return @{ Status='closed'; Client=$null }
    }
    return @{ Status='closed'; Client=$null }
  } finally {
    if ($ar) { $ar.AsyncWaitHandle.Close() | Out-Null }
  }
}

function Get-Banner {
  param(
    [System.Net.Sockets.TcpClient]$Client,
    [int]$Port,
    [int]$TimeoutMs
  )
  try {
    $stream = $Client.GetStream()
    $stream.ReadTimeout = [Math]::Max(500, [Math]::Min($TimeoutMs, 3000))

    # Send simple protocol nudges where appropriate
    $probe = switch ($Port) {
      21  { "FEAT`r`n" }                 # FTP
      22  { "" }                         # SSH servers speak first
      23  { "`r`n" }                     # Telnet/TN3270 might negotiate; keep it minimal
      25  { "EHLO example.com`r`n" }     # SMTP
      80  { "HEAD / HTTP/1.0`r`nHost: example.com`r`n`r`n" } # HTTP
      110 { "QUIT`r`n" }                 # POP3
      143 { "a001 CAPABILITY`r`n" }      # IMAP
      389 { "" }                         # LDAP often silent until bind
      443 { "HEAD / HTTP/1.0`r`nHost: example.com`r`n`r`n" } # may be TLS-garbage, but sometimes clear on offloads
      446 { "" }                          # DRDA often silent until connect packet
      512 { "`r`n" }                      # rexec
      513 { "`r`n" }                      # rlogin
      514 { "`r`n" }                      # rsh
      631 { "GET / HTTP/1.0`r`nHost: example.com`r`n`r`n" }  # IPP/HTTP
      992 { "`r`n" }                      # telnets/tn3270e over TLS—likely gibberish
      1099 { "" }                         # RMI may talk on handshake
      1414 { "" }                         # MQ often silent until MQI
      8080 { "HEAD / HTTP/1.0`r`nHost: example.com`r`n`r`n" }
      8443 { "HEAD / HTTP/1.0`r`nHost: example.com`r`n`r`n" }
      9043 { "HEAD / HTTP/1.0`r`nHost: example.com`r`n`r`n" }
      9080 { "HEAD / HTTP/1.0`r`nHost: example.com`r`n`r`n" }
      default { "" }
    }

    if ($probe.Length -gt 0 -and $stream.CanWrite) {
      $bytes = [System.Text.Encoding]::ASCII.GetBytes($probe)
      $stream.Write($bytes, 0, $bytes.Length)
      $stream.Flush()
    }

    # Read a small chunk
    $buf = New-Object byte[] 2048
    $read = 0
    if ($stream.DataAvailable -or $Port -eq 22) {
      # SSH usually greets immediately
      $read = $stream.Read($buf, 0, $buf.Length)
    } else {
      # brief wait for response
      Start-Sleep -Milliseconds 150
      if ($stream.DataAvailable) { $read = $stream.Read($buf, 0, $buf.Length) }
    }

    if ($read -gt 0) {
      $raw = [System.Text.Encoding]::ASCII.GetString($buf,0,$read)
      # sanitize newlines and non-printables
      $clean = ($raw -replace '[^\x20-\x7E\r\n]','?').Trim()
      return $clean.Substring(0, [Math]::Min(300, $clean.Length))
    } else {
      return ""
    }
  } catch {
    return ""
  } finally {
    try { $Client.Close() } catch {}
  }
}

function Guess-Service {
  param(
    [int]$Port,
    [string]$Banner
  )
  # Start with static hint
  $hint = $ServiceHints[$Port.ToString()]
  if ([string]::IsNullOrWhiteSpace($Banner)) { return $hint }

  $b = $Banner.ToLowerInvariant()

  if ($b -match 'ssh-2\.0|openssh') { return 'ssh' }
  if ($b -match '^220 .*ftp') { return 'ftp' }
  if ($b -match '^220-|^250-|^ehlo') { return 'smtp' }
  if ($b -match 'http/1\.[01]|server:|<html') { return if ($Port -eq 443 -or $Port -eq 8443 -or $Port -eq 9443) {'https'} else {'http'} }
  if ($b -match '^ok.*pop|^\+ok') { return 'pop3' }
  if ($b -match 'capability|imap4') { return 'imap' }
  if ($b -match 'mqseries|ibm mq') { return 'ibm mq' }
  if ($b -match 'drda|sql\d*|db2') { return 'drda/db2' }
  if ($b -match 'ims|cics') { return 'ims/cics frontend' }
  if ($b -match 'tn3270|telnet') { return 'tn3270/telnet' }
  if ($b -match 'rmi') { return 'java-rmi' }
  if ($b -match 'postgres') { return 'postgres' }
  if ($b -match 'mysql') { return 'mysql' }
  if ($b -match 'weblogic') { return 'weblogic' }
  if ($b -match 'zosmf|websphere') { return 'zosmf/websphere' }

  # fallback to hint
  return $hint
}

# Resolve output path
if (-not $OutputPath) {
  $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
  $safeTarget = ($Target -replace '[^A-Za-z0-9\.-]','_')
  $OutputPath = ".\portscan-$safeTarget-$ts.csv"
}

# Container for results
$Results = New-Object System.Collections.Generic.List[pscustomobject]

Write-Host "Scanning $Target with $($Shuffled.Count) TCP ports..."
Write-Host "Delays: ${DelayMinMs}-${DelayMaxMs} ms, Timeout: ${TimeoutMs} ms, BannerCapture: $BannerCapture"
Write-Host "Writing CSV to: $OutputPath"
Write-Host ""

$swAll = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($p in $Shuffled) {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $status = 'unknown'
  $banner = ''
  $service = $ServiceHints[$p.ToString()]
  try {
    $res = Test-TcpPort -Host $Target -Port $p -TimeoutMs $TimeoutMs
    $status = $res.Status
    if ($status -eq 'open' -and $BannerCapture.IsPresent -and $res.Client) {
      $banner = Get-Banner -Client $res.Client -Port $p -TimeoutMs $TimeoutMs
    } elseif ($res.Client) {
      try { $res.Client.Close() } catch {}
    }
    $service = Guess-Service -Port $p -Banner $banner
  } catch {
    $status = 'error'
  } finally {
    $sw.Stop()
  }

  $obj = [pscustomobject]@{
    Timestamp    = (Get-Date).ToString("s")
    Host         = $Target
    Port         = $p
    Status       = $status
    ServiceGuess = $(if ($service) { $service } else { '' })
    Banner       = $banner
    ElapsedMs    = $sw.ElapsedMilliseconds
  }
  $Results.Add($obj) | Out-Null

  # Low-noise console line:
  Write-Host ("{0,5}/tcp  {1,-18}  {2}" -f $p, "[$status]", $(if ($service) { $service } else { '' }))

  # randomized pacing
  Invoke-Delay -MinMs $DelayMinMs -MaxMs $DelayMaxMs
}

$swAll.Stop()

# Write CSV
$Results | Sort-Object Port | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath

Write-Host ""
Write-Host ("Completed in {0:n1}s. Results saved to: {1}" -f ($swAll.Elapsed.TotalSeconds), (Resolve-Path $OutputPath))
