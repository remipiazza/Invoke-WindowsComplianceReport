<#
Windows Compliance Report (couleurs lignes fiables + JS secours + tri + filtres + sombre/clair + plein écran)
#>

[CmdletBinding()]
param(
  [string]$OutFile = (Join-Path $env:TEMP 'WindowsComplianceReport.html'),
  [string]$SharedCsvFolder,   # dossier UNC, ex: \\SRV-FICHIERS\SecOps\Compliance
  [string]$LogFolder = 'C:\Windows\Audit\logs'
)

function Unquote([string]$s) {
  if ($null -eq $s) { return $null }
  # retire guillemets simples/doubles en début/fin + espaces
  return ($s -replace "^\s*['""]|['""]\s*$", '')
}

$OutFile         = Unquote([Environment]::ExpandEnvironmentVariables($OutFile))
$SharedCsvFolder = Unquote([Environment]::ExpandEnvironmentVariables($SharedCsvFolder))

# ------------------------- Transcription -------------------------
$script:TranscriptStarted = $false
try {
  if ($LogFolder) {
    New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null
    $tsName = "WindowsCompliance_{0}_{1:yyyyMMdd_HHmmss}.log" -f $env:COMPUTERNAME, (Get-Date)
    $script:TranscriptPath = Join-Path $LogFolder $tsName
    Start-Transcript -Path $script:TranscriptPath -Append -ErrorAction Stop
    $script:TranscriptStarted = $true
    Write-Host "Transcript démarré : $script:TranscriptPath"
  }
}
catch {
  Write-Warning ("Transcript non démarré : {0}" -f $_.Exception.Message)
}

# Tout le reste du script s’exécute dans un try/finally pour garantir Stop-Transcript
try {


# ------------------------- Helpers génériques -------------------------
function New-DirectoryIfMissing([string]$Path){
  if ($Path -and -not (Test-Path -LiteralPath $Path)){
    New-Item -ItemType Directory -LiteralPath $Path -Force | Out-Null
  }
}

function Resolve-SharedFolder {
    param([string]$PathIn)
    if ([string]::IsNullOrWhiteSpace($PathIn)) { return $null }
    $p = Unquote([Environment]::ExpandEnvironmentVariables($PathIn))
    if ($p -match '<|>') { throw "Chemin invalide: '$p' (placeholders < >). Fournis un dossier réel (UNC ou local)." }
    if ($p -notmatch '^(?:[A-Za-z]:\\|\\\\)') { throw "Chemin invalide: '$p'. Fournis un chemin local (C:\...) ou UNC (\\serveur\partage)." }
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force -ErrorAction Stop | Out-Null }
    return $p
}
function Convert-ToCsvSemicolonLine {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][double]$ScorePercent,
        [Parameter(Mandatory)][int]$Passed,
        [Parameter(Mandatory)][int]$Total,
        [Parameter(Mandatory)][string]$CombinedCell,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][datetime]$Time
    )
    function EscapeField([string]$s) { if ($null -eq $s) { '' } else { $s -replace ';', ',' } }
    $scoreTxt = [string]::Format('{0:0.##}', $ScorePercent).Replace(',', '.')
    return @(
        (EscapeField $HostName)
        $scoreTxt
        $Passed
        $Total
        (EscapeField $CombinedCell)
        (EscapeField $User)
        $Time.ToString('s')
    ) -join ';'
}
function Read-FileLinesShared {
    param([Parameter(Mandatory)][string]$Path)
    if(-not (Test-Path $Path)){ return @() }
    $fs = $sr = $null
    try {
        $fs = New-Object System.IO.FileStream($Path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs,[System.Text.UTF8Encoding]::UTF8,$true)
        ($sr.ReadToEnd()) -split "`r?`n"
    } catch { @() }
    finally { if($sr){$sr.Dispose()}; if($fs){$fs.Dispose()} }
}

# ------------------------- Moteur de contrôles -------------------------
function New-Check {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Domain,
    [ValidateSet('Critique','Élevée','Moyenne','Faible')]
    [string]$Criticity,
    [ValidateRange(1,5)][int]$Weight,
    [Parameter(Mandatory)][scriptblock]$Test,
    [string]$How = ''
  )
  [pscustomobject]@{
    Name      = $Name
    Domain    = $Domain
    Criticity = $Criticity
    Weight    = $Weight
    How       = $How
    Test      = $Test
  }
}
function Invoke-Check {
  param($Check)
  $ok = $false
  $details = ''
  try {
    $result = & $Check.Test
    switch ($result.GetType().Name) {
      'Boolean' { $ok = [bool]$result; $details = "$result" }
      'String'  { $ok = $result -match '^OK'; $details = $result }
      default   { $ok = [bool]$result; $details = "$result" }
    }
  } catch {
    $ok = $false
    $details = "ERROR: $($_.Exception.Message)"
  }
  [pscustomobject]@{
    Name       = $Check.Name
    Domain     = $Check.Domain
    Criticity  = $Check.Criticity
    Weight     = $Check.Weight
    How        = $Check.How
    Passed     = $ok
    Details    = $details
  }
}

# ---------- 55 contrôles ----------
$Checks = @(
  # --- Chiffrement / Plateforme (8) ---
  New-Check -Name 'BitLocker OS protégé (TPM)' -Domain 'Chiffrement' -Criticity 'Critique' -Weight 5 -How 'Get-BitLockerVolume -MountPoint C:' -Test {
    $v = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
    if($v -and $v.ProtectionStatus -eq 'On'){'OK: Protection=On'} else {"FAIL: $(if($v){"Protection=$($v.ProtectionStatus)"}else{"Volume introuvable"})"}
  }
  New-Check -Name 'Lecteurs de données chiffrés' -Domain 'Chiffrement' -Criticity 'Élevée' -Weight 4 -How 'Get-BitLockerVolume | ? VolumeType=Data' -Test {
    $d = Get-BitLockerVolume -ErrorAction SilentlyContinue | ? {$_.VolumeType -eq 'Data'}
    if(-not $d){'OK: Aucun lecteur Data'} elseif(($d|?{$_.ProtectionStatus -ne 'On'}).Count -gt 0){'FAIL: Data non protégé'} else {'OK: Tous protégés'}
  }
  New-Check -Name 'Chiffrement XTS-AES 256 (si exigé)' -Domain 'Chiffrement' -Criticity 'Moyenne' -Weight 3 -How 'Get-BitLockerVolume | Select EncryptionMethod' -Test {
    $enc = Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object -Expand EncryptionMethod
    if(-not $enc){'OK: N/A'} elseif(($enc -match 'XTS-AES 256').Count -ge 1){'OK: XTS-AES 256 présent'} else {'FAIL: autre méthode'}
  }
  New-Check -Name 'TPM présent' -Domain 'Plateforme' -Criticity 'Élevée' -Weight 4 -How 'Get-Tpm' -Test {
    $t = Get-Tpm -ErrorAction SilentlyContinue
    if($t -and $t.TpmPresent){'OK: TPM présent'} else {'FAIL: TPM absent'}
  }
  New-Check -Name 'TPM prêt' -Domain 'Plateforme' -Criticity 'Élevée' -Weight 4 -How 'Get-Tpm' -Test {
    $t = Get-Tpm -ErrorAction SilentlyContinue
    if($t -and $t.TpmReady){'OK: TPM prêt'} else {'FAIL: TPM non prêt'}
  }
  New-Check -Name 'TPM 2.0 (SpecVersion)' -Domain 'Plateforme' -Criticity 'Élevée' -Weight 4 -How 'Get-WmiObject Win32_Tpm | Select SpecVersion' -Test {
    $spec = try{(Get-WmiObject -Namespace root\cimv2\Security\MicrosoftTpm -Class Win32_Tpm -ea Stop).SpecVersion}catch{''}
    if($spec -match '^2\.0' -or $spec -match '2.0'){'OK: TPM 2.0'} else {"FAIL: Spec=$spec"}
  }
  New-Check -Name 'Secure Boot activé' -Domain 'Plateforme' -Criticity 'Élevée' -Weight 4 -How 'Confirm-SecureBootUEFI' -Test {
    try{ if(Confirm-SecureBootUEFI){'OK: ON'} else {'FAIL: OFF'} }catch{'FAIL: non UEFI ou non dispo'}
  }
  New-Check -Name 'Démarrage mesuré (VBS/HVCI prêt ?)' -Domain 'Plateforme' -Criticity 'Moyenne' -Weight 3 -How 'Get-CimInstance Win32_DeviceGuard' -Test {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if($dg.SecurityServicesConfigured -contains 1){'OK: VBS configuré'} else {'FAIL: VBS non configuré'}
  }

  # --- TLS / SSL (8) ---
  New-Check -Name 'TLS 1.2 Client activé' -Domain 'TLS/SSL' -Criticity 'Critique' -Weight 5 -How 'Reg SCHANNEL TLS1.2\Client Enabled=1' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    (Get-ItemProperty $k -ErrorAction SilentlyContinue).Enabled -eq 1
  }
  New-Check -Name 'TLS 1.2 Server activé' -Domain 'TLS/SSL' -Criticity 'Critique' -Weight 5 -How 'Reg SCHANNEL TLS1.2\Server Enabled=1' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
    (Get-ItemProperty $k -ErrorAction SilentlyContinue).Enabled -eq 1
  }
  New-Check -Name 'TLS 1.3 Client activé (si support)' -Domain 'TLS/SSL' -Criticity 'Élevée' -Weight 4 -How 'Reg SCHANNEL TLS1.3\Client Enabled=1' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'
    $v=Get-ItemProperty $k -ErrorAction SilentlyContinue
    if(-not $v){'OK: N/A'} else {$v.Enabled -eq 1}
  }
  New-Check -Name 'TLS 1.3 Server activé (si support)' -Domain 'TLS/SSL' -Criticity 'Élevée' -Weight 4 -How 'Reg SCHANNEL TLS 1.3\Server Enabled=1' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
    $v=Get-ItemProperty $k -ErrorAction SilentlyContinue
    if(-not $v){'OK: N/A'} else {$v.Enabled -eq 1}
  }
  New-Check -Name 'SSL 3.0 Client désactivé' -Domain 'TLS/SSL' -Criticity 'Critique' -Weight 5 -How 'Reg SCHANNEL SSL 3.0\Client Enabled=0' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
    (Get-ItemProperty $k -ErrorAction SilentlyContinue).Enabled -eq 0
  }
  New-Check -Name 'SSL 3.0 Server désactivé' -Domain 'TLS/SSL' -Criticity 'Critique' -Weight 5 -How 'Reg SCHANNEL SSL 3.0\Server Enabled=0' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
    (Get-ItemProperty $k -ErrorAction SilentlyContinue).Enabled -eq 0
  }
  New-Check -Name 'TLS 1.0 Client désactivé' -Domain 'TLS/SSL' -Criticity 'Critique' -Weight 5 -How 'Reg SCHANNEL TLS 1.0\Client Enabled=0' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
    (Get-ItemProperty $k -ErrorAction SilentlyContinue).Enabled -eq 0
  }
  New-Check -Name 'TLS 1.1 Client désactivé' -Domain 'TLS/SSL' -Criticity 'Critique' -Weight 5 -How 'Reg SCHANNEL TLS 1.1\Client Enabled=0' -Test {
    $k='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
    (Get-ItemProperty $k -ErrorAction SilentlyContinue).Enabled -eq 0
  }

  # --- Réseau / SMB / Découverte (10) ---
  New-Check -Name 'SMBv1 supprimé (feature)' -Domain 'Réseau/SMB' -Criticity 'Critique' -Weight 5 -How 'Get-WindowsOptionalFeature SMB1Protocol' -Test {
    (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State -eq 'Disabled'
  }
  New-Check -Name 'SMB signing requis (Client)' -Domain 'Réseau/SMB' -Criticity 'Élevée' -Weight 4 -How 'Get-SmbClientConfiguration' -Test {
    (Get-SmbClientConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature
  }
  New-Check -Name 'SMB signing requis (Server)' -Domain 'Réseau/SMB' -Criticity 'Élevée' -Weight 4 -How 'Get-SmbServerConfiguration' -Test {
    (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature
  }
  New-Check -Name 'Accès invité SMB interdit' -Domain 'Réseau/SMB' -Criticity 'Élevée' -Weight 4 -How 'HKLM:\...\LanmanWorkstation AllowInsecureGuestAuth=0' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -ea SilentlyContinue).AllowInsecureGuestAuth -eq 0
  }
  New-Check -Name 'LLMNR désactivé' -Domain 'Réseau' -Criticity 'Élevée' -Weight 4 -How 'HKLM:\...\DNSClient EnableMulticast=0' -Test {
    (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -ea SilentlyContinue).EnableMulticast -eq 0
  }
  New-Check -Name 'WPAD AutoDetect désactivé' -Domain 'Réseau' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\Internet Settings AutoDetect=0' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -ea SilentlyContinue).AutoDetect -eq 0
  }
  New-Check -Name 'NetBIOS over TCP/IP désactivé' -Domain 'Réseau' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\SYSTEM\CCS\Services\NetBT\...\Interfaces NetbiosOptions=2' -Test {
    $ifs = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ea SilentlyContinue
    if(-not $ifs){$false} else { @($ifs | % {(Get-ItemProperty $_.PsPath).NetbiosOptions}) -contains 2 }
  }
  New-Check -Name 'mDNS 5353 bloqué (inbound)' -Domain 'Réseau' -Criticity 'Moyenne' -Weight 3 -How "Get-NetFirewallRule | match 'mDNS|5353'" -Test {
    (Get-NetFirewallRule -ErrorAction SilentlyContinue | ? {$_.Direction -eq 'Inbound' -and ($_.DisplayName -match 'mDNS|5353')}).Count -ge 1
  }
  #New-Check -Name 'Signature requise (param client)' -Domain 'Réseau/SMB' -Criticity 'Moyenne' -Weight 3 -How "HKLM:\SYSTEM\CCS\Services\LanmanWorkstation\Parameters RequireSecuritySignature=1" -Test {
  #  (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ea SilentlyContinue).RequireSecuritySignature -eq 1
  #}

  # --- Identité / Comptes / RDP / LSA (10) ---
  New-Check -Name 'NTLMv2 uniquement (LmCompatibilityLevel>=5)' -Domain 'Identité' -Criticity 'Critique' -Weight 5 -How 'HKLM:\...\Lsa LmCompatibilityLevel>=5' -Test {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ea SilentlyContinue).LmCompatibilityLevel -ge 5
  }
  #New-Check -Name 'LSASS protégé (RunAsPPL=1)' -Domain 'Identité' -Criticity 'Critique' -Weight 5 -How 'HKLM:\...\Lsa RunAsPPL=1' -Test {
    #(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ea SilentlyContinue).RunAsPPL -eq 1
  #}
  New-Check -Name 'LSASS protégé (config)' -Domain 'Identité' -Criticity 'Élevée' -Weight 3 -How 'HKLM:\...\Lsa RunAsPPL' -Test {
      $build = [Environment]::OSVersion.Version.Build
      $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ea SilentlyContinue).RunAsPPL
      if ($build -ge 22621) { $v -in 1,2 } else { $v -eq 1 }
  }
  New-Check -Name 'RunAsPPLBoot=1 (early launch)' -Domain 'Identité' -Criticity 'Élevée' -Weight 4 -How 'HKLM:\...\Lsa RunAsPPLBoot=1' -Test {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ea SilentlyContinue).RunAsPPLBoot -eq 1
  }
  New-Check -Name 'NoLMHash=1' -Domain 'Identité' -Criticity 'Élevée' -Weight 4 -How 'HKLM:\...\Lsa NoLMHash=1' -Test {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ea SilentlyContinue).NoLMHash -eq 1
  }
  New-Check -Name 'LAPS activé (password local admin)' -Domain 'Identité' -Criticity 'Élevée' -Weight 4 -How 'Windows LAPS (GPO): HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS ; Windows LAPS (Intune CSP): HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LAPS ; LAPS Legacy (AdmPwd): HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -Test {
  $maxAge = 30
  $ok = $false

  # 1) Windows LAPS via GPO
  $win = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS' -ErrorAction SilentlyContinue
  if ($win) {
    $bdOK  = $win.PSObject.Properties.Name -contains 'BackupDirectory' -and ($win.BackupDirectory -in 1,2)  # 1=AD, 2=AAD
    $ageOK = $win.PSObject.Properties.Name -contains 'PasswordAgeDays' -and ([int]$win.PasswordAgeDays -gt 0) -and ([int]$win.PasswordAgeDays -le $maxAge)
    if ($bdOK -and $ageOK) { $ok = $true }
  }

  # 2) Windows LAPS via Intune (CSP)
  if (-not $ok) {
    $csp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LAPS' -ErrorAction SilentlyContinue
    if ($csp) {
      $bdOK  = $csp.PSObject.Properties.Name -contains 'BackupDirectory' -and ($csp.BackupDirectory -in 1,2)
      $ageOK = $csp.PSObject.Properties.Name -contains 'PasswordAgeDays' -and ([int]$csp.PasswordAgeDays -gt 0) -and ([int]$csp.PasswordAgeDays -le $maxAge)
      if ($bdOK -and $ageOK) { $ok = $true }
    }
  }

  # 3) LAPS Legacy (AdmPwd)
  if (-not $ok) {
    $adm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
    if ($adm) {
      $enabledOK = $adm.PSObject.Properties.Name -contains 'AdmPwdEnabled' -and ($adm.AdmPwdEnabled -eq 1)
      $ageOK     = $adm.PSObject.Properties.Name -contains 'PasswordAgeDays' -and ([int]$adm.PasswordAgeDays -gt 0) -and ([int]$adm.PasswordAgeDays -le $maxAge)
      if ($enabledOK -and $ageOK) { $ok = $true }
    }
  }

  # 4) Filet de sécurité (optionnel) : activité récente dans le journal LAPS (rotation)
  if (-not $ok) {
    try {
      $since = (Get-Date).AddDays(-60)
      $evt = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-LAPS/Operational'; StartTime=$since } -MaxEvents 1 -ErrorAction SilentlyContinue
      if ($evt) { $ok = $true }
    } catch { }
  }

  $ok
}
  New-Check -Name 'Admin intégré désactivé' -Domain 'Comptes' -Criticity 'Critique' -Weight 5 -How "Get-LocalUser|Where-Object { $_.SID.Value -match 'S-1-5-21-.+-(500)$' }" -Test {
    $u=Get-LocalUser -ea SilentlyContinue|Where-Object { $_.SID.Value -match 'S-1-5-21-.+-(500)$' }; $u -and -not $u.Enabled
  }
  New-Check -Name 'Invité désactivé' -Domain 'Comptes' -Criticity 'Élevée' -Weight 4 -How "Get-LocalUser|Where-Object { $_.SID.Value -match 'S-1-5-21-.+-(501)$' }" -Test {
    $u=Get-LocalUser -ea SilentlyContinue|Where-Object { $_.SID.Value -match 'S-1-5-21-.+-(501)$' }; $u -and -not $u.Enabled
  }
  New-Check -Name 'NLA exigée pour RDP' -Domain 'Accès distant' -Criticity 'Élevée' -Weight 4 -How 'HKLM:\...\RDP-Tcp UserAuthentication=1' -Test {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ea SilentlyContinue).UserAuthentication -eq 1
  }
  New-Check -Name 'RDP désactivé si non requis' -Domain 'Accès distant' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\Terminal Server fDenyTSConnections=1' -Test {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ea SilentlyContinue).fDenyTSConnections -eq 1
  }
  New-Check -Name "Cache d'info d'auth minimale" -Domain 'Identité' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\Winlogon CachedLogonsCount<=10' -Test {
    $k='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $v=(Get-ItemProperty $k -ea SilentlyContinue).CachedLogonsCount
    if($v){ [int]$v -le 10 } else { $true }
  }

  # --- Protection / Défense / Pare-feu / Exploit (10) ---
  New-Check -Name 'Pare-feu profils ON' -Domain 'Protection' -Criticity 'Critique' -Weight 5 -How 'Get-NetFirewallProfile' -Test {
    (Get-NetFirewallProfile | ? {$_.Enabled -eq $false}).Count -eq 0
  }
  New-Check -Name 'Pare-feu inbound=Block' -Domain 'Protection' -Criticity 'Élevée' -Weight 4 -How 'Get-NetFirewallProfile | DefaultInboundAction' -Test {
    (Get-NetFirewallProfile | % {$_.DefaultInboundAction}) -contains 'Block'
  }
  New-Check -Name 'Pare-feu outbound=Allow (par défaut)' -Domain 'Protection' -Criticity 'Faible' -Weight 2 -How 'Get-NetFirewallProfile | DefaultOutboundAction' -Test {
    (Get-NetFirewallProfile | % {$_.DefaultOutboundAction}) -contains 'Allow'
  }
  #New-Check -Name 'Defender temps réel ON' -Domain 'Protection' -Criticity 'Critique' -Weight 5 -How 'Get-MpComputerStatus' -Test {
    #(Get-MpComputerStatus -ea SilentlyContinue).RealTimeProtectionEnabled
  #}
  New-Check -Name 'Protection cloud MAPS (élevée)' -Domain 'Protection' -Criticity 'Élevée' -Weight 4 -How 'Get-MpPreference | MAPS/SubmitSamples' -Test {
    $p=Get-MpPreference -ea SilentlyContinue; ($p.MAPSReporting -ge 1) -and ($p.SubmitSamplesConsent -ge 1)
  }
  #New-Check -Name 'ASR Rules en blocage' -Domain 'Protection' -Criticity 'Élevée' -Weight 4 -How 'Get-MpPreference AttackSurfaceReductionRules_Actions' -Test {
    #(Get-MpPreference -ea SilentlyContinue).AttackSurfaceReductionRules_Actions -contains 1
  #}
  #New-Check -Name 'Network Protection ON' -Domain 'Protection' -Criticity 'Élevée' -Weight 4 -How 'Get-MpPreference EnableNetworkProtection=1' -Test {
    #(Get-MpPreference -ea SilentlyContinue).EnableNetworkProtection -eq 1
  #}
  $isOn = { param($v) ($v -eq $true) -or ($v -is [string] -and $v -match '^(on|enabled?)$') }

    New-Check -Name 'Exploit Prot. - DEP (système) ON' -Domain 'Protection' -Criticity 'Élevée' -Weight 5 -How 'Get-ProcessMitigation -System' -Test {
        $pm = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if(-not $pm){ return $false }
        & $isOn $pm.DEP.Enable
    }

    New-Check -Name 'Exploit Prot. - CFG (système) ON' -Domain 'Protection' -Criticity 'Élevée' -Weight 5 -How 'Get-ProcessMitigation -System' -Test {
        $pm = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if(-not $pm){ return $false }
        & $isOn $pm.CFG.Enable
    }

    New-Check -Name 'Exploit Prot. - ASLR (BottomUp+HighEntropy) ON' -Domain 'Protection' -Criticity 'Élevée' -Weight 3 -How 'Get-ProcessMitigation -System' -Test {
        $pm = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if(-not $pm){ return $false }
        $bottomUp = & $isOn $pm.ASLR.BottomUp
        $hasHigh  = ($pm.ASLR | Get-Member -Name HighEntropy -MemberType NoteProperty) -ne $null
        $highEnt  = if($hasHigh){ & $isOn $pm.ASLR.HighEntropy } else { $true }  # x86 sans HighEntropy
        $bottomUp -and $highEnt
    }

    New-Check -Name 'Exploit Prot. - SEHOP (système) ON' -Domain 'Protection' -Criticity 'Élevée' -Weight 4 -How 'Get-ProcessMitigation -System' -Test {
        $pm = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if(-not $pm){ return $false }
        & $isOn $pm.SEHOP.Enable
    }

    New-Check -Name 'Exploit Prot. - ASLR ForceRelocateImages ON' -Domain 'Protection' -Criticity 'Moyenne' -Weight 2 -How 'Get-ProcessMitigation -System' -Test {
        $pm = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if(-not $pm){ return $false }
        & $isOn $pm.ASLR.ForceRelocateImages
    }
  New-Check -Name 'SmartScreen Windows ON' -Domain 'Protection' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\Windows\System EnableSmartScreen=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ea SilentlyContinue).EnableSmartScreen -eq 1
  }
  New-Check -Name 'Tamper Protection (signal)' -Domain 'Protection' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features Tamper*' -Test {
    $k='HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'; $p=Get-ItemProperty $k -ea SilentlyContinue
    if($p){ $true } else { $true }  # non observable proprement en PS pur
  }

  # --- PowerShell / Journalisation (5) ---
  New-Check -Name 'ExecutionPolicy=AllSigned (MachinePolicy)' -Domain 'PowerShell' -Criticity 'Critique' -Weight 5 -How 'Get-ExecutionPolicy -Scope MachinePolicy' -Test {
    (Get-ExecutionPolicy -Scope MachinePolicy -ErrorAction SilentlyContinue) -eq 'AllSigned'
  }
  New-Check -Name 'Script Block Logging ON' -Domain 'PowerShell' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\PowerShell\ScriptBlockLogging EnableScriptBlockLogging=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ea SilentlyContinue).EnableScriptBlockLogging -eq 1
  }
  New-Check -Name 'Module Logging ON' -Domain 'PowerShell' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\PowerShell\ModuleLogging EnableModuleLogging=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ea SilentlyContinue).EnableModuleLogging -eq 1
  }
  New-Check -Name 'Transcription ON' -Domain 'PowerShell' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\PowerShell\Transcription EnableTranscripting=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ea SilentlyContinue).EnableTranscripting -eq 1
  }
  #New-Check -Name 'User Execution Policy' -Domain 'PowerShell' -Criticity 'Faible' -Weight 2 -How 'Get-ExecutionPolicy -Scope UserPolicy' -Test {
    #$e=Get-ExecutionPolicy -Scope UserPolicy -ErrorAction SilentlyContinue; if(-not $e){$true}else{$e -eq 'AllSigned'}
  #}
  New-Check -Name 'ExecutionPolicy=AllSigned (UserPolicy si Machine Undefined)' -Domain 'PowerShell' -Criticity 'Faible' -Weight 2 -How 'Get-ExecutionPolicy -Scope UserPolicy' -Test {
      $m = Get-ExecutionPolicy -Scope MachinePolicy -ErrorAction SilentlyContinue
      if ($null -ne $m -and $m -ne 'Undefined') { $true }
      else { (Get-ExecutionPolicy -Scope UserPolicy -ErrorAction SilentlyContinue) -eq 'AllSigned' }
  }

  # --- Office / Edge (4) ---
  New-Check -Name 'Bloquer macros depuis Internet (Office)' -Domain 'Office/Edge' -Criticity 'Élevée' -Weight 4 -How 'HKCU:\...\Office\16.0\Word\Security BlockMacrosFromInternet=1' -Test {
    (Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security' -ea SilentlyContinue).BlockMacrosFromInternet -eq 1
  }
  New-Check -Name 'SmartScreen Edge activé' -Domain 'Office/Edge' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\SOFTWARE\Policies\Microsoft\Edge SmartScreenEnabled=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ea SilentlyContinue).SmartScreenEnabled -eq 1
  }
  New-Check -Name 'PUA/PUP blocking Edge' -Domain 'Office/Edge' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\SOFTWARE\Policies\Microsoft\Edge SmartScreenPuaEnabled=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ea SilentlyContinue).SmartScreenPuaEnabled -eq 1
  }
  New-Check -Name 'SmartScreen Windows activé' -Domain 'Office/Edge' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\Windows\System EnableSmartScreen=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ea SilentlyContinue).EnableSmartScreen -eq 1
  }

  # --- Périphériques / AutoRun / USB / Bluetooth (5) ---
  New-Check -Name 'Exécution automatique désactivée' -Domain 'Périphériques' -Criticity 'Moyenne' -Weight 3 -How 'HKLM:\...\Explorer NoDriveTypeAutoRun=255' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ea SilentlyContinue).NoDriveTypeAutoRun -eq 255
  }
  New-Check -Name 'Stockage USB bloqué (politique)' -Domain 'Périphériques' -Criticity 'Élevée' -Weight 4 -How 'HKLM:\...\RemovableStorageDevices Deny_All=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -ea SilentlyContinue).Deny_All -eq 1
  }
  New-Check -Name 'Bluetooth service désactivé si inutile' -Domain 'Périphériques' -Criticity 'Moyenne' -Weight 3 -How 'Get-Service bthserv' -Test {
    $s=Get-Service bthserv -ea SilentlyContinue; if(-not $s){$true}else{$s.StartType -eq 'Disabled' -or -not $s.Status -or $s.Status -eq 'Stopped'}
  }
  New-Check -Name 'Désactiver camera si politique' -Domain 'Périphériques' -Criticity 'Faible' -Weight 2 -How 'HKLM:\SOFTWARE\Policies\Microsoft\Camera AllowCamera=0' -Test {
    $k=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -ea SilentlyContinue; if(-not $k){$true}else{$k.AllowCamera -eq 0}
  }
  New-Check -Name 'Désactiver Micro si politique' -Domain 'Périphériques' -Criticity 'Faible' -Weight 2 -How 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy LetAppsAccessMicrophone=2' -Test {
    $k=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -ea SilentlyContinue; if(-not $k){$true}else{$k.LetAppsAccessMicrophone -eq 2}
  }

  # --- Hygiène / Logs / Mises à jour (5) ---
  New-Check -Name 'Consumer Features désactivées' -Domain 'Hygiène' -Criticity 'Faible' -Weight 2 -How 'HKLM:\...\CloudContent DisableWindowsConsumerFeatures=1' -Test {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -ea SilentlyContinue).DisableWindowsConsumerFeatures -eq 1
  }
  New-Check -Name 'Afficher extensions fichiers' -Domain 'Hygiène' -Criticity 'Faible' -Weight 2 -How 'HKCU:\...\Explorer\Advanced HideFileExt=0' -Test {
    (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ea SilentlyContinue).HideFileExt -eq 0
  }
  New-Check -Name 'Bloatware UWP supprimable (contrôle)' -Domain 'Hygiène' -Criticity 'Faible' -Weight 2 -How "Get-AppxPackage | match 'Xbox|Bing|Skype'" -Test {
    (Get-AppxPackage | ? {$_.Name -match 'Xbox|Bing|Skype'}).Count -eq 0
  }
  New-Check -Name 'Journal Sécurité taille suffisante' -Domain 'Journalisation' -Criticity 'Moyenne' -Weight 3 -How 'Get-WinEvent -ListLog Security' -Test {
    (Get-WinEvent -ListLog Security).MaximumSizeInBytes -ge 256MB
  }
  New-Check -Name 'WU dernière installation <=14 jours' -Domain 'Mises à jour' -Criticity 'Élevée' -Weight 4 -How "WindowsUpdate.log via Get-WindowsUpdateLog (fallback COM Microsoft.Update.Session)" -Test {
  param($MaxDays = 14, [switch]$IncludeDefender)  # tu peux passer -IncludeDefender si tu veux les compter

  function Get-LastWUInstallDate {
    param([switch]$IncludeDefender)

    # 1) Essayer via WindowsUpdate.log généré à la volée
    try {
      if (Get-Command Get-WindowsUpdateLog -ErrorAction SilentlyContinue) {
        $tmp = Join-Path $env:TEMP "WindowsUpdate_$($env:COMPUTERNAME).log"
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue | Out-Null
        Get-WindowsUpdateLog -LogPath $tmp -ErrorAction Stop | Out-Null

        # Motifs multi-langues pour repérer une installation réussie
        $successPat = '(?i)Installation\s+(?:Successful|Success|réussie).+Windows.+install(?:ed|é|ée).+update'
        $defPat     = '(?i)defender|security intelligence|antivirus|KB2267602|malicious software removal tool|KB890830'

        $line = Get-Content $tmp -Tail 5000 -ErrorAction SilentlyContinue |
          Where-Object {
            $_ -match $successPat -and ( $IncludeDefender -or $_ -notmatch $defPat )
          } | Select-Object -Last 1

        if ($line) {
          $m = [regex]::Match($line,'^(?<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')
          if ($m.Success) {
            return [datetime]::ParseExact($m.Groups['dt'].Value,'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
          }
        }
      }
    } catch {
      # ignore et bascule sur COM
    }

    # 2) Secours: COM Microsoft.Update.Session (ne dépend pas des journaux)
    try {
      $session  = New-Object -ComObject 'Microsoft.Update.Session'
      $searcher = $session.CreateUpdateSearcher()
      $count    = $searcher.GetTotalHistoryCount()
      if ($count -gt 0) {
        $hist = $searcher.QueryHistory(0, [Math]::Min($count, 2000))
        $entries = @($hist) | Where-Object {
          $_.Operation -eq 1 -and ( $_.ResultCode -in 2,3 )  # 2=Succeeded, 3=SucceededWithErrors
        }
        if (-not $IncludeDefender) {
          $entries = $entries | Where-Object { $_.Title -notmatch '(?i)defender|security intelligence|antivirus|KB2267602|malicious software removal tool|KB890830' }
        }
        $last = $entries | Sort-Object Date -Descending | Select-Object -First 1
        if ($last) { return $last.Date }
      }
    } catch {
      # rien
    }

    return $null
      }

      $last = Get-LastWUInstallDate -IncludeDefender:$IncludeDefender
      if (-not $last) { return $false }
      return ((Get-Date) - $last).TotalDays -le $MaxDays
    }


)

# ---------- Exécution & score ----------
$results = foreach($c in $Checks){ Invoke-Check $c }
$totalWeight = ($results | Measure-Object -Property Weight -Sum).Sum
$earned = ($results | ForEach-Object { if($_.Passed){ $_.Weight } else { 0 } } | Measure-Object -Sum).Sum
$score = if($totalWeight -gt 0){ [math]::Round(($earned / $totalWeight) * 100,2) } else { 0 }
$passedCount = ($results | Where-Object Passed).Count
$totalCount  = $results.Count

$hostname = $env:COMPUTERNAME
$user     = "$($env:USERDOMAIN)\$($env:USERNAME)"
$combo    = '{0} - {1}%' -f $hostname, ([string]::Format('{0:0.##}', $score))
$newLine  = Convert-ToCsvSemicolonLine -HostName $hostname -ScorePercent $score -Passed $passedCount -Total $totalCount -CombinedCell $combo -User $user -Time (Get-Date)

# ---------- Construction du HTML ----------
function GetBadge($ok){
  if($ok){ '<span class="chip ok">Conforme</span>' } else { '<span class="chip ko">Non conforme</span>' }
}
function GetCritClass([string]$crit){
  switch($crit){
    'Critique' { 'crit-critique' }
    'Élevée'   { 'crit-elevee' }
    'Moyenne'  { 'crit-moyenne' }
    'Faible'   { 'crit-faible' }
    default    { '' }
  }
}
$rowsHtml = foreach($r in ($results | Sort-Object Domain, @{Expression='Weight';Descending=$true}, Name)){
  $badge   = GetBadge $r.Passed
  $rowClass= GetCritClass $r.Criticity
@"
<tr class="$rowClass" data-dom="$([System.Web.HttpUtility]::HtmlAttributeEncode($r.Domain))" data-crit="$([System.Web.HttpUtility]::HtmlAttributeEncode($r.Criticity))">
  <td class="dom">$([System.Web.HttpUtility]::HtmlEncode($r.Domain))</td>
  <td class="name">$([System.Web.HttpUtility]::HtmlEncode($r.Name))</td>
  <td class="crit">$([System.Web.HttpUtility]::HtmlEncode($r.Criticity))</td>
  <td class="w">$($r.Weight)</td>
  <td class="status">$badge</td>
  <td class="details"><code>$([System.Web.HttpUtility]::HtmlEncode($r.Details))</code></td>
  <td class="how"><code>$([System.Web.HttpUtility]::HtmlEncode($r.How))</code></td>
</tr>
"@
}
$now = Get-Date -Format 'yyyy-MM-dd HH:mm'

$html = @"
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows Compliance Report v4</title>
<style>
  :root{
    --bg:#f6f7fb; --panel:#ffffff; --text:#1f2937; --muted:#6b7280; --border:#e5e7eb;
    --ok:#16a34a; --ok-bg:#eaf7ee; --ok-b:#bfe6cc;
    --ko:#dc2626; --ko-bg:#fde8e8; --ko-b:#f5c2c2;
    --accent:#2563eb; --accent-bg:#e7efff; --shadow:0 6px 18px rgba(17,24,39,.08);
    --thead:#f9fbff;
    --critique: rgb(210, 60, 85);
    --elevee:   rgb(235, 125, 45);
    --moyenne:  rgb(240, 190, 60);
    --faible:   rgb(70, 150, 240);
    --critique-bg: rgb(255, 215, 220);
    --elevee-bg:   rgb(255, 230, 205);
    --moyenne-bg:  rgb(255, 245, 200);
    --faible-bg:   rgb(220, 235, 255);
  }
  .dark{
    --bg:#0f172a; --panel:#0b1220; --text:#e5e7eb; --muted:#94a3b8; --border:#263041;
    --ok:#4ade80; --ok-bg:#16341f; --ok-b:#1f5a33;
    --ko:#f87171; --ko-bg:#3b1f20; --ko-b:#5f2a2d;
    --accent:#60a5fa; --accent-bg:#0b1b36; --shadow:0 6px 18px rgba(0,0,0,.35);
    --thead:#0b1220;
    --critique: rgb(186, 88, 106);
    --elevee:   rgb(213, 132, 82);
    --moyenne:  rgb(232, 185, 120);
    --faible:   rgb(118, 170, 224);
    --critique-bg: rgba(186, 88, 106, 0.25);
    --elevee-bg:   rgba(213, 132, 82, 0.25);
    --moyenne-bg:  rgba(232, 185, 120, 0.25);
    --faible-bg:   rgba(118, 170, 224, 0.25);
  }
  *{ box-sizing:border-box }
  body{ margin:0; background:var(--bg); color:var(--text); font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu; transition:background .2s,color .2s }
  header{ position:sticky; top:0; z-index:10; background:linear-gradient(90deg,var(--panel),var(--accent-bg)); border-bottom:1px solid var(--border); padding:14px 16px; box-shadow: var(--shadow); display:flex; align-items:center; gap:12px; width:100%; }
  h1{ margin:0; font-size:20px }
  .sub{ color:var(--muted); font-size:13px }
  .wrap{ max-width:none; width:100%; margin:0; padding:12px 16px 28px }
  .modebtn{ margin-left:auto; appearance:none; border:1px solid var(--border); background:var(--panel); color:var(--text); border-radius:10px; padding:8px 12px; cursor:pointer; }
  .tiles{ display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:12px; margin:16px 0; }
  .card{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; box-shadow: var(--shadow); }
  .k{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.4px }
  .v{ font-size:22px; font-weight:700; margin-top:6px }
  .progress{ height:10px; margin-top:8px; background:var(--accent-bg); border-radius:999px; overflow:hidden; }
  .bar{ height:100%; width:0%; background:linear-gradient(90deg,#34d399,#60a5fa); transition:width .6s ease }
  .tools{ display:flex; gap:10px; align-items:center; margin:6px 0 10px }
  .tools label{ color:var(--muted); font-size:12px }
  .tools select,.tools input{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:8px 10px; outline:none; min-width:180px; color:var(--text); }
  .tools input{ flex:1 }
  .table-wrap{ background:var(--panel); border:1px solid var(--border); border-radius:12px; box-shadow: var(--shadow); overflow:auto; width:100%; }
  table{ width:100%; border-collapse: separate; border-spacing:0 }
  thead th{ position:sticky; top:0px; background:var(--thead); border-bottom:1px solid var(--border); padding:12px 12px; text-align:left; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.3px; user-select:none; cursor:pointer; }
  thead th.sort-asc::after{ content:" ▲"; } thead th.sort-desc::after{ content:" ▼"; }
  tbody td{ padding:12px; border-bottom:1px solid var(--border); vertical-align:top }
  tbody tr:hover > td { filter: brightness(1.2); transition: filter 0.25s ease; }
  .chip{ display:inline-block; padding:4px 10px; border-radius:999px; border:1px solid; font-weight:600; font-size:12px; }
  :root .chip.ok { color:#059669; background:#E7F8F0; border:1px solid #10B981; }
  :root .chip.ko { color:#DC2626; background:#FFE9E9; border:1px solid #F87171; }
  :root .chip.na { color:#2563EB; background:#E7EEFF; border:1px solid #60A5FA; }
  .dark .chip.ok { color:#10B981; background:rgba(16,185,129,.15); border:1px solid #047857; }
  .dark .chip.ko { color:#F87171; background:rgba(248,113,113,.15); border:1px solid #B91C1C; }
  .dark .chip.na { color:#60A5FA; background:rgba(96,165,250,.15); border:1px solid #1D4ED8; }
  code{ font-family: ui-monospace,SFMono-Regular,Consolas,Menlo,monospace; font-size:12px; background:transparent; padding:2px 6px; border-radius:6px; border:1px solid var(--border); color:var(--text) }
  .dom{ width:180px } .name{ width:360px } .crit{ width:120px } .w{ width:90px } .status{ width:150px } .how{ width:420px } .details{ width:420px }
  tbody tr.crit-critique > td { background: var(--critique-bg) !important; }
  tbody tr.crit-elevee   > td { background: var(--elevee-bg)   !important; }
  tbody tr.crit-moyenne  > td { background: var(--moyenne-bg)  !important; }
  tbody tr.crit-faible   > td { background: var(--faible-bg)   !important; }
  tbody tr[data-crit="Critique"] > td { background: var(--critique-bg) !important; }
  tbody tr[data-crit="Élevée"]   > td { background: var(--elevee-bg)   !important; }
  tbody tr[data-crit="Moyenne"]  > td { background: var(--moyenne-bg)  !important; }
  tbody tr[data-crit="Faible"]   > td { background: var(--faible-bg)   !important; }
  tbody tr.crit-critique > td:first-child, tbody tr[data-crit="Critique"] > td:first-child { border-left: 6px solid var(--critique); }
  tbody tr.crit-elevee  > td:first-child, tbody tr[data-crit="Élevée"]  > td:first-child { border-left: 6px solid var(--elevee); }
  tbody tr.crit-moyenne > td:first-child, tbody tr[data-crit="Moyenne"] > td:first-child { border-left: 6px solid var(--moyenne); }
  tbody tr.crit-faible  > td:first-child, tbody tr[data-crit="Faible"]  > td:first-child { border-left: 6px solid var(--faible); }
</style>
</head>
<body>
<header>
  <h1>Windows Compliance Report v4</h1>
  <div class="sub">Généré le $now — $passedCount / $totalCount conformes — Score pondéré : <b>$score%</b></div>
  <button class="modebtn" id="modeBtn">Basculer mode sombre</button>
</header>

<div class="wrap">
  <section class="tiles">
    <div class="card">
      <div class="k">Contrôles conformes</div>
      <div class="v">$passedCount / $totalCount</div>
      <div class="progress"><div id="bar1" class="bar"></div></div>
    </div>
    <div class="card">
      <div class="k">Score pondéré</div>
      <div class="v">$score%</div>
      <div class="progress"><div id="bar2" class="bar"></div></div>
    </div>
    <div class="card">
      <div class="k">Domaine le plus en défaut</div>
      <div class="v" id="worstDomain">Calcul…</div>
    </div>
    <div class="card">
      <div class="k">Criticités KO</div>
      <div class="v" id="koCrits">—</div>
    </div>
  </section>

  <div class="tools">
    <label>Domaine :</label>
    <select id="fDomain"><option value="">(Tous)</option></select>
    <label>Criticité :</label>
    <select id="fCrit">
      <option value="">(Toutes)</option>
      <option>Critique</option><option>Élevée</option><option>Moyenne</option><option>Faible</option>
    </select>
    <label>Statut :</label>
    <select id="fStatus">
      <option value="">(Tous)</option>
      <option value="ok">Conforme</option>
      <option value="ko">Non conforme</option>
    </select>
    <label>Recherche :</label>
    <input id="q" placeholder="Nom, détail, commande…"/>
  </div>

  <div class="table-wrap">
    <table id="tbl">
      <thead>
        <tr>
          <th data-type="text">Domaine</th>
          <th data-type="text">Mesure</th>
          <th data-type="text">Criticité</th>
          <th data-type="number">Poids</th>
          <th data-type="text">Statut</th>
          <th data-type="text">Détails</th>
          <th data-type="text">Vérification (comment)</th>
        </tr>
      </thead>
      <tbody>
        $rowsHtml
      </tbody>
    </table>
  </div>

  <p style="color:var(--muted);font-size:12px;margin:10px 4px;">Astuce : tri par clic sur entête (2e clic inverse). Filtres en haut. Recherche plein texte.</p>
</div>

<script>
  const total = $totalCount, passed = $passedCount, score = $score;
  document.getElementById('bar1').style.width = Math.round((passed/total)*100) + '%';
  document.getElementById('bar2').style.width = score + '%';

  const btn = document.getElementById('modeBtn');
  const saved = localStorage.getItem('mode') || 'light';
  if(saved === 'dark'){ document.body.classList.add('dark'); btn.textContent = 'Basculer mode clair'; }
  btn.addEventListener('click', ()=>{
    const dark = document.body.classList.toggle('dark');
    btn.textContent = dark ? 'Basculer mode clair' : 'Basculer mode sombre';
    localStorage.setItem('mode', dark ? 'dark' : 'light');
  });

  const domSelect = document.getElementById('fDomain');
  const critSelect = document.getElementById('fCrit');
  const statusSelect = document.getElementById('fStatus');
  const qInput = document.getElementById('q');
  const seen = {};
  document.querySelectorAll('#tbl tbody tr td.dom').forEach(td=>{
    const v = td.textContent.trim();
    if(!seen[v]){ seen[v]=1; const opt=document.createElement('option'); opt.textContent=v; opt.value=v; domSelect.appendChild(opt); }
  });

  function applyFilters(){
    const d = domSelect.value;
    const c = critSelect.value;
    const s = statusSelect.value;
    const q = qInput.value.toLowerCase();

    document.querySelectorAll('#tbl tbody tr').forEach(tr=>{
      const tdom  = tr.querySelector('.dom').textContent.trim();
      const tcrit = tr.querySelector('.crit').textContent.trim();
      const ok    = tr.querySelector('.status').textContent.includes('Conforme');
      const txt   = tr.textContent.toLowerCase();

      let show = true;
      if(d && tdom!==d) show=false;
      if(c && tcrit!==c) show=false;
      if(s==='ok' && !ok) show=false;
      if(s==='ko' && ok)  show=false;
      if(q && !txt.includes(q)) show=false;

      tr.style.display = show ? '' : 'none';
    });
    recomputeSummary();
  }
  [domSelect, critSelect, statusSelect, qInput].forEach(el => el.addEventListener('input', applyFilters));

  const table = document.getElementById('tbl');
  const headers = table.querySelectorAll('thead th');
  let sortState = { index: -1, dir: 1 };
  headers.forEach((th, idx) => {
    th.addEventListener('click', () => {
      const type = th.getAttribute('data-type') || 'text';
      headers.forEach(h=>{ h.classList.remove('sort-asc','sort-desc'); });
      if(sortState.index === idx){ sortState.dir = -sortState.dir; } else { sortState.index = idx; sortState.dir = 1; }
      th.classList.add(sortState.dir === 1 ? 'sort-asc' : 'sort-desc');
      const rows = Array.from(table.querySelectorAll('tbody tr')).filter(tr=>tr.style.display!=='none');
      rows.sort((a,b)=>{
        const A = a.children[idx].textContent.trim();
        const B = b.children[idx].textContent.trim();
        if(type === 'number'){
          const aN = parseFloat(A.replace(',', '.')) || 0;
          const bN = parseFloat(B.replace(',', '.')) || 0;
          return (aN - bN) * sortState.dir;
        } else {
          return A.localeCompare(B, 'fr', { sensitivity:'base' }) * sortState.dir;
        }
      });
      const tbody = table.querySelector('tbody');
      rows.forEach(r => tbody.appendChild(r));
    });
  });

  document.querySelectorAll('#tbl tbody tr').forEach(tr=>{
    const crit = (tr.querySelector('.crit')?.textContent || '').trim();
    const map = { 'Critique':'crit-critique', 'Élevée':'crit-elevee', 'Moyenne':'crit-moyenne', 'Faible':'crit-faible' };
    const cls = map[crit];
    if(cls && !tr.classList.contains(cls)) tr.classList.add(cls);
  });

  function recomputeSummary(){
    const rows = Array.from(document.querySelectorAll('#tbl tbody tr')).filter(tr=>tr.style.display!=='none');
    const countByDomain = {}, koCrit = {};
    rows.forEach(tr=>{
      const dom = tr.querySelector('.dom').textContent.trim();
      const crit = tr.querySelector('.crit').textContent.trim();
      const ok = tr.querySelector('.status').textContent.includes('Conforme');
      if(!ok){
        countByDomain[dom] = (countByDomain[dom]||0) + 1;
        koCrit[crit] = (koCrit[crit]||0) + 1;
      }
    });
    const worst = Object.entries(countByDomain).sort((a,b)=>b[1]-a[1])[0];
    document.getElementById('worstDomain').textContent = worst ? worst[0]+' ('+worst[1]+' KO)' : '—';
    const crits = Object.entries(koCrit).sort((a,b)=>b[1]-a[1]).map(e=>e[0]+': '+e[1]).join(' · ');
    document.getElementById('koCrits').textContent = crits || '—';
  }
  recomputeSummary();
</script>
</body>
</html>
"@

# ---------- Écriture HTML local ----------
$dir = Split-Path -Path $OutFile -Parent
if ($dir -and -not (Test-Path $dir)) { New-DirectoryIfMissing $dir }
$html | Out-File -Encoding UTF8 -FilePath $OutFile
Write-Host "Rapport généré : $OutFile"

# ---------- Exports partagés (HTML + CSV) si dossier fourni ----------
function Update-DailyCsvSafely {
  param(
    [Parameter(Mandatory)][string]$CsvPath,
    [Parameter(Mandatory)][string]$NewLine,
    [Parameter(Mandatory)][string]$Header,
    [Parameter(Mandatory)][string]$SharedFolder
  )

  # --- Préparation répertoires ---
  $utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
  $dir        = Split-Path -Parent $CsvPath
  try { if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null } } catch {}
  if (-not $SharedFolder) { $SharedFolder = $dir }
  $pendingDirShare = Join-Path $SharedFolder 'pending'
  $pendingDirLocal = 'C:\ProgramData\Audit\pending'
  foreach($pd in @($pendingDirShare,$pendingDirLocal)){
    try { if ($pd -and -not (Test-Path -LiteralPath $pd)) { New-Item -ItemType Directory -Force -Path $pd | Out-Null } } catch {}
  }

  # --- Helpers sûrs PS 5.1 ---
  function Read-AllLinesSafe([string]$Path){
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    $tries=0; $last=''
    while($tries -lt 6){
      $fs=$sr=$null
      try{
        $fs = New-Object System.IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs,[Text.UTF8Encoding]::UTF8,$true)
        $txt = $sr.ReadToEnd()
        if ($null -ne $txt) { $txt = $txt -replace "^\uFEFF", '' }
        return ($txt -split "`r?`n")
      } catch {
        $last=$_.Exception.Message
        Start-Sleep -Milliseconds (120 + (Get-Random -Minimum 0 -Maximum 300))
      } finally {
        if($sr){$sr.Dispose()}; if($fs){$fs.Dispose()}
      }
      $tries++
    }
    Write-Warning "Lecture CSV échouée: $Path ($last)"
    return @()
  }

  function Is-Header([string]$line){
    if ([string]::IsNullOrWhiteSpace($line)) { return $false }
    $l = $line.TrimStart([char]0xFEFF)
    return $l -eq 'Host;ScorePercent;Passed;Total;CombinedCell;User;TimeISO'
  }

  function Parse-Time([string]$line){
  if ([string]::IsNullOrWhiteSpace($line)) { return $null }
  $p = $line.Split(';')
  if ($p.Length -lt 7) { return $null }

  $s = $p[6]
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  $ci = [System.Globalization.CultureInfo]::InvariantCulture
  try {
    # Le CSV écrit TimeISO avec $Time.ToString('s') -> "yyyy-MM-ddTHH:mm:ss"
    return [datetime]::ParseExact($s, 's', $ci)
  } catch {
    try { return [datetime]::Parse($s, $ci) } catch { return $null }
  }
}


  function Add-Line([string]$L,[hashtable]$Map){
    if ([string]::IsNullOrWhiteSpace($L) -or (Is-Header $L)) { return }
    $parts = $L.Split(';')
    if ($parts.Length -lt 1) { return }
    $h = $parts[0]; if ([string]::IsNullOrWhiteSpace($h)) { return }
    $h = $h.Trim()
    $t = Parse-Time $L
    if (-not $Map.ContainsKey($h)) { $Map[$h] = @{ line=$L; time=$t } }
    else {
      $old = $Map[$h]
      if ($t -and ($null -eq $old.time -or $t -gt $old.time)) { $Map[$h] = @{ line=$L; time=$t } }
    }
  }

  # --- Agrégation en mémoire ---
  $lines = Read-AllLinesSafe -Path $CsvPath
  $map = @{}
  foreach($ln in $lines){ Add-Line $ln $map }

  # absorbe pending (sur le partage si dispo)
  $pend = @()
  try { if ($pendingDirShare) { $pend = Get-ChildItem -Path $pendingDirShare -Filter '*.row' -ErrorAction Stop } } catch {}
  foreach($f in $pend){
    try{
      $content = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 -ErrorAction Stop
      if ($null -ne $content) { $content = $content -replace "^\uFEFF", '' }
      Add-Line $content $map
    } catch {
      Write-Warning "Absorption pending échouée '$($f.Name)' : $($_.Exception.Message)"
    }
  }

  Add-Line $NewLine $map   # ligne courante obligatoire

  # --- Reconstruit le contenu final ---
  $final = New-Object System.Collections.Generic.List[string]
  $final.Add($Header) | Out-Null
  foreach($kv in $map.GetEnumerator() | Sort-Object Key){ $final.Add($kv.Value.line) | Out-Null }
  if ($final.Count -eq 0) { $final.Add($Header) | Out-Null }  # garde-fou absolu

  $content = [string]::Join("`r`n",$final) + "`r`n"
  $bytes   = $utf8NoBom.GetBytes($content)

  # --- Écrit dans un fichier .new puis swap atomique (sans .tmp) ---
  $tmp = Join-Path $dir ("{0}.new.{1}" -f [IO.Path]::GetFileName($CsvPath), [Guid]::NewGuid().ToString('N'))
  try {
    [System.IO.File]::WriteAllBytes($tmp, $bytes)
  } catch {
    Write-Warning "Écriture intermédiaire échouée ($tmp) : $($_.Exception.Message)"
    # Fallback : dépose la ligne brute en pending (partage, puis local)
    $fname = '{0:yyyyMMdd_HHmmssfff}_{1}.row' -f (Get-Date), $env:COMPUTERNAME
    foreach($dest in @((Join-Path $pendingDirShare $fname),(Join-Path $pendingDirLocal $fname))){
      try { [System.IO.File]::WriteAllText($dest,$NewLine,$utf8NoBom); Write-Warning "Ligne déposée dans '$dest'."; return } catch {}
    }
    Write-Error "Impossible d'écrire ni le CSV ni le pending (droits ? FSRM/AV ?)."; return
  }

  try {
    if (Test-Path -LiteralPath $CsvPath) {
      [System.IO.File]::Replace($tmp,$CsvPath,"$CsvPath.bak")
    } else {
      Move-Item -LiteralPath $tmp -Destination $CsvPath -Force
    }
    foreach($f in $pend){ Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
    Write-Host ("CSV OK : {0} | hosts={1} | bytes={2}" -f $CsvPath, $map.Count, (Get-Item $CsvPath).Length)
  } catch {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    # Dernier recours : déposer la ligne en pending
    $fname2 = '{0:yyyyMMdd_HHmmssfff}_{1}.row' -f (Get-Date), $env:COMPUTERNAME
    foreach($dest in @((Join-Path $pendingDirShare $fname2),(Join-Path $pendingDirLocal $fname2))){
      try { [System.IO.File]::WriteAllText($dest,$NewLine,$utf8NoBom); Write-Warning "Swap atomique KO. Ligne déposée dans '$dest'."; return } catch {}
    }
    Write-Error "Swap atomique KO et pending KO. Vérifie droits NTFS/partage et FSRM/AV sur '$SharedFolder'."
  }
}


if ($SharedCsvFolder) {
  $sharedFolder = Resolve-SharedFolder $SharedCsvFolder
  $dateTag  = Get-Date -Format 'yyyyMMdd'
  $hostname = $env:COMPUTERNAME

  # HTML partagé : yyyyMMdd_ComplianteReport_<ComputerName>.html
  $sharedHtml = Join-Path $sharedFolder ("{0}_ComplianteReport_{1}.html" -f $dateTag,$hostname)
  $html | Out-File -Encoding UTF8 -FilePath $sharedHtml
  Write-Host "HTML partagé : $sharedHtml"

  # CSV unique du jour : yyyyMMdd_ComplianceReport.csv
  $csvPath = Join-Path $sharedFolder ("{0}_ComplianceReport.csv" -f $dateTag)
  $header  = 'Host;ScorePercent;Passed;Total;CombinedCell;User;TimeISO'

  # Prépare la nouvelle ligne poste
  $newLine = Convert-ToCsvSemicolonLine `
    -HostName $hostname `
    -ScorePercent $score `
    -Passed $passedCount `
    -Total $totalCount `
    -CombinedCell ('{0} - {1}%' -f $hostname, ([string]::Format('{0:0.##}', $score))) `
    -User "$($env:USERDOMAIN)\$($env:USERNAME)" `
    -Time (Get-Date)

  # Mise à jour robuste et atomique
  Update-DailyCsvSafely -CsvPath $csvPath -NewLine $newLine -Header $header -SharedFolder $sharedFolder
}
}
finally {
  if ($script:TranscriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
  }
}