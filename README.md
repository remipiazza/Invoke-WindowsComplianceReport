# WindowsComplianceReport.ps1

Script PowerShell d’audit de conformité des postes Windows (workstations et serveurs) générant :

- un **rapport HTML interactif** (design moderne, clair/sombre, tri, filtres, recherche plein texte) ;
- des **exports CSV par poste** (un fichier CSV par machine et par jour, prêt à être agrégé).

L’objectif est de vérifier automatiquement un ensemble de mesures d’hygiène et de durcissement Windows inspirées de plusieurs référentiels :

- Recommandations de l’**ANSSI** (hygiène informatique, durcissement des postes, TLS, journalisation…)  
- **CIS Benchmarks** pour Windows 10/11 et Windows Server  
- **Microsoft Security Baselines** (Windows, Edge, Office, Defender)  

> ⚠️ Ce script **ne constitue pas une implémentation officielle** de ces référentiels.  
> Il s’en inspire pour proposer un socle d’hygiène cohérent et automatisable.

---

## 1. Paramètres

### 1.1 Définition

```powershell
[CmdletBinding()]
param(
  [string]$OutFile = (Join-Path $env:TEMP 'WindowsComplianceReport.html'),
  [string]$SharedCsvFolder,   # dossier UNC, ex: \\SRV-FICHIERS\SecOps\Compliance
  [string]$LogFolder = 'C:\Windows\Audit\logs'
)
```

### 1.2 Détails des paramètres

#### `-OutFile`

- **Type** : `string`  
- **Par défaut** : `%TEMP%\WindowsComplianceReport.html`  
- **Rôle** : chemin de sortie du **rapport HTML local**.  
- Le dossier parent est créé automatiquement si nécessaire.  
- Encodage UTF-8.

#### `-SharedCsvFolder`

- **Type** : `string`  
- **Obligatoire ?** : non  
- **Rôle** : dossier local ou UNC où le script dépose les exports par poste :

  - `yyyyMMdd_ComplianceReport_<ComputerName>.html`
  - `yyyyMMdd_ComplianceReport_<ComputerName>.csv`

- Exemples :

  ```powershell
  -SharedCsvFolder '\\FILESRV01\SecOps\Compliance'
  -SharedCsvFolder 'D:\Reports\Compliance'
  ```

Le CSV par poste contient **un header et une seule ligne** pour la machine :

```text
Host;ScorePercent;Passed;Total;CombinedCell;User;TimeISO
```

Un second script peut ensuite **agréger** tous ces CSV journaliers en un **CSV global**, puis **supprimer** les fichiers sources après agrégation réussie.

#### `-LogFolder`

- **Type** : `string`  
- **Par défaut** : `C:\Windows\Audit\logs`  
- **Rôle** : dossier où est enregistré le **transcript PowerShell** :

  - `WindowsCompliance_<COMPUTERNAME>_<YYYYMMDD_HHMMSS>.log`

- Si le transcript échoue (droits/politiques), le script journalise un avertissement et continue.

---

## 2. Prérequis

- Windows 10 / 11 ou Windows Server récents.
- PowerShell 5.1+ (ou 7+ avec compatibilité).
- Exécution en **administrateur local** pour que tous les contrôles soient pertinents.
- Accès en écriture sur :

  - `OutFile` (rapport local) ;
  - `LogFolder` (si utilisé) ;
  - `SharedCsvFolder` (si utilisé).

Certains contrôles utilisent des cmdlets / composants spécifiques :

- `Get-BitLockerVolume` (module BitLocker)
- `Get-Tpm`
- `Get-CimInstance Win32_DeviceGuard`
- `Get-NetFirewallProfile`, `Get-SmbClientConfiguration`, `Get-SmbServerConfiguration`
- `Get-MpPreference`
- `Get-ProcessMitigation`
- `Get-WinEvent`, `Get-WindowsUpdateLog`, COM `Microsoft.Update.Session`

---

## 3. Exemples d’utilisation

### 3.1 Rapport local uniquement

```powershell
.\WindowsComplianceReport.ps1
```

ou :

```powershell
.\WindowsComplianceReport.ps1 -OutFile 'C:\Reports\WindowsCompliance_%COMPUTERNAME%.html'
```

### 3.2 Rapport local + export réseau par poste

```powershell
.\WindowsComplianceReport.ps1 `
  -OutFile 'C:\Reports\WindowsCompliance_%COMPUTERNAME%.html' `
  -SharedCsvFolder '\\FILESRV01\SecOps\Compliance'
```

Résultat typique pour la date `20251105` et l’hôte `PC001` :

- `C:\Reports\WindowsCompliance_PC001.html` (local)
- `\\FILESRV01\SecOps\Compliance\20251105_ComplianceReport_PC001.html`
- `\\FILESRV01\SecOps\Compliance\20251105_ComplianceReport_PC001.csv`

---

## 4. Architecture du script

1. Normalisation des chemins (`Unquote`, expansion des variables d’environnement).
2. Démarrage optionnel d’un **transcript** dans `-LogFolder`.
3. Définition d’un moteur de contrôles :

   - `New-Check` : décrit un contrôle (Nom, Domaine, Criticité, Poids, Test, How).
   - `Invoke-Check` : exécute le scriptblock de test et renvoie un objet résultat.

4. Construction de la liste de contrôles (`$Checks`).
5. Exécution de tous les contrôles, calcul :

   - du **score global pondéré** ;
   - du nombre de contrôles conformes / total.

6. Génération du **HTML** (tuiles de synthèse + tableau détaillé).
7. Écriture du HTML local (`-OutFile`).
8. Si `-SharedCsvFolder` est renseigné :

   - écriture d’un HTML par poste sur le partage ;
   - écriture d’un CSV par poste sur le partage.

9. Arrêt du transcript dans le bloc `finally`.

---

## 5. Score de conformité

Chaque contrôle possède un **poids** (`Weight` de 1 à 5) calibré sur la criticité :

- **Critique** → poids élevé (≈ 4–5)
- **Élevée**
- **Moyenne**
- **Faible**

Le score global est calculé ainsi :

```text
Score = (somme des poids des contrôles Passed=$true) /
        (somme de tous les poids) × 100
```

Ce score est affiché :

- dans les tuiles du rapport HTML ;
- dans le CSV par poste (`ScorePercent`).

---

## 6. Exports HTML et CSV

### 6.1 HTML local (`-OutFile`)

Le rapport inclut :

- un header sticky avec :
  - la date de génération ;
  - le score et le nombre de contrôles conformes ;
- des **tuiles** de synthèse :
  - nombre de contrôles conformes ;
  - score pondéré ;
  - domaine le plus en défaut ;
  - distribution des criticités KO ;
- un **tableau interactif** :
  - tri par colonne (clic sur l’en-tête) ;
  - filtres par domaine, criticité, statut ;
  - recherche plein texte sur toutes les colonnes ;
  - coloration des lignes par criticité, avec un liseré à gauche.

Un bouton permet de **basculer entre mode clair et sombre**, avec persistance en `localStorage`.

### 6.2 HTML + CSV par poste (`-SharedCsvFolder`)

Si `-SharedCsvFolder` est renseigné, le script écrit pour chaque poste :

- `yyyyMMdd_ComplianceReport_<ComputerName>.html`
- `yyyyMMdd_ComplianceReport_<ComputerName>.csv`

Le CSV est un fichier autonome **par machine et par jour** (header + 1 ligne).  
Un second script d’agrégation peut ensuite :

1. lire tous les CSV `yyyyMMdd_ComplianceReport_*.csv` d’un dossier ;
2. construire un **CSV global** ;
3. **supprimer** les CSV sources après agrégation réussie.

---

## 7. Liste des contrôles et référentiels

> Seuls les contrôles **non commentés** dans le script sont listés ci-dessous.  
> Les contrôles commentés (`# New-Check ...`) ne sont pas exécutés et ne figurent pas dans ce tableau.

Pour chaque contrôle :

- **Nom** : identique à celui du script ;
- **Domaine** : domaine fonctionnel ;
- **Ce que ça vérifie** : logique fonctionnelle ;
- **Implémentation** : principe de test (cmdlet, registre…) ;
- **Référentiels** : grandes familles de bonnes pratiques auxquelles la mesure renvoie.

---

## 7.1 Chiffrement / Plateforme

1. **BitLocker OS protégé (TPM)**  
   - **Domaine** : Chiffrement  
   - **Ce que ça vérifie** : le volume système `C:` est protégé par BitLocker avec une protection active.  
   - **Implémentation** : `Get-BitLockerVolume -MountPoint C:` et vérification de `ProtectionStatus = On`.  
   - **Référentiels** : ANSSI (chiffrement des postes), CIS Windows, Microsoft Security Baselines (BitLocker).

2. **Lecteurs de données chiffrés**  
   - **Domaine** : Chiffrement  
   - **Ce que ça vérifie** : tous les volumes de type Data sont chiffrés, ou aucun volume Data n’est présent.  
   - **Implémentation** : `Get-BitLockerVolume | Where-Object VolumeType -eq 'Data'` et contrôle de `ProtectionStatus`.  
   - **Référentiels** : ANSSI (supports de stockage), CIS (Data drives), Baselines Microsoft (chiffrement des volumes de données).

3. **Chiffrement XTS-AES 256 (si exigé)**  
   - **Domaine** : Chiffrement  
   - **Ce que ça vérifie** : au moins un volume utilise XTS-AES 256 si cette exigence est en place.  
   - **Implémentation** : `Get-BitLockerVolume | Select-Object -Expand EncryptionMethod` et recherche de `XTS-AES 256`.  
   - **Référentiels** : ANSSI (choix des algorithmes), CIS BitLocker, Microsoft (recommandation XTS-AES 256).

4. **TPM présent**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : la machine dispose d’un module TPM.  
   - **Implémentation** : `Get-Tpm` et vérification de `TpmPresent`.  
   - **Référentiels** : ANSSI Windows / plateforme de confiance, CIS Windows, Baselines Microsoft (TPM requis pour certaines fonctions).

5. **TPM prêt**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : le TPM est initialisé et prêt à l’emploi.  
   - **Implémentation** : `Get-Tpm` et vérification de `TpmReady`.  
   - **Référentiels** : ANSSI Windows 10 sécurité, CIS Windows, Baselines Microsoft.

6. **TPM 2.0 (SpecVersion)**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : la version de spécification du TPM est 2.0.  
   - **Implémentation** : `Get-WmiObject -Namespace root\cimv2\Security\MicrosoftTpm -Class Win32_Tpm` et lecture de `SpecVersion`.  
   - **Référentiels** : ANSSI (VBS, Device Guard), CIS, Microsoft (prérequis Windows 11 / VBS).

7. **Secure Boot activé**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : Secure Boot (UEFI) est activé.  
   - **Implémentation** : `Confirm-SecureBootUEFI`.  
   - **Référentiels** : ANSSI (chaîne de démarrage de confiance), CIS Windows, Baselines Microsoft.

8. **Démarrage mesuré (VBS/HVCI prêt ?)**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : la machine est prête pour Virtualization Based Security / Device Guard (services de sécurité configurés).  
   - **Implémentation** : `Get-CimInstance Win32_DeviceGuard` et contrôle de `SecurityServicesConfigured`.  
   - **Référentiels** : ANSSI Windows 10 sécu (VBS, Credential Guard), CIS, Microsoft (Device Guard / Memory Integrity).


---

## 7.2 TLS / SSL

1. **TLS 1.2 Client activé**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : TLS 1.2 est activé côté client pour SCHANNEL.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client` avec `Enabled=1`.  
   - **Référentiels** : ANSSI (TLS ≥ 1.2), CIS Windows, Baselines Microsoft.

2. **TLS 1.2 Server activé**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : TLS 1.2 est activé côté serveur.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server` avec `Enabled=1`.  
   - **Référentiels** : ANSSI, CIS, Baselines Microsoft.

3. **TLS 1.3 Client activé (si support)**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : si TLS 1.3 est disponible, il est activé côté client.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client` `Enabled=1` si présente, sinon considéré N/A.  
   - **Référentiels** : ANSSI (versions récentes TLS), CIS Windows 11, Baselines Microsoft récentes.

4. **TLS 1.3 Server activé (si support)**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : si TLS 1.3 est disponible, il est activé côté serveur.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server` `Enabled=1` si présente, sinon N/A.  
   - **Référentiels** : ANSSI, CIS Windows, Baselines Microsoft.

5. **SSL 3.0 Client désactivé**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : SSL 3.0 est désactivé côté client.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client` `Enabled=0`.  
   - **Référentiels** : ANSSI (interdiction SSL obsolètes), CIS, Microsoft (POODLE).

6. **SSL 3.0 Server désactivé**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : SSL 3.0 est désactivé côté serveur.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server` `Enabled=0`.  
   - **Référentiels** : ANSSI, CIS, Microsoft.

7. **TLS 1.0 Client désactivé**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : TLS 1.0 est désactivé côté client.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client` `Enabled=0`.  
   - **Référentiels** : ANSSI (TLS 1.0 obsolète), CIS, Baselines Microsoft.

8. **TLS 1.1 Client désactivé**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : TLS 1.1 est désactivé côté client.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client` `Enabled=0`.  
   - **Référentiels** : ANSSI (éviter TLS 1.1), CIS, Baselines Microsoft.


---

## 7.3 Réseau / SMB / Découverte

1. **SMBv1 supprimé (feature)**  
   - **Domaine** : Réseau/SMB  
   - **Ce que ça vérifie** : la fonctionnalité SMB 1.0/CIFS est désactivée.  
   - **Implémentation** : `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` et `State = Disabled`.  
   - **Référentiels** : ANSSI (SMBv1 à proscrire), CIS Windows, Microsoft (post-WannaCry).

2. **SMB signing requis (Client)**  
   - **Domaine** : Réseau/SMB  
   - **Ce que ça vérifie** : le client SMB exige la signature des communications.  
   - **Implémentation** : `Get-SmbClientConfiguration` et `RequireSecuritySignature = $true`.  
   - **Référentiels** : ANSSI (intégrité SMB), CIS Windows, Baselines Microsoft.

3. **SMB signing requis (Server)**  
   - **Domaine** : Réseau/SMB  
   - **Ce que ça vérifie** : le serveur SMB exige la signature des communications.  
   - **Implémentation** : `Get-SmbServerConfiguration` et `RequireSecuritySignature = $true`.  
   - **Référentiels** : ANSSI, CIS Windows, Baselines Microsoft.

4. **Accès invité SMB interdit**  
   - **Domaine** : Réseau/SMB  
   - **Ce que ça vérifie** : les accès invités non sécurisés sont interdits.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation` `AllowInsecureGuestAuth=0`.  
   - **Référentiels** : ANSSI (partages invités), CIS, Baselines Microsoft.

5. **LLMNR désactivé**  
   - **Domaine** : Réseau  
   - **Ce que ça vérifie** : le protocole LLMNR est désactivé (évite certaines attaques de spoofing).  
   - **Implémentation** : clé `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` `EnableMulticast=0`.  
   - **Référentiels** : ANSSI (réduction surface réseau), CIS Windows, Baselines Microsoft.

6. **WPAD AutoDetect désactivé**  
   - **Domaine** : Réseau  
   - **Ce que ça vérifie** : la découverte automatique de proxy WPAD via WinHTTP est désactivée.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` `DisableWpad=1`.  
   - **Référentiels** : ANSSI (risques WPAD), CIS, bonnes pratiques Microsoft.

7. **NetBIOS over TCP/IP désactivé**  
   - **Domaine** : Réseau  
   - **Ce que ça vérifie** : NetBIOS over TCP/IP est désactivé sur les interfaces.  
   - **Implémentation** : lecture des clés sous `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces` et recherche de `NetbiosOptions=2`.  
   - **Référentiels** : ANSSI (services hérités), CIS Windows, durcissement Microsoft.

8. **mDNS 5353 bloqué (inbound)**  
   - **Domaine** : Réseau  
   - **Ce que ça vérifie** : au moins une règle pare-feu gère/bloque le trafic mDNS (port 5353) en entrée.  
   - **Implémentation** : `Get-NetFirewallRule` filtré sur `Direction = Inbound` et `DisplayName` contenant `mDNS` ou `5353`.  
   - **Référentiels** : ANSSI (limiter découverte non contrôlée), CIS (pare-feu), Baselines Microsoft.


---

## 7.4 Identité / Comptes / RDP / LSA

1. **NTLMv2 uniquement (LmCompatibilityLevel>=5)**  
   - **Domaine** : Identité  
   - **Ce que ça vérifie** : désactive LM et NTLMv1 ; l’authentification se fait en NTLMv2 uniquement.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `LmCompatibilityLevel>=5`.  
   - **Référentiels** : ANSSI, CIS, Microsoft (NTLM hardening).

2. **LSASS protégé (config)**  
   - **Domaine** : Identité  
   - **Ce que ça vérifie** : LSASS est configuré pour fonctionner en mode protégé (PPL), selon la version de l’OS.  
   - **Implémentation** : dans `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, vérifie `RunAsPPL` (1 ou 2 selon build).  
   - **Référentiels** : ANSSI (protection des secrets), CIS Windows, Microsoft (LSA Protection / Credential Guard).

3. **RunAsPPLBoot=1 (early launch)**  
   - **Domaine** : Identité  
   - **Ce que ça vérifie** : LSASS protégé est lancé précocement au démarrage (early launch).  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `RunAsPPLBoot=1`.  
   - **Référentiels** : Renforcement LSASS (Microsoft), CIS, ANSSI Windows 10 sécu.

4. **NoLMHash=1**  
   - **Domaine** : Identité  
   - **Ce que ça vérifie** : les hash LM ne sont pas stockés.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `NoLMHash=1`.  
   - **Référentiels** : ANSSI (hash obsolètes), CIS Windows, Microsoft.

5. **LAPS activé (password local admin)**  
   - **Domaine** : Identité  
   - **Ce que ça vérifie** : un mécanisme LAPS (Windows LAPS GPO, Intune CSP ou legacy AdmPwd) gère les mots de passe des comptes locaux admin, avec rotation régulière.  
   - **Implémentation** : lecture des clés LAPS (`HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS`, `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\LAPS`, `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd`) + éventuellement le journal LAPS.  
   - **Référentiels** : ANSSI (comptes locaux), ANSSI Admin AD, CIS Windows, Microsoft (Windows LAPS).

6. **Admin intégré désactivé**  
   - **Domaine** : Comptes  
   - **Ce que ça vérifie** : le compte Administrateur intégré (RID 500) est désactivé.  
   - **Implémentation** : `Get-LocalUser` et détection de SID se terminant par `-500`, puis `Enabled = $false`.  
   - **Référentiels** : ANSSI, CIS Windows, Baselines Microsoft.

7. **Invité désactivé**  
   - **Domaine** : Comptes  
   - **Ce que ça vérifie** : le compte Invité (RID 501) est désactivé.  
   - **Implémentation** : `Get-LocalUser` et détection de SID se terminant par `-501`, puis `Enabled = $false`.  
   - **Référentiels** : ANSSI, CIS Windows, Baselines Microsoft.

8. **NLA exigée pour RDP**  
   - **Domaine** : Accès distant  
   - **Ce que ça vérifie** : l’authentification au niveau réseau (NLA) est obligatoire pour RDP.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` `UserAuthentication=1`.  
   - **Référentiels** : ANSSI (sécurisation RDP), CIS Windows, Baselines Microsoft.

9. **RDP désactivé si non requis**  
   - **Domaine** : Accès distant  
   - **Ce que ça vérifie** : le service RDP est désactivé quand il n’est pas nécessaire.  
   - **Implémentation** : clé `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` `fDenyTSConnections=1`.  
   - **Référentiels** : ANSSI (réduire surface d’exposition), CIS, Baselines Microsoft.

10. **Cache d’info d’auth minimale**  
    - **Domaine** : Identité  
    - **Ce que ça vérifie** : limite le nombre de connexions mises en cache localement (≤ 10).  
    - **Implémentation** : clé `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` `CachedLogonsCount` (≤ 10 ou valeur par défaut acceptée).  
    - **Référentiels** : CIS Windows, bonnes pratiques Microsoft.


---

## 7.5 Protection / Défense / Pare-feu / Exploit

1. **Pare-feu profils ON**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : tous les profils du pare-feu Windows (Domain, Private, Public) sont activés.  
   - **Implémentation** : `Get-NetFirewallProfile` et vérification de `Enabled`.  
   - **Référentiels** : ANSSI hygiène, CIS Windows, Baselines Microsoft.

2. **Pare-feu inbound=Block**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : l’action par défaut en entrée est le blocage (Block) au niveau du pare-feu.  
   - **Implémentation** : `Get-NetFirewallProfile` et lecture de `DefaultInboundAction`.  
   - **Référentiels** : ANSSI (tout bloquer par défaut), CIS Windows, Baselines Microsoft.

3. **Pare-feu outbound=Allow (par défaut)**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : l’action par défaut en sortie est Allow (comportement standard sans politique egress stricte).  
   - **Implémentation** : `Get-NetFirewallProfile` et lecture de `DefaultOutboundAction`.  
   - **Référentiels** : bonnes pratiques Microsoft / CIS (profil par défaut), utilisé ici surtout comme information.

4. **Protection cloud MAPS (élevée)**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : la protection cloud de Microsoft Defender (MAPS) est active, ainsi que l’envoi d’échantillons.  
   - **Implémentation** : `Get-MpPreference` et contrôle de `MAPSReporting` et `SubmitSamplesConsent`.  
   - **Référentiels** : Microsoft Defender, Baselines Microsoft, CIS Windows (config Defender).

5. **Exploit Prot. – DEP (système) ON**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : Data Execution Prevention (DEP) est activé au niveau système.  
   - **Implémentation** : `Get-ProcessMitigation -System` puis `DEP.Enable`.  
   - **Référentiels** : ANSSI (mitigations), CIS Windows, Microsoft Exploit Protection.

6. **Exploit Prot. – CFG (système) ON**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : Control Flow Guard (CFG) est activé au niveau système.  
   - **Implémentation** : `Get-ProcessMitigation -System` puis `CFG.Enable`.  
   - **Référentiels** : CIS Windows, Microsoft Exploit Protection, recommandations ANSSI.

7. **Exploit Prot. – ASLR (BottomUp+HighEntropy) ON**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : ASLR system-wide est activé (BottomUp + High Entropy si disponible).  
   - **Implémentation** : `Get-ProcessMitigation -System` puis `ASLR.BottomUp` et `ASLR.HighEntropy` (ou toléré si absent sur x86).  
   - **Référentiels** : ANSSI (randomisation mémoire), CIS Windows, Baselines Microsoft.

8. **Exploit Prot. – SEHOP (système) ON**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : SEHOP (Structured Exception Handler Overwrite Protection) est activé au niveau système.  
   - **Implémentation** : `Get-ProcessMitigation -System` puis `SEHOP.Enable`.  
   - **Référentiels** : CIS Windows, Microsoft Exploit Protection.

9. **Exploit Prot. – ASLR ForceRelocateImages ON**  
   - **Domaine** : Protection  
   - **Ce que ça vérifie** : ASLR force la relocation des images chargées.  
   - **Implémentation** : `Get-ProcessMitigation -System` puis `ASLR.ForceRelocateImages`.  
   - **Référentiels** : Microsoft Exploit Protection, CIS Windows.

10. **SmartScreen Windows ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : SmartScreen Windows (niveau OS) est activé via stratégie.  
    - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` `EnableSmartScreen=1`.  
    - **Référentiels** : Baselines Microsoft, CIS Windows, ANSSI (filtrage d’exécution / réputation).

11. **Tamper Protection (signal)**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : présence de la clé de fonctionnalités Defender indiquant une configuration de Tamper Protection (signal indicatif, non strict).  
    - **Implémentation** : existence de `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`.  
    - **Référentiels** : Microsoft Defender (Tamper Protection), Baselines Microsoft.


---

## 7.6 PowerShell / Journalisation

1. **ExecutionPolicy=AllSigned (MachinePolicy)**  
   - **Domaine** : PowerShell  
   - **Ce que ça vérifie** : la politique d’exécution PowerShell définie par GPO machine est `AllSigned`.  
   - **Implémentation** : `Get-ExecutionPolicy -Scope MachinePolicy`.  
   - **Référentiels** : ANSSI (scripts signés), CIS Windows, Baselines Microsoft PowerShell.

2. **Script Block Logging ON**  
   - **Domaine** : PowerShell  
   - **Ce que ça vérifie** : la journalisation des blocs de scripts PowerShell est activée.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` `EnableScriptBlockLogging=1`.  
   - **Référentiels** : ANSSI (journalisation détaillée), CIS Windows, Baselines Microsoft.

3. **Module Logging ON**  
   - **Domaine** : PowerShell  
   - **Ce que ça vérifie** : la journalisation des modules PowerShell est activée.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` `EnableModuleLogging=1`.  
   - **Référentiels** : ANSSI, CIS Windows, Baselines Microsoft.

4. **Transcription ON**  
   - **Domaine** : PowerShell  
   - **Ce que ça vérifie** : la transcription PowerShell (capture des sessions) est activée via GPO.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` `EnableTranscripting=1`.  
   - **Référentiels** : ANSSI (traces des actions d’admin), CIS Windows, Baselines Microsoft.

5. **ExecutionPolicy=AllSigned (UserPolicy si Machine Undefined)**  
   - **Domaine** : PowerShell  
   - **Ce que ça vérifie** : si MachinePolicy n’est pas définie, la politique UserPolicy impose `AllSigned`.  
   - **Implémentation** : lecture de `Get-ExecutionPolicy -Scope MachinePolicy`, puis de `UserPolicy` si MachinePolicy = `Undefined`.  
   - **Référentiels** : ANSSI, CIS, Baselines Microsoft (contrôle des scripts côté utilisateur).


---

## 7.7 Office / Edge

1. **Bloquer macros depuis Internet (Office)**  
   - **Domaine** : Office/Edge  
   - **Ce que ça vérifie** : les macros provenant d’Internet sont bloquées dans Word 16.0.  
   - **Implémentation** : clé `HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security` `BlockMacrosFromInternet=1`.  
   - **Référentiels** : ANSSI (macro-malveillance), CIS Microsoft Office, Baselines Microsoft Office.

2. **SmartScreen Edge activé**  
   - **Domaine** : Office/Edge  
   - **Ce que ça vérifie** : SmartScreen est activé dans Microsoft Edge.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Edge` `SmartScreenEnabled=1`.  
   - **Référentiels** : CIS Microsoft Edge, Edge Security Baseline, ANSSI (navigation sécurisée).

3. **PUA/PUP blocking Edge**  
   - **Domaine** : Office/Edge  
   - **Ce que ça vérifie** : le blocage des applications potentiellement indésirables (PUA/PUP) est activé dans Edge.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Edge` `SmartScreenPuaEnabled=1`.  
   - **Référentiels** : Microsoft (PUA protection), CIS Edge, Baselines Microsoft.

4. **SmartScreen Windows activé**  
   - **Domaine** : Office/Edge  
   - **Ce que ça vérifie** : SmartScreen Windows (même clé que 7.5.10) est activé pour l’écosystème navigateur / OS.  
   - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` `EnableSmartScreen=1`.  
   - **Référentiels** : Baselines Microsoft, CIS, ANSSI (filtrage URL / fichiers).


---

## 7.8 Périphériques / AutoRun / USB / Bluetooth

1. **Exécution automatique désactivée**  
   - **Domaine** : Périphériques  
   - **Ce que ça vérifie** : AutoRun/AutoPlay sont désactivés pour tous les types de lecteurs.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` `NoDriveTypeAutoRun=255`.  
   - **Référentiels** : ANSSI hygiène (supports amovibles), CIS Windows, Baselines Microsoft.

2. **Stockage USB bloqué (politique)**  
   - **Domaine** : Périphériques  
   - **Ce que ça vérifie** : les périphériques de stockage amovibles sont bloqués via politique.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices` `Deny_All=1`.  
   - **Référentiels** : ANSSI (supports amovibles), CIS Windows, Baselines Microsoft (device control).

3. **Bluetooth service désactivé si inutile**  
   - **Domaine** : Périphériques  
   - **Ce que ça vérifie** : le service Bluetooth (`bthserv`) est désactivé ou arrêté s’il n’est pas nécessaire.  
   - **Implémentation** : `Get-Service bthserv` puis contrôle de `StartType` et `Status`.  
   - **Référentiels** : ANSSI (réduction surface radio), CIS Windows (services inutiles).

4. **Désactiver camera si politique**  
   - **Domaine** : Périphériques  
   - **Ce que ça vérifie** : une politique de désactivation de la caméra est appliquée si pertinente.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Camera` `AllowCamera=0` si présente, sinon considéré N/A/OK.  
   - **Référentiels** : ANSSI / CNIL (confidentialité), Baselines Microsoft (Camera privacy).

5. **Désactiver Micro si politique**  
   - **Domaine** : Périphériques  
   - **Ce que ça vérifie** : une politique limite l’accès des applications au micro.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy` `LetAppsAccessMicrophone=2` si présente, sinon N/A/OK.  
   - **Référentiels** : Confidentialité (CNIL), Baselines Microsoft, durcissement des postes.


---

## 7.9 Hygiène / Logs / Mises à jour

1. **Consumer Features désactivées**  
   - **Domaine** : Hygiène  
   - **Ce que ça vérifie** : les fonctionnalités “consommateur” Windows (apps sponsorisées, suggestions, etc.) sont désactivées.  
   - **Implémentation** : clé `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent` `DisableWindowsConsumerFeatures=1`.  
   - **Référentiels** : CIS Windows, Baselines Microsoft (CloudContent), ANSSI (réduction bloat / télémétrie non nécessaire).

2. **Bloatware UWP supprimable (contrôle)**  
   - **Domaine** : Hygiène  
   - **Ce que ça vérifie** : absence de certaines apps UWP préinstallées (Xbox, Bing, Skype) hors quelques exceptions nécessaires.  
   - **Implémentation** : `Get-AppxPackage -AllUsers` filtré sur `Name` contenant `Xbox|Bing|Skype` et non dans la liste blanche (`Microsoft.XboxGameCallableUI`, `Microsoft.BingSearch`).  
   - **Référentiels** : ANSSI (réduire la surface applicative), CIS Windows (built-in apps), Baselines Microsoft.

3. **Journal Sécurité taille suffisante**  
   - **Domaine** : Journalisation  
   - **Ce que ça vérifie** : la taille maximale du journal Security est au moins de 256 Mo.  
   - **Implémentation** : `Get-WinEvent -ListLog Security` et contrôle `MaximumSizeInBytes -ge 256MB`.  
   - **Référentiels** : ANSSI hygiène (journalisation riche), ANSSI Admin AD, CIS Windows, Baselines Microsoft.

4. **WU dernière installation ≤ 14 jours**  
   - **Domaine** : Mises à jour  
   - **Ce que ça vérifie** : au moins une mise à jour Windows (hors simples signatures, selon filtre) a été installée dans les 14 derniers jours.  
   - **Implémentation** : génération de `WindowsUpdate.log` via `Get-WindowsUpdateLog` + parsing, puis fallback COM `Microsoft.Update.Session` pour l’historique d’updates ; comparaison de la date avec `(Get-Date).AddDays(-14)`.  
   - **Référentiels** : ANSSI hygiène (mise à jour régulière), ANSSI Windows/AD, CIS Windows (Windows Update), Baselines Microsoft.


---

## 8. Limitations et adaptations

- Le script vise un **compromis** entre exhaustivité et maintenabilité.
- Certaines vérifications sont **tolérantes** (considèrent “OK/N/A” lorsqu’aucune politique n’est définie) afin de ne pas sur-pénaliser des postes hors scope.
- Tu peux ajuster :
  - les **poids** (Weight) ;
  - les **criticités** ;
  - les **seuils** (taille de journal, délai WU, âge LAPS, etc.) ;
  - la **liste des bloatwares**.

---

## 9. Avertissement

Ce script est fourni à titre d’outil d’audit / de diagnostic :

- il **ne remplace pas** un audit complet basé sur un référentiel formel (CIS, ANSSI, etc.) ;
- il peut nécessiter des adaptations à ton contexte (politiques internes, contraintes applicatives, exemptions) ;
- il est recommandé de le faire valider par les équipes **sécu / conformité** avant utilisation en production.

## License

This project is released under a custom **Non-Commercial License**.

You are allowed to use, copy, modify, and distribute this software **for non-commercial purposes only**.  
Any commercial use (including resale, inclusion in paid products or services, or use within a commercial offering)
requires prior written permission from the author.

See the [LICENSE](./LICENSE) file for details.
