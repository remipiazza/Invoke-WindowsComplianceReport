# WindowsComplianceReport.ps1 – README

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

### 7.1 Chiffrement / Plateforme

1. **BitLocker OS protégé (TPM)**  
   - **Domaine** : Chiffrement  
   - **Ce que ça vérifie** : le volume système `C:` est protégé par BitLocker, `ProtectionStatus = On`.  
   - **Implémentation** : `Get-BitLockerVolume -MountPoint C:`  
   - **Référentiels** : ANSSI (chiffrement des postes), CIS Windows, Microsoft Security Baselines (BitLocker).

2. **Lecteurs de données chiffrés**  
   - **Domaine** : Chiffrement  
   - **Ce que ça vérifie** : tous les volumes `Data` sont chiffrés ou aucun volume Data n’est présent.  
   - **Implémentation** : `Get-BitLockerVolume | Where VolumeType=Data` et `ProtectionStatus`.  
   - **Référentiels** : ANSSI (supports de stockage), CIS (Data drives), Microsoft (BitLocker sur volumes de données).

3. **Chiffrement XTS-AES 256 (si exigé)**  
   - **Domaine** : Chiffrement  
   - **Ce que ça vérifie** : au moins un volume utilise XTS-AES 256 lorsqu’on l’exige.  
   - **Implémentation** : `Get-BitLockerVolume | Select -Expand EncryptionMethod`.  
   - **Référentiels** : recommandations sur les algorithmes / tailles de clé (ANSSI, Microsoft, CIS).

4. **TPM présent**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : présence d’un TPM sur la machine.  
   - **Implémentation** : `Get-Tpm` (`TpmPresent`).  
   - **Référentiels** : ANSSI (plateforme de confiance), CIS, Microsoft (TPM obligatoire pour certaines fonctionnalités).

5. **TPM prêt**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : le TPM est initialisé et prêt (`TpmReady`).  
   - **Implémentation** : `Get-Tpm`.  
   - **Référentiels** : mêmes que ci-dessus.

6. **TPM 2.0 (SpecVersion)**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : la version de spécification du TPM est 2.0.  
   - **Implémentation** : `Get-WmiObject Win32_Tpm` (namespace DeviceGuard) → `SpecVersion`.  
   - **Référentiels** : ANSSI, Microsoft (TPM 2.0 recommandé / requis pour VBS, etc.), CIS.

7. **Secure Boot activé**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : UEFI Secure Boot est actif.  
   - **Implémentation** : `Confirm-SecureBootUEFI`.  
   - **Référentiels** : ANSSI (chaîne de démarrage de confiance), Microsoft, CIS.

8. **Démarrage mesuré (VBS/HVCI prêt ?)**  
   - **Domaine** : Plateforme  
   - **Ce que ça vérifie** : présence de services Device Guard / VBS configurés.  
   - **Implémentation** : `Get-CimInstance Win32_DeviceGuard` → `SecurityServicesConfigured`.  
   - **Référentiels** : ANSSI (VBS, Credential Guard), Microsoft (Device Guard / VBS), CIS.

---

### 7.2 TLS / SSL

9. **TLS 1.2 Client activé**  
   - **Domaine** : TLS/SSL  
   - **Ce que ça vérifie** : TLS 1.2 côté client est activé dans SCHANNEL.  
   - **Implémentation** : registre `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client` `Enabled=1`.  
   - **Référentiels** : ANSSI (version minimale TLS), CIS, Microsoft.

10. **TLS 1.2 Server activé**  
    - **Domaine** : TLS/SSL  
    - **Ce que ça vérifie** : TLS 1.2 côté serveur est activé.  
    - **Implémentation** : même principe sous `...\TLS 1.2\Server`.  
    - **Référentiels** : idem.

11. **TLS 1.3 Client activé (si support)**  
    - **Domaine** : TLS/SSL  
    - **Ce que ça vérifie** : si les clés TLS 1.3 existent, `Enabled=1` côté client.  
    - **Implémentation** : `...\Protocols\TLS 1.3\Client`.  
    - **Référentiels** : adoption des versions récentes TLS.

12. **TLS 1.3 Server activé (si support)**  
    - **Domaine** : TLS/SSL  
    - **Ce que ça vérifie** : idem côté serveur.  
    - **Implémentation** : `...\Protocols\TLS 1.3\Server`.  
    - **Référentiels** : idem.

13. **SSL 3.0 Client désactivé**  
    - **Domaine** : TLS/SSL  
    - **Ce que ça vérifie** : SSL 3.0 désactivé côté client.  
    - **Implémentation** : `...\SSL 3.0\Client` `Enabled=0`.  
    - **Référentiels** : ANSSI, CIS, Microsoft (POODLE).

14. **SSL 3.0 Server désactivé**  
    - **Domaine** : TLS/SSL  
    - **Ce que ça vérifie** : SSL 3.0 désactivé côté serveur.  
    - **Implémentation** : `...\SSL 3.0\Server` `Enabled=0`.  
    - **Référentiels** : idem.

15. **TLS 1.0 Client désactivé**  
    - **Domaine** : TLS/SSL  
    - **Ce que ça vérifie** : TLS 1.0 client désactivé.  
    - **Implémentation** : `...\TLS 1.0\Client` `Enabled=0`.  
    - **Référentiels** : ANSSI (TLS 1.0 obsolète), CIS, Microsoft.

16. **TLS 1.1 Client désactivé**  
    - **Domaine** : TLS/SSL  
    - **Ce que ça vérifie** : TLS 1.1 client désactivé.  
    - **Implémentation** : `...\TLS 1.1\Client` `Enabled=0`.  
    - **Référentiels** : idem.

---

### 7.3 Réseau / SMB / Découverte

17. **SMBv1 supprimé (feature)**  
    - **Domaine** : Réseau/SMB  
    - **Ce que ça vérifie** : la fonctionnalité SMB 1.0/CIFS est désactivée.  
    - **Implémentation** : `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.  
    - **Référentiels** : ANSSI, CIS, Microsoft (post-WannaCry).

18. **SMB signing requis (Client)**  
    - **Domaine** : Réseau/SMB  
    - **Ce que ça vérifie** : le client SMB exige la signature.  
    - **Implémentation** : `Get-SmbClientConfiguration` → `RequireSecuritySignature`.  
    - **Référentiels** : ANSSI, CIS, Microsoft Security Baselines.

19. **SMB signing requis (Server)**  
    - **Domaine** : Réseau/SMB  
    - **Ce que ça vérifie** : le serveur SMB exige la signature.  
    - **Implémentation** : `Get-SmbServerConfiguration` → `RequireSecuritySignature`.  
    - **Référentiels** : idem.

20. **Accès invité SMB interdit**  
    - **Domaine** : Réseau/SMB  
    - **Ce que ça vérifie** : l’accès invité non sécurisé est interdit.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation` `AllowInsecureGuestAuth=0`.  
    - **Référentiels** : ANSSI, CIS, Microsoft.

21. **LLMNR désactivé**  
    - **Domaine** : Réseau  
    - **Ce que ça vérifie** : désactivation de LLMNR.  
    - **Implémentation** : `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` `EnableMulticast=0`.  
    - **Référentiels** : ANSSI (réduction surface d’attaque), CIS.

22. **WPAD AutoDetect désactivé**  
    - **Domaine** : Réseau  
    - **Ce que ça vérifie** : désactivation de la découverte automatique WPAD (WinHTTP).  
    - **Implémentation** : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` `DisableWpad=1`.  
    - **Référentiels** : ANSSI (risques WPAD), bonnes pratiques Microsoft / CIS.

23. **NetBIOS over TCP/IP désactivé**  
    - **Domaine** : Réseau  
    - **Ce que ça vérifie** : `NetbiosOptions=2` sur toutes les interfaces NetBT.  
    - **Implémentation** : clés sous `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`.  
    - **Référentiels** : ANSSI (services hérités), CIS.

24. **mDNS 5353 bloqué (inbound)**  
    - **Domaine** : Réseau  
    - **Ce que ça vérifie** : existence d’au moins une règle pare-feu gérant/bloquant mDNS (port 5353) en entrée.  
    - **Implémentation** : `Get-NetFirewallRule` filtré sur `Direction=Inbound` et `DisplayName` contenant `mDNS` ou `5353`.  
    - **Référentiels** : pratiques de durcissement réseau (découverte de services).

---

### 7.4 Identité / Comptes / RDP / LSA

25. **NTLMv2 uniquement (LmCompatibilityLevel>=5)**  
    - **Domaine** : Identité  
    - **Ce que ça vérifie** : désactive LM et NTLMv1 (NTLMv2 only).  
    - **Implémentation** : `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `LmCompatibilityLevel>=5`.  
    - **Référentiels** : ANSSI, CIS, Microsoft (NTLM hardening).

26. **LSASS protégé (config)**  
    - **Domaine** : Identité  
    - **Ce que ça vérifie** : LSASS en mode PPL selon la version de l’OS.  
    - **Implémentation** :  
      - si build ≥ 22621 → `RunAsPPL` ∈ {1,2}  
      - sinon → `RunAsPPL=1`  
      dans `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.  
    - **Référentiels** : ANSSI (protection des secrets), Microsoft (LSA Protection), CIS.

27. **RunAsPPLBoot=1 (early launch)**  
    - **Domaine** : Identité  
    - **Ce que ça vérifie** : démarrage anticipé de LSASS en mode protégé.  
    - **Implémentation** : `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `RunAsPPLBoot=1`.  
    - **Référentiels** : renforcement LSASS (Microsoft, CIS).

28. **NoLMHash=1**  
    - **Domaine** : Identité  
    - **Ce que ça vérifie** : pas de stockage de hash LM.  
    - **Implémentation** : `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `NoLMHash=1`.  
    - **Référentiels** : ANSSI, CIS, Microsoft.

29. **LAPS activé (password local admin)**  
    - **Domaine** : Identité  
    - **Ce que ça vérifie** : présence d’une configuration LAPS (Windows LAPS GPO, Windows LAPS Intune CSP ou LAPS Legacy) avec mots de passe locaux uniques, stockés en directory, rotation ≤ 30 jours.  
    - **Implémentation** : lecture des clés LAPS + event log LAPS (fallback).  
    - **Référentiels** : ANSSI (comptes locaux), Microsoft (Windows LAPS), CIS.

30. **Admin intégré désactivé**  
    - **Domaine** : Comptes  
    - **Ce que ça vérifie** : le compte Administrateur intégré (`RID 500`) est désactivé.  
    - **Implémentation** : `Get-LocalUser` match SID `S-1-5-21-...-500`.  
    - **Référentiels** : ANSSI, CIS, Microsoft Baselines.

31. **Invité désactivé**  
    - **Domaine** : Comptes  
    - **Ce que ça vérifie** : le compte Invité (`RID 501`) est désactivé.  
    - **Implémentation** : `Get-LocalUser` match SID `S-1-5-21-...-501`.  
    - **Référentiels** : idem.

32. **NLA exigée pour RDP**  
    - **Domaine** : Accès distant  
    - **Ce que ça vérifie** : Network Level Authentication obligatoire pour RDP.  
    - **Implémentation** : `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` `UserAuthentication=1`.  
    - **Référentiels** : ANSSI RDP, CIS, Microsoft.

33. **RDP désactivé si non requis**  
    - **Domaine** : Accès distant  
    - **Ce que ça vérifie** : Remote Desktop désactivé (`fDenyTSConnections=1`).  
    - **Implémentation** : `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`.  
    - **Référentiels** : durcissement d’exposition RDP (ANSSI, CIS).

34. **Cache d’info d’auth minimale**  
    - **Domaine** : Identité  
    - **Ce que ça vérifie** : limite le nombre de logons mis en cache (≤ 10).  
    - **Implémentation** : `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` `CachedLogonsCount<=10` (ou valeur par défaut acceptée).  
    - **Référentiels** : CIS, bonnes pratiques Microsoft.

---

### 7.5 Protection / Défense / Pare-feu / Exploit

35. **Pare-feu profils ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : tous les profils pare-feu (Domain, Private, Public) sont activés.  
    - **Implémentation** : `Get-NetFirewallProfile` → `Enabled`.  
    - **Référentiels** : ANSSI, CIS, Microsoft.

36. **Pare-feu inbound=Block**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : l’action par défaut en entrée est **Block** sur au moins un profil (et généralement tous).  
    - **Implémentation** : `Get-NetFirewallProfile | Select DefaultInboundAction`.  
    - **Référentiels** : ANSSI (par défaut tout bloquer), CIS.

37. **Pare-feu outbound=Allow (par défaut)**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : l’action par défaut en sortie est Allow (comportement standard).  
    - **Implémentation** : `DefaultOutboundAction`.  
    - **Référentiels** : indicateur plutôt informatif (non bloquant).

38. **Protection cloud MAPS (élevée)**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : intégration Defender au cloud (MAPS) + envoi d’échantillons.  
    - **Implémentation** : `Get-MpPreference` → `MAPSReporting`, `SubmitSamplesConsent`.  
    - **Référentiels** : Microsoft Defender, Security Baselines, CIS.

39. **Exploit Prot. – DEP (système) ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : Data Execution Prevention globale activée.  
    - **Implémentation** : `Get-ProcessMitigation -System` → `DEP.Enable`.  
    - **Référentiels** : ANSSI, CIS, Microsoft Exploit Protection.

40. **Exploit Prot. – CFG (système) ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : Control Flow Guard système activé.  
    - **Implémentation** : `Get-ProcessMitigation -System` → `CFG.Enable`.  
    - **Référentiels** : Microsoft Exploit Protection, CIS.

41. **Exploit Prot. – ASLR (BottomUp+HighEntropy) ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : ASLR Bottom-Up + High Entropy (si supporté) activés.  
    - **Implémentation** : `Get-ProcessMitigation -System` → `ASLR.BottomUp` + `ASLR.HighEntropy`.  
    - **Référentiels** : Microsoft, CIS.

42. **Exploit Prot. – SEHOP (système) ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : Structured Exception Handler Overwrite Protection activé.  
    - **Implémentation** : `Get-ProcessMitigation -System` → `SEHOP.Enable`.  
    - **Référentiels** : Microsoft, CIS.

43. **Exploit Prot. – ASLR ForceRelocateImages ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : relocation forcée des images (ASLR).  
    - **Implémentation** : `ASLR.ForceRelocateImages`.  
    - **Référentiels** : Microsoft Exploit Protection.

44. **SmartScreen Windows ON**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : SmartScreen Windows global activé via GPO.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` `EnableSmartScreen=1`.  
    - **Référentiels** : Microsoft Security Baselines, CIS.

45. **Tamper Protection (signal)**  
    - **Domaine** : Protection  
    - **Ce que ça vérifie** : présence de la clé `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` (indicateur, non binaire strict).  
    - **Implémentation** : existence de la clé (le contrôle est tolérant).  
    - **Référentiels** : Microsoft Defender Tamper Protection (signal faible).

---

### 7.6 PowerShell / Journalisation

46. **ExecutionPolicy=AllSigned (MachinePolicy)**  
    - **Domaine** : PowerShell  
    - **Ce que ça vérifie** : politique d’exécution GPO machine = `AllSigned`.  
    - **Implémentation** : `Get-ExecutionPolicy -Scope MachinePolicy`.  
    - **Référentiels** : ANSSI (contrôle d’exécution de scripts), CIS, Microsoft.

47. **Script Block Logging ON**  
    - **Domaine** : PowerShell  
    - **Ce que ça vérifie** : journalisation des blocs de scripts PowerShell.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` `EnableScriptBlockLogging=1`.  
    - **Référentiels** : ANSSI (journalisation renforcée), CIS, Microsoft Baselines.

48. **Module Logging ON**  
    - **Domaine** : PowerShell  
    - **Ce que ça vérifie** : journalisation des modules PowerShell.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` `EnableModuleLogging=1`.  
    - **Référentiels** : idem.

49. **Transcription ON**  
    - **Domaine** : PowerShell  
    - **Ce que ça vérifie** : transcription PowerShell via GPO activée.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` `EnableTranscripting=1`.  
    - **Référentiels** : ANSSI, CIS, Microsoft Baselines.

50. **ExecutionPolicy=AllSigned (UserPolicy si Machine Undefined)**  
    - **Domaine** : PowerShell  
    - **Ce que ça vérifie** : si la MachinePolicy n’est pas définie, alors UserPolicy = `AllSigned`.  
    - **Implémentation** : `Get-ExecutionPolicy -Scope MachinePolicy` puis `UserPolicy`.  
    - **Référentiels** : mêmes objectifs que le contrôle 46.

---

### 7.7 Office / Edge

51. **Bloquer macros depuis Internet (Office)**  
    - **Domaine** : Office/Edge  
    - **Ce que ça vérifie** : blocage des macros provenant d’Internet dans Word 16.0.  
    - **Implémentation** : `HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security` `BlockMacrosFromInternet=1`.  
    - **Référentiels** : ANSSI macros, Microsoft, CIS Office.

52. **SmartScreen Edge activé**  
    - **Domaine** : Office/Edge  
    - **Ce que ça vérifie** : SmartScreen activé dans Edge.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Edge` `SmartScreenEnabled=1`.  
    - **Référentiels** : Microsoft Edge Security Baseline, CIS.

53. **PUA/PUP blocking Edge**  
    - **Domaine** : Office/Edge  
    - **Ce que ça vérifie** : blocage des applications potentiellement indésirables (PUA) dans Edge.  
    - **Implémentation** : `SmartScreenPuaEnabled=1`.  
    - **Référentiels** : Microsoft, CIS.

54. **SmartScreen Windows activé**  
    - **Domaine** : Office/Edge  
    - **Ce que ça vérifie** : même clé que contrôle 44 mais classée ici côté “navigateur / OS”.  
    - **Implémentation** : `EnableSmartScreen=1`.  
    - **Référentiels** : Microsoft, CIS.

---

### 7.8 Périphériques / AutoRun / USB / Bluetooth

55. **Exécution automatique désactivée**  
    - **Domaine** : Périphériques  
    - **Ce que ça vérifie** : AutoRun désactivé sur tous les types de lecteurs.  
    - **Implémentation** : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` `NoDriveTypeAutoRun=255`.  
    - **Référentiels** : ANSSI (supports amovibles), CIS.

56. **Stockage USB bloqué (politique)**  
    - **Domaine** : Périphériques  
    - **Ce que ça vérifie** : blocage général des périphériques de stockage amovibles via GPO.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices` `Deny_All=1`.  
    - **Référentiels** : ANSSI, CIS, Microsoft.

57. **Bluetooth service désactivé si inutile**  
    - **Domaine** : Périphériques  
    - **Ce que ça vérifie** : service `bthserv` désactivé ou arrêté si présent.  
    - **Implémentation** : `Get-Service bthserv`.  
    - **Référentiels** : surface d’attaque radio / proximité.

58. **Désactiver camera si politique**  
    - **Domaine** : Périphériques  
    - **Ce que ça vérifie** : GPO de désactivation de la caméra (si appliquée).  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Camera` `AllowCamera=0` ; si pas de clé, considéré “OK/N/A”.  
    - **Référentiels** : confidentialité / durcissement.

59. **Désactiver Micro si politique**  
    - **Domaine** : Périphériques  
    - **Ce que ça vérifie** : GPO de restriction de l’accès au micro par les apps.  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy` `LetAppsAccessMicrophone=2` ; si pas de clé, considéré “OK/N/A”.  
    - **Référentiels** : confidentialité / durcissement.

---

### 7.9 Hygiène / Logs / Mises à jour

60. **Consumer Features désactivées**  
    - **Domaine** : Hygiène  
    - **Ce que ça vérifie** : désactivation des fonctionnalités “consommateur” (suggestions, apps sponsorisées, etc.).  
    - **Implémentation** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent` `DisableWindowsConsumerFeatures=1`.  
    - **Référentiels** : Microsoft Baselines, CIS (bloat / distractions).

61. **Bloatware UWP supprimable (contrôle)**  
    - **Domaine** : Hygiène  
    - **Ce que ça vérifie** : absence de certaines apps UWP préinstallées (Xbox, Bing, Skype) hors exceptions :  
      - on considère conforme si **aucun** package `Xbox|Bing|Skype` restant, à part `Microsoft.XboxGameCallableUI` et `Microsoft.BingSearch`.  
    - **Implémentation** : `Get-AppxPackage -AllUsers | Where-Object { Name -match 'Xbox|Bing|Skype' -and Name -notin exceptions }`  
    - **Référentiels** : hygiène / réduction de la surface d’attaque applicative.

62. **Journal Sécurité taille suffisante**  
    - **Domaine** : Journalisation  
    - **Ce que ça vérifie** : taille max du journal **Security** ≥ 256 MB.  
    - **Implémentation** : `Get-WinEvent -ListLog Security` → `MaximumSizeInBytes -ge 256MB`.  
    - **Référentiels** : ANSSI (journalisation riche), CIS, Microsoft.

63. **WU dernière installation ≤ 14 jours**  
    - **Domaine** : Mises à jour  
    - **Ce que ça vérifie** : existence d’une mise à jour Windows installée (hors signatures Defender si choisi) dans les 14 derniers jours.  
    - **Implémentation** :  
      - tentative via `Get-WindowsUpdateLog` + parsing de `WindowsUpdate.log` ;  
      - fallback via COM `Microsoft.Update.Session` (historique WU) ;  
      - filtre Defender / update de définitions selon param interne.  
    - **Référentiels** : ANSSI (correctif régulier), CIS, Microsoft (Patch Tuesday, cadence de mises à jour).

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
