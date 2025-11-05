# WindowsComplianceReport.ps1 – README

Script PowerShell d’audit de conformité des postes Windows (workstations et serveurs) générant :

- un **rapport HTML interactif** (design moderne, clair/sombre, tri, filtres, recherche) ;
- des **exports CSV par poste** (un fichier CSV par machine et par jour, prêt à être agrégé).

L’objectif est de vérifier automatiquement un ensemble de mesures d’hygiène et de durcissement Windows inspirées de plusieurs référentiels :

- Recommandations de l’**ANSSI** (hygiène informatique, durcissement des postes, TLS, journaux…)  
- **CIS Benchmarks** pour Windows (10/11, Server)  
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
  [string]$SharedCsvFolder,   # dossier UNC, ex: \SRV-FICHIERS\SecOps\Compliance
  [string]$LogFolder = 'C:\Windows\Audit\logs'
)
```

### 1.2 Détails des paramètres

#### `-OutFile`

- **Type** : `string`  
- **Par défaut** : `%TEMP%\WindowsComplianceReport.html`  
- **Rôle** : chemin de sortie du **rapport HTML local**.  
- Le dossier parent est créé automatiquement si nécessaire.

#### `-SharedCsvFolder`

- **Type** : `string`  
- **Obligatoire ?** : non  
- **Rôle** : dossier local ou UNC où le script dépose les exports par poste :
  - `yyyyMMdd_ComplianceReport_<ComputerName>.html`
  - `yyyyMMdd_ComplianceReport_<ComputerName>.csv`
- Exemples :
  - `-SharedCsvFolder '\\FILESRV01\SecOps\Compliance'`
  - `-SharedCsvFolder 'D:\Reports\Compliance'`

Le CSV par poste contient **un header et une seule ligne** pour la machine :

```text
Host;ScorePercent;Passed;Total;CombinedCell;User;TimeISO
```

Un second script peut ensuite agréger tous ces CSV journaliers en un **CSV global**, puis supprimer les fichiers sources.

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
  - `OutFile` (rapport local),
  - `LogFolder` (si utilisé),
  - `SharedCsvFolder` (si utilisé).

Certains contrôles utilisent des cmdlets spécifiques :

- `Get-BitLockerVolume` (module BitLocker)
- `Get-Tpm` / `Get-CimInstance Win32_DeviceGuard`
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

ou

```powershell
.\WindowsComplianceReport.ps1 -OutFile 'C:\Reports\WindowsCompliance_<HOST>.html'
```

### 3.2 Rapport local + export réseau par poste

```powershell
.\WindowsComplianceReport.ps1 `
  -OutFile 'C:\Reports\WindowsCompliance_<HOST>.html' `
  -SharedCsvFolder '\\FILESRV01\SecOps\Compliance'
```

Résultat typique pour la date `20251105` :

- `C:\Reports\WindowsCompliance_PC001.html` (local)
- `\\FILESRV01\SecOps\Compliance\20251105_ComplianceReport_PC001.html`
- `\\FILESRV01\SecOps\Compliance\20251105_ComplianceReport_PC001.csv`

---

## 4. Architecture du script

1. Normalisation des chemins (`Unquote`, expansion des variables d’environnement).
2. Démarrage optionnel d’un **transcript** dans `-LogFolder`.
3. Définition d’un moteur de contrôles :
   - `New-Check` : décrit un contrôle (nom, domaine, criticité, poids, test, how).
   - `Invoke-Check` : exécute le scriptblock et renvoie un objet résultat.
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

- **Critique** → poids généralement plus élevé (4–5)
- **Élevée**
- **Moyenne**
- **Faible**

Le score global est calculé ainsi :

```text
Score = (somme des poids des contrôles Passed=$true) /
        (somme de tous les poids) × 100
```

Ce score est affiché :

- dans les tuiles du rapport HTML,
- dans le CSV par poste (`ScorePercent`).

---

## 6. Exports HTML et CSV

### 6.1 HTML local (`-OutFile`)

Le rapport inclut :

- un header sticky avec :
  - la date de génération,
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
  - coloration des lignes par criticité.

Un bouton permet de **basculer entre mode clair et sombre**, avec persistance en `localStorage`.

### 6.2 HTML + CSV par poste (`-SharedCsvFolder`)

Si `-SharedCsvFolder` est renseigné, le script écrit :

- `yyyyMMdd_ComplianceReport_<ComputerName>.html`
- `yyyyMMdd_ComplianceReport_<ComputerName>.csv`

Le CSV est un fichier autonome **par machine et par jour** (header + 1 ligne).  
Un second script peut agréger tous ces fichiers en un CSV global, puis supprimer les sources après agrégation réussie.

---

## 7. Liste des mesures vérifiées

> Les contrôles commentés dans le code ne figurent pas ici (ils ne sont pas exécutés).

Pour chaque contrôle :

- **Nom** : identique à celui du script,
- **Domaine** : regroupe les mesures,
- **Description** : ce qui est vérifié,
- **Vérification** : principe / commande ou clé,
- **Référentiels** : principaux documents / bonnes pratiques visées (sans prétendre couvrir un benchmark précis).

### 7.1 Chiffrement / Plateforme

#### BitLocker OS protégé (TPM)

- **Domaine** : Chiffrement  
- **Description** : Vérifie que la partition système (C:) est protégée par BitLocker et que l’état de protection est `On`.  
- **Vérification** : `Get-BitLockerVolume -MountPoint C:` → `ProtectionStatus -eq 'On'`.  
- **Référentiels** :
  - ANSSI – chiffrement des données au repos / poste de travail ;
  - CIS Benchmarks Windows (BitLocker pour lecteur système) ;
  - Microsoft Security Baseline – Device Encryption / BitLocker.

#### Lecteurs de données chiffrés

- **Domaine** : Chiffrement  
- **Description** : Contrôle que tous les volumes de type `Data` sont soit absents, soit protégés par BitLocker.  
- **Vérification** : `Get-BitLockerVolume | Where VolumeType=Data` et `ProtectionStatus`.  
- **Référentiels** :
  - ANSSI – chiffrement des supports, disques de données ;
  - CIS – chiffrement des volumes non système ;
  - Microsoft – BitLocker sur lecteurs de données.

#### Chiffrement XTS-AES 256 (si exigé)

- **Domaine** : Chiffrement  
- **Description** : Vérifie qu’au moins un volume utilise XTS-AES 256 si la politique interne l’exige.  
- **Vérification** : `Get-BitLockerVolume | Select EncryptionMethod`.  
- **Référentiels** :
  - ANSSI – algorithmes et tailles de clés recommandés ;
  - CIS – configuration des options BitLocker ;
  - Microsoft – recommandations BitLocker (XTS-AES).

#### TPM présent / TPM prêt / TPM 2.0

- **Domaine** : Plateforme  
- **Description** :
  - TPM présent (`Get-Tpm`).  
  - TPM prêt (`TpmReady`).  
  - Version TPM 2.0 (via WMI Win32_Tpm / SpecVersion).  
- **Référentiels** :
  - ANSSI – plateforme de confiance, usages du TPM ;
  - CIS – requirement TPM pour BitLocker et protections avancées ;
  - Microsoft – exigences matérielles Windows 10/11, sécurité basée sur la virtualisation.

#### Secure Boot activé

- **Domaine** : Plateforme  
- **Description** : Vérifie que l’amorçage UEFI sécurisé (Secure Boot) est actif.  
- **Vérification** : `Confirm-SecureBootUEFI`.  
- **Référentiels** :
  - ANSSI – démarrage sécurisé, intégrité de la chaîne de boot ;
  - Microsoft – recommandation Secure Boot pour Windows.

#### Démarrage mesuré (VBS/HVCI prêt ?)

- **Domaine** : Plateforme  
- **Description** : Vérifie la configuration Device Guard / VBS via `Win32_DeviceGuard` (SecurityServicesConfigured).  
- **Référentiels** :
  - ANSSI – VBS, Device Guard / Credential Guard ;
  - Microsoft – Virtualization-based Security, Memory Integrity (HVCI) ;
  - CIS – recommandations sur Device Guard / Credential Guard.

---

### 7.2 TLS / SSL

#### TLS 1.2 Client / Server activés

- **Domaine** : TLS/SSL  
- **Description** : Vérifie que TLS 1.2 est activé côté client et côté serveur dans SCHANNEL.  
- **Vérification** :  
  - `HKLM\...\SCHANNEL\Protocols\TLS 1.2\Client` `Enabled=1`  
  - `HKLM\...\SCHANNEL\Protocols\TLS 1.2\Server` `Enabled=1`  
- **Référentiels** :
  - ANSSI – recommandations TLS, version minimale ;
  - CIS – activation TLS 1.2 ;
  - Microsoft – durcissement SCHANNEL.

#### TLS 1.3 Client / Server activés (si support)

- **Domaine** : TLS/SSL  
- **Description** : Si présent dans le registre, vérifie que TLS 1.3 est activé.  
- **Vérification** : clés `TLS 1.3\Client` / `Server`, `Enabled=1` si presentes.  
- **Référentiels** :
  - ANSSI – recommandations récentes sur TLS ;
  - Microsoft – support TLS 1.3 ;
  - CIS – adoption des dernières versions TLS.

#### SSL 3.0 Client / Server désactivés

- **Domaine** : TLS/SSL  
- **Description** : Vérifie la désactivation de SSL 3.0 côté client et serveur.  
- **Vérification** : `Enabled=0` sous `Protocols\SSL 3.0\Client/Server`.  
- **Référentiels** :
  - ANSSI – interdiction SSL 3.0 ;
  - CIS – désactivation des protocoles obsolètes ;
  - Microsoft – mitigation POODLE, etc.

#### TLS 1.0 / 1.1 Client désactivés

- **Domaine** : TLS/SSL  
- **Description** : Désactivation des protocoles TLS 1.0 et 1.1 côté client.  
- **Vérification** : `TLS 1.0\Client` et `TLS 1.1\Client` `Enabled=0`.  
- **Référentiels** :
  - ANSSI – dépréciation TLS 1.0/1.1 ;
  - CIS – désactivation TLS 1.0/1.1 ;
  - Microsoft – deprecation roadmap TLS 1.0/1.1.

---

### 7.3 Réseau / SMB / Découverte

#### SMBv1 supprimé (feature)

- **Domaine** : Réseau/SMB  
- **Description** : Vérifie que la fonctionnalité SMB 1.0/CIFS est désactivée.  
- **Vérification** : `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` → `State = Disabled`.  
- **Référentiels** :
  - ANSSI – désactivation SMBv1 ;
  - CIS – suppression SMBv1 ;
  - Microsoft – recommandations post-WannaCry.

#### SMB signing requis (Client / Server)

- **Domaine** : Réseau/SMB  
- **Description** :
  - Client : `RequireSecuritySignature = $true`.  
  - Server : `RequireSecuritySignature = $true`.  
- **Vérification** : `Get-SmbClientConfiguration`, `Get-SmbServerConfiguration`.  
- **Référentiels** :
  - ANSSI – intégrité des flux SMB ;
  - CIS – SMB Signing ;
  - Microsoft – Windows Security Baselines.

#### Accès invité SMB interdit

- **Domaine** : Réseau/SMB  
- **Description** : Interdit les partages SMB accessibles en invité non authentifié.  
- **Vérification** : `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation` `AllowInsecureGuestAuth=0`.  
- **Référentiels** :
  - ANSSI – interdiction des partages invités ;
  - CIS – Guest access désactivé ;
  - Microsoft – durcissement SMB guest.

#### LLMNR désactivé

- **Domaine** : Réseau  
- **Description** : Désactivation de LLMNR (résolution de noms multicast) pour éviter les attaques de type poisoning.  
- **Vérification** : `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` `EnableMulticast=0`.  
- **Référentiels** :
  - ANSSI – réduction de surface d’attaque (LLMNR, NetBIOS) ;
  - CIS – désactivation LLMNR ;
  - Guides internes de durcissement réseau Windows.

#### WPAD AutoDetect désactivé

- **Domaine** : Réseau  
- **Description** : Désactive la découverte automatique de proxy (WPAD) côté WinHTTP.  
- **Vérification** : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` `DisableWpad=1`.  
- **Référentiels** :
  - ANSSI – risques liés à WPAD spoofing ;
  - CIS – durcissement Internet Settings ;
  - Microsoft – recommandations WPA

#### NetBIOS over TCP/IP désactivé

- **Domaine** : Réseau  
- **Description** : Vérifie que les interfaces NetBT ont `NetbiosOptions=2` (désactivé).  
- **Vérification** : clés sous `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`.  
- **Référentiels** :
  - ANSSI – désactivation de services hérités (NetBIOS) ;
  - CIS – réduction de surface réseau ;
  - Bonnes pratiques SMB/NetBIOS.

#### mDNS 5353 bloqué (inbound)

- **Domaine** : Réseau  
- **Description** : Vérifie la présence d’au moins une règle pare-feu bloquant ou contrôlant le port mDNS (UDP 5353) en entrée.  
- **Vérification** : `Get-NetFirewallRule` filtré sur `Direction=Inbound` et `DisplayName` contenant `mDNS` ou `5353`.  
- **Référentiels** :
  - ANSSI – maîtrise des services de découverte réseau ;
  - CIS – filtrage des ports non nécessaires ;
  - Bonnes pratiques sur mDNS/Bonjour.

---

### 7.4 Identité / Comptes locaux / RDP / LSA

#### NTLMv2 uniquement (LmCompatibilityLevel>=5)

- **Domaine** : Identité  
- **Description** : Impose NTLMv2 uniquement, désactivant LM et NTLMv1.  
- **Vérification** : `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `LmCompatibilityLevel >= 5`.  
- **Référentiels** :
  - ANSSI – interdiction LM/NTLMv1 ;
  - CIS – LmCompatibilityLevel ;
  - Microsoft – durcissement NTLM.

#### LSASS protégé (config RunAsPPL)

- **Domaine** : Identité  
- **Description** : Vérifie le mode protégé de LSASS (Protected Process Light).  
- **Vérification** :  
  - Build récent (Windows 11/Server 2022+) → `RunAsPPL` ∈ {1,2}  
  - Sinon → `RunAsPPL=1`  
- **Référentiels** :
  - ANSSI – protection des secrets en mémoire (Credential Guard / PPL) ;
  - Microsoft – LSA Protection ;
  - CIS – LSASS as a Protected Process.

#### RunAsPPLBoot=1 (early launch)

- **Domaine** : Identité  
- **Description** : Active le démarrage anticipé de LSASS en mode PPL.  
- **Vérification** : `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `RunAsPPLBoot=1`.  
- **Référentiels** :
  - Microsoft – renforcement LSASS ;
  - ANSSI – durcissement de l’authentification locale.

#### NoLMHash=1

- **Domaine** : Identité  
- **Description** : Empêche la conservation de hash LM dans SAM.  
- **Vérification** : `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `NoLMHash=1`.  
- **Référentiels** :
  - ANSSI – interdiction LM ;
  - CIS – Passwords Do Not Store LM Hash Value ;
  - Microsoft – Password storage hardening.

#### LAPS activé (password local admin)

- **Domaine** : Identité  
- **Description** : Vérifie la présence d’une configuration LAPS (Windows LAPS GPO, Windows LAPS Intune CSP ou LAPS Legacy) avec :
  - sauvegarde du mot de passe dans AD/AAD ;
  - rotation dans un délai raisonnable (<= 30 jours).  
- **Vérification** : clés de registre LAPS / journal LAPS.  
- **Référentiels** :
  - ANSSI – gestion des comptes locaux et mots de passe uniques ;
  - Microsoft – Windows LAPS (remplaçant LAPS classique) ;
  - CIS – LAPS ou équivalent.

#### Admin intégré désactivé

- **Domaine** : Comptes  
- **Description** : Vérifie que le compte Administrateur intégré (`RID 500`) est désactivé.  
- **Vérification** : `Get-LocalUser` SID `S-1-5-21-...-500` et `Enabled=$false`.  
- **Référentiels** :
  - ANSSI – réduction de l’usage du compte admin intégré ;
  - CIS – Disable Local Administrator Account ;
  - Microsoft – recommendations admin locale.

#### Invité désactivé

- **Domaine** : Comptes  
- **Description** : Vérifie que le compte Invité (`RID 501`) est désactivé.  
- **Vérification** : `Get-LocalUser` SID `S-1-5-21-...-501`.  
- **Référentiels** :
  - ANSSI – interdiction des comptes invités ;
  - CIS – Guest Account Status ;
  - Microsoft – Guest account disabled.

#### NLA exigée pour RDP

- **Domaine** : Accès distant  
- **Description** : Impos
