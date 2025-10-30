# Windows Compliance Report v4 — Documentation (Markdown)

## 🎯 Objectif

Générer un **rapport HTML** clair et moderne sur la conformité sécurité Windows (55 contrôles pondérés), avec :

- Couleurs de lignes fiables par **criticité** (Critique, Élevée, Moyenne, Faible)  
- **Tri** par clic sur les entêtes + **filtres** (domaine/criticité/statut) + **recherche plein-texte**  
- **Mode sombre/clair** persistant (localStorage)  
- Barres de progression (contrôles conformes / score pondéré)  
- Calcul du **domaine le plus en défaut** et des **criticités KO** visibles selon filtres  
- Exports **HTML** (local + partagé) et **CSV** journalier consolidé (avec **écriture atomique** et **file d’attente pending** en cas de verrouillage fichier)

---

## 🧩 Paramètres du script

```powershell
[CmdletBinding()]
param(
  [string]$OutFile = (Join-Path $env:TEMP 'WindowsComplianceReport.html'),
  [string]$SharedCsvFolder,   # dossier UNC, ex: \\SRV-FICHIERS\SecOps\Compliance
  [string]$LogFolder = 'C:\Windows\Audit\logs'
)
```

| Paramètre           | Type    | Valeur par défaut                                  | Description détaillée | Exemples |
|---                  |---      |---                                                 |---                    |---|
| `OutFile`           | string  | `%TEMP%\WindowsComplianceReport.html`              | Chemin du **rapport HTML local** à générer. Les **variables d’environnement** sont supportées et les **guillemets** superflus sont retirés (fonction `Unquote`). Le répertoire cible est créé si nécessaire. | `-OutFile 'C:\Audit\report.html'`  •  `-OutFile '%USERPROFILE%\Desktop\WinReport.html'` |
| `SharedCsvFolder`   | string  | *(vide)*                                           | Dossier **partagé** (UNC recommandé) pour les **exports collaboratifs** : <br>• `yyyyMMdd_ComplianteReport_<HOST>.html` (copie du rapport du jour) <br>• `yyyyMMdd_ComplianceReport.csv` (tableau consolidé « dernier état par hôte »). <br>Le chemin est **validé et créé** (`Resolve-SharedFolder`). <br>Si l’écriture directe du CSV échoue (fichier verrouillé, FSRM/AV…), une **ligne `.row`** est déposée dans `pending\` (sur le partage, puis **fallback local** `C:\ProgramData\Audit\pending`) pour **absorption ultérieure**. | `-SharedCsvFolder '\\\\FILESRV01\\SecOps\\Compliance'`  •  `-SharedCsvFolder 'D:\\Shares\\Compliance'` |
| `LogFolder`         | string  | `C:\Windows\Audit\logs`                            | Dossier des **transcripts PowerShell**. Le script lance `Start-Transcript` au début et `Stop-Transcript` en `finally`, même en cas d’erreur, pour garder une **traçabilité complète**. | `-LogFolder 'C:\Logs\SecOps'` |

> 💡 **Entrées acceptent les variables d’environnement** et la fonction `Unquote` retire les guillemets/espaces parasites en début/fin.

---

## 🗂️ Fichiers produits & conventions

- **HTML local** : `OutFile` (ex. `C:\...\WindowsComplianceReport.html`)  
- **HTML partagé (optionnel)** : `\\partage\...\yyyyMMdd_ComplianteReport_<HOST>.html`  
- **CSV journalier consolidé (optionnel)** : `\\partage\...\yyyyMMdd_ComplianceReport.csv`  
  - **En-tête fixe** : `Host;ScorePercent;Passed;Total;CombinedCell;User;TimeISO`  
  - **Déduplication par hôte** : conserve **la ligne la plus récente** (colonne `TimeISO`).  
  - **Écriture atomique** : écriture d’abord dans un `.new.<GUID>`, puis **Replace** (swap).  
  - **Fallback pending** : si écritures impossibles, dépôt d’une ligne unique `*.row` dans `pending\` (sur partage et/ou `C:\ProgramData\Audit\pending`) → absorbée au prochain passage.

---

## 🖥️ Interface du rapport HTML

- **En-tête sticky** avec titre, date, **score pondéré**, compteur conformités, bouton **mode sombre/clair**.  
- **Tuiles** KPI : conformités, score, domaine le plus KO, criticités KO (réactifs aux filtres).  
- **Tableau** avec colonnes : *Domaine · Mesure · Criticité · Poids · Statut · Détails · Vérification (comment)*  
- **Tri** : clic sur en-tête (2ᵉ clic inverse le sens).  
- **Filtres** : domaine / criticité / statut (*Conforme*, *Non conforme*), + **recherche plein-texte**.  
- **Couleurs fiables** : le **fond de ligne** et un **liseré gauche** reprennent la **criticité**.  
- **Mode sombre/clair** : persistant via `localStorage`.  
- **Plein écran** : utilisez le **plein écran navigateur** (ex. `F11`) si souhaité.

---

## 📊 Score & logique des contrôles

- **55 contrôles** répartis par domaines (Chiffrement, Plateforme, TLS/SSL, Réseau/SMB, Identité/RDP/LSA, Protection/Exploit, PowerShell/Logs, Office/Edge, Périphériques, Hygiène/Logs/WU).  
- Chaque contrôle a une **criticité** (visuelle) et un **poids** (1–5) qui **compte dans le score**.  
- **Score pondéré (%)** = somme des **poids conformes** / somme de **tous les poids** × 100.  
- La colonne **Statut** affiche un badge *Conforme* / *Non conforme*.  
- La colonne **Détails** donne la valeur brute/erreur (utile pour le diagnostic rapide).  
- La colonne **Vérification (comment)** rappelle **comment la mesure est testée** (commande/registre).

---

## 🔎 Détails spécifiques (exemples notables)

- **BitLocker/TPM/Secure Boot** : nécessite souvent exécution **élevée** (Admin) et matériels compatibles.  
- **Exploit Protection** (`Get-ProcessMitigation`) : agrège DEP/CFG/ASLR/SEHOP etc.  
- **LAPS** : supporte **Windows LAPS** (GPO & CSP Intune) **et** **LAPS Legacy (AdmPwd)**.  
- **WU dernière installation ≤ 14 jours** :  
  1) Tente une **analyse rapide du WindowsUpdate.log** (généré à la volée) en **ignorant Defender** par défaut.  
  2) **Secours** via **COM** `Microsoft.Update.Session` (indépendant du journal).  
  > Pour valider manuellement :  
  > ```powershell
  > # Journal brut
  > $tmp = "$env:TEMP\WindowsUpdate_$env:COMPUTERNAME.log"
  > Get-WindowsUpdateLog -LogPath $tmp
  > Select-String -Path $tmp -Pattern 'Installation\s+(Successful|Success|réussie)'
  >
  > # Fallback COM (ne dépend pas des logs)
  > $s = New-Object -ComObject 'Microsoft.Update.Session'
  > $h = $s.CreateUpdateSearcher().QueryHistory(0,2000) |
  >      Where-Object { $_.Operation -eq 1 -and $_.ResultCode -in 2,3 } |
  >      Sort-Object Date -Descending | Select-Object -First 5
  > $h | Select Date, Title, ResultCode
  > ```

---

## 🛠️ Fonctions internes & paramètres (référence)

### `New-Check`
Crée un objet contrôle.

| Paramètre | Type | Notes |
|---|---|---|
| `Name` | string | Nom lisible de la mesure |
| `Domain` | string | Domaine logique (affiché et filtrable) |
| `Criticity` | enum | `Critique` / `Élevée` / `Moyenne` / `Faible` |
| `Weight` | int (1–5) | Poids utilisé dans le **score** |
| `Test` | scriptblock | Retourne **bool** (ou string débutant par `OK`), exceptions → **KO** |
| `How` | string | Mémo de vérification (affiché dans le HTML) |

### `Invoke-Check`
Exécute un contrôle et renvoie : `Name,Domain,Criticity,Weight,How,Passed,Details`.

### `Convert-ToCsvSemicolonLine`
Construit une **ligne CSV** (séparateur `;`).

| Paramètre | Type | Description |
|---|---|---|
| `HostName` | string | Nom d’hôte |
| `ScorePercent` | double | Score global (%) |
| `Passed` | int | Nb de contrôles conformes |
| `Total` | int | Nb total de contrôles |
| `CombinedCell` | string | Concat court (ex.: `HOST - 87.5%`) |
| `User` | string | `Domaine\Utilisateur` |
| `Time` | datetime | ISO court (`yyyy-MM-ddTHH:mm:ss`) |

### `Resolve-SharedFolder`
- Valide un chemin **local** (`C:\...`) ou **UNC** (`\\serveur\partage`).  
- **Crée** le dossier s’il n’existe pas, sinon lève une erreur (placeholders `< >` interdits).

### `Update-DailyCsvSafely`
Met à jour **de façon robuste** le CSV du jour (consolidé par hôte).

| Paramètre | Type | Description |
|---|---|---|
| `CsvPath` | string | Chemin du CSV du jour (`yyyyMMdd_ComplianceReport.csv`) |
| `NewLine` | string | Nouvelle ligne **formatée** (via `Convert-ToCsvSemicolonLine`) |
| `Header` | string | En-tête attendu (doit être `Host;ScorePercent;Passed;Total;CombinedCell;User;TimeISO`) |
| `SharedFolder` | string | Racine du partage (crée/maintient `pending\`) |

**Comportement clé** :  
- Lecture avec **partage ReadWrite** (*évite les locks*), strip du **BOM** si présent.  
- **Agrégation mémoire** par **hôte** → **conserve la plus récente** (`TimeISO`).  
- Écriture **UTF-8 sans BOM** dans un `*.new.<GUID>` → `File.Replace()` (swap atomique).  
- Si échec → **dépose `*.row`** dans `pending\` (partage → fallback local) + warning.

---

## ▶️ Exemples d’exécution

### 1) Rapport local simple (défaut)
```powershell
.\WindowsCompliance.ps1
```

### 2) Rapport local vers un chemin dédié
```powershell
.\WindowsCompliance.ps1 -OutFile 'C:\Audit\WindowsCompliance\report.html'
```

### 3) Exports collaboratifs (UNC + CSV consolidé)
```powershell
.\WindowsCompliance.ps1 -SharedCsvFolder '\\\\FILESRV01\\SecOps\\Compliance'
```

### 4) Dossier de logs personnalisé
```powershell
.\WindowsCompliance.ps1 -LogFolder 'D:\Logs\Compliance'
```

---

## ⏰ Planification (exemple tâche planifiée, gMSA recommandé)

> **Pré-requis** : le compte (ou **gMSA**) doit avoir lecture registre/WMI/BitLocker/Defender, écriture `SharedCsvFolder`, etc.

```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\WindowsCompliance.ps1" -SharedCsvFolder "\\\\FILESRV01\\SecOps\\Compliance"'
$trigger = New-ScheduledTaskTrigger -Daily -At 09:00
$principal = New-ScheduledTaskPrincipal -UserId 'DOMAIN\gmsa-Compliance$' -LogonType Password -RunLevel Highest
Register-ScheduledTask -TaskName 'Windows Compliance Daily' -Action $action -Trigger $trigger -Principal $principal -Description 'Rapport conformité Windows quotidien'
```

*(Adaptez le `LogonType` à votre méthode d’exécution des gMSA / service accounts.)*

---

## 🔐 Prérequis & droits

- **PowerShell 5.1+** (ok sur Windows 10/11/Server).  
- Exécution **élevée** recommandée (plusieurs mesures exigent des droits admin).  
- Modules/cmdlets Windows natifs (BitLocker, Defender, Smb, NetFirewall…).  
- **COM** `Microsoft.Update.Session` disponible (WU check secours).  
- Accès **écriture** sur `SharedCsvFolder` si renseigné.

---

## 🧯 Dépannage

- **Le CSV est souvent verrouillé** ➜ c’est géré : écriture atomique + `.row` **pending**.  
- **FSRM / Antivirus bloquent** ➜ autoriser l’extension `.new.*` et le dossier `pending\`.  
- **Couleurs/arrondis** sous certains Outlook/IE legacy ➜ ouvrir le **HTML dans un navigateur moderne**.  
- **Mesure WU** ne trouve rien ➜ valider via la section *WU* ci-dessus (journaux ou COM).

---

## 📌 Sorties console typiques

- `Transcript démarré : C:\Windows\Audit\logs\WindowsCompliance_<HOST>_<yyyyMMdd_HHmmss>.log`  
- `Rapport généré : C:\...\WindowsComplianceReport.html`  
- `HTML partagé : \\FILESRV01\SecOps\Compliance\20251030_ComplianteReport_<HOST>.html`  
- `CSV OK : \\FILESRV01\SecOps\Compliance\20251030_ComplianceReport.csv | hosts=12 | bytes=...`  
- Ou, en cas de fallback : `Swap atomique KO. Ligne déposée dans '\\FILESRV01\SecOps\Compliance\pending\...row'.`

---

## ✅ Résumé

- **Utilisez** `-SharedCsvFolder` pour centraliser l’état des postes par jour (CSV + HTML copie).  
- **Ouvrez** le rapport HTML dans un navigateur moderne pour profiter du **tri/filtres/mode sombre**.  
- **Vérifiez** les logs dans `LogFolder` pour l’audit et le diagnostic.  

Besoin d’une version *light* (moins de contrôles), d’un export JSON, ou d’un bouton *plein écran* dans l’UI ? Dis-le et je te fournis une variante prête à l’emploi.
