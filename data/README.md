# Données

| Dossier | Contenu | Origine |
|---|---|---|
| `ablation/` | 3 scénarios × 4 variantes (attaque, jumeau bénin SCCM, attaque déguisée) | écrits à la main, `scripts/make_variants.py` |
| `ait/` | 53 clusters d'attaque + 240 clusters bénins échantillonnés, issus de vraies alertes Wazuh | AIT-ADS, `scripts/build_ait_dataset.py` |
| `apt29/` | 24 clusters d'attaque (11 multi-étapes) + 57 bénins, alertes Wazuh Windows/Sysmon | émulation APT29 (OTRF) rejouée dans Wazuh, `scripts/build_apt29_dataset.py` |
| `raw/` | jeux bruts téléchargés (ignoré par git, 2,8 Go) | voir ci-dessous |
| `splits.yaml` | split train / validation / test, fixé **par scénario** | – |

## AIT Alert Data Set (AIT-ADS)

Landauer, M., Skopik, F., Wurzenberger, M. (2024). *Introducing a New Alert Data Set for
Multi-Step Attack Analysis.* CSET 2024. Données : <https://zenodo.org/record/8263181>,
licence **CC-BY 4.0**. Les fichiers de `ait/` sont des dérivés (clusters résumés) de ce jeu.

8 scénarios (fox, harrison, russellmitchell, santos, shaw, wardbeck, wheeler, wilson),
4 à 6 jours chacun, 2,6 millions d'alertes Wazuh + Suricata. Chaque scénario contient la même
attaque multi-étapes avec des variations : scans (nmap, dirb, wpscan), webshell, cassage de
mots de passe, reverse shell, escalade de privilèges, arrêt de service, exfiltration DNS.
Environnement Linux / web : pas de Windows ni de Sysmon.

### Régénérer `ait/`

```bash
mkdir -p data/raw/ait_ads && cd data/raw/ait_ads
curl -L -o ait_ads.zip https://zenodo.org/api/records/8263181/files/ait_ads.zip/content
curl -L -o labels.csv  https://zenodo.org/api/records/8263181/files/labels.csv/content
unzip ait_ads.zip && rm ait_ads.zip && cd ../../..
python scripts/build_ait_dataset.py     # ~1 min, écrit data/ait/ et data/ait/summary.json
```

### Comment les clusters sont labellisés (et les limites)

- Le jeu ne fournit que des **fenêtres de temps** par phase d'attaque (`labels.csv`).
- Une alerte est « attaque » si elle tombe dans une fenêtre **et** que sa règle n'est pas du
  bruit de fond (règle vue hors attaque dans au moins 3 heures différentes : ClamAV, Dovecot…).
- Un cluster est « attaque » s'il contient au moins une alerte d'attaque. Son étape
  (`kill_chain_stage`) est la plus avancée de ses alertes.
- Limites : labellisation approximative (une alerte légitime dans une fenêtre d'attaque peut
  être comptée) ; les 8 scénarios rejouent le même plan d'attaque, donc ils ne sont pas
  indépendants ; seul un échantillon de 30 clusters bénins par scénario est jugé, les totaux
  réels (`summary.json`) servent à estimer le volume de faux positifs par jour.

## Émulation APT29 (Windows / Sysmon), rejouée dans un vrai Wazuh

Source : OTRF Security-Datasets, `datasets/compound/apt29` (journaux Windows, Sysmon et
PowerShell enregistrés pendant la reproduction de l'évaluation ATT&CK APT29 de MITRE, jour 1
et jour 2, 4 machines du domaine `dmevals.local`). Plan d'émulation public :
<https://github.com/mitre-attack/attack-arsenal/tree/master/adversary_emulation/APT29>.

### Régénérer `apt29/`

```bash
# 1. Wazuh manager de LAB (paquet officiel), démarré
sudo apt-get install wazuh-manager && sudo /var/ossec/bin/wazuh-control start
# 2. Journaux bruts
mkdir -p data/raw/apt29/alerts && cd data/raw/apt29
for d in day1 day2; do
  curl -L -o $d.zip https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/$d/apt29_evals_${d}_manual.zip
  unzip $d.zip && rm $d.zip
done
cd ../../..
# 3. Rejeu dans le moteur de règles Wazuh (~1 min par jour), puis clusters labellisés
sudo python scripts/wazuh_replay.py data/raw/apt29/apt29_evals_day1_manual_*.json data/raw/apt29/alerts/day1_wazuh.ndjson
sudo python scripts/wazuh_replay.py data/raw/apt29/apt29_evals_day2_manual_*.json data/raw/apt29/alerts/day2_wazuh.ndjson
python scripts/build_apt29_dataset.py
```

Jour 1 : 196 081 événements → 2 704 alertes Wazuh. Jour 2 : 587 286 événements → 6 752
alertes (Wazuh 4.14.8, règles officielles, aucune règle ajoutée).

### Labellisation et limites

- Pas de label par événement dans le jeu. Les alertes de l'attaquant sont repérées par une liste
  d'**indicateurs** tirés du plan d'émulation (charges `3aka3.scr`, contournement UAC `sdclt`,
  `sdelete`, PsExec / WinRM / `python.exe` pour le mouvement latéral, `m.exe` et `VaultCli` pour
  les identifiants, persistance WMI / `javamtsup` / `hostui`…), chacun rattaché à une étape.
  Des artefacts bénins connus sont exclus d'abord (`__PSScriptPolicyTest`, accès à Explorer par
  des processus système, agents Azure). Liste complète : `scripts/build_apt29_dataset.py`.
- Cluster « attack » = au moins une alerte indicatrice ; « multi-étapes » = au moins 2 étapes.
- Deux règles ont été corrigées après examen des désaccords avec Jev (voir README) : les
  résultats APT29 sont donc légèrement optimistes.
- Enregistrements courts (~35 min) et denses : pas d'estimation de faux positifs par jour.
- Tout APT29 est en **test** : aucun seuil n'y est réglé.
