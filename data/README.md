# Données

| Dossier | Contenu | Origine |
|---|---|---|
| `ablation/` | 3 scénarios × 4 variantes (attaque, jumeau bénin SCCM, attaque déguisée) | écrits à la main, `scripts/make_variants.py` |
| `ait/` | 53 clusters d'attaque + 240 clusters bénins échantillonnés, issus de vraies alertes Wazuh | AIT-ADS, `scripts/build_ait_dataset.py` |
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
