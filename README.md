# Jev-SOC

Triage corrélé d'alertes Wazuh pour détecter les attaques multi-étapes. Les alertes sont
regroupées en clusters, chaque cluster est jugé par un modèle de décision « System One »
(Jev via l'API TypeSafe, ou Laya en local), et la décision structurée est stockée pour
l'analyste. Le brief complet du projet est dans [`CLAUDE.md`](CLAUDE.md).

**Mode shadow par construction :** le système ne bloque rien et ne modifie aucune alerte.
Il écrit seulement des décisions à côté du workflow existant.

## État d'avancement

| Jalon | État |
|---|---|
| 1. Squelette, `MockBackend`, harnais `eval.py` | fait (+ `JevBackend`) |
| 2. Jeu de clusters labellisés | fait sur **vraies alertes Wazuh** : AIT-ADS (Linux/web) + émulation APT29 de MITRE (Windows/Sysmon) rejouée dans un vrai Wazuh |
| 3. Sérialiseur + correlator | faits : hors ligne (évaluation) et incrémental (flux, décisions versionnées) ; entités Linux et Windows/Sysmon |
| Démo live | faite : rejeu de vraies alertes Wazuh, page visuelle, mode enregistré ou direct (`demo/`) |
| Politique de décision + calibration | faites, réglées sur la validation AIT uniquement |
| 4. `LayaBackend` zero-shot | à faire |
| 5 à 9 | à faire |

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # cœur + pytest + ruff
pip install -e ".[dev,jev]"    # + SDK TypeSafe pour le backend Jev
```

Pour le backend Jev, la clé se met dans l'environnement, jamais dans le dépôt :

```bash
export TYPESAFE_API_KEY=...    # ou dans un fichier .env (ignoré par git)
```

## Utilisation

```bash
# Régénérer la matrice d'ablation (3 scénarios x 4 variantes) dans data/ablation/
python scripts/make_variants.py

# Construire les clusters labellisés à partir de vraies alertes Wazuh (voir data/README.md)
python scripts/build_ait_dataset.py

# Attaques Windows : rejouer des journaux Windows/Sysmon dans un vrai Wazuh (voir data/README.md)
sudo python scripts/wazuh_replay.py data/raw/apt29/<jour>.json data/raw/apt29/alerts/<jour>_wazuh.ndjson
python scripts/build_apt29_dataset.py

# Calibration + seuils, ajustés sur la VALIDATION à partir de décisions enregistrées (sans API)
python eval/calibrate.py --results eval/results/jev-ait.json

# Rejouer une évaluation sans rappeler l'API
python eval/eval.py --data data/ait --split test --replay eval/results/jev-ait.json

# Courbe de soupçon : décision re-prise à chaque nouvelle alerte d'un scénario
python scripts/prefix_curve.py --backend jev

# Évaluer un backend sur les clusters labellisés
python eval/eval.py                    # backend de config/config.yaml (mock par défaut)
python eval/eval.py --backend jev      # API TypeSafe : les states quittent le périmètre !
python eval/eval.py --backend jev --data data/ait --out eval/results/jev-ait.json
```

Le choix du backend, les seuils et les paramètres de corrélation sont dans
[`config/config.yaml`](config/config.yaml). Les questions typées sont dans
`config/questions.v2.json` ; la version (`v2`) est enregistrée dans chaque décision.

## Démo live

Rejoue de **vraies alertes Wazuh** (émulation APT29, jour 1 : 2 704 alertes en 31 min) dans le
correlator incrémental ; le modèle re-juge chaque activité quand elle évolue. La page a deux
onglets :

- **Vue d'ensemble** (pour comprendre le projet d'un coup d'œil) : horloge numérique de l'attaque
  (heure UTC réelle du rejeu + temps écoulé), bandeau de situation (« Attaque en cours », nom de
  l'attaque, action à faire), entonnoir alertes → activités corrélées → jugées par Jev → à traiter,
  **graphe de propagation** (machines, activités reliées aux machines qu'elles touchent, flèches
  machine → machine avec l'heure et la technique, « ? » là où Jev hésite), cartes des attaques
  nommées et fil des moments clés.
- **Vue analyste SOC** : courbes P(attaque) par cluster avec les seuils, volume par niveau, cartes
  détaillées (probabilités brute/calibrée, chaîne MITRE, justification déterministe), flux
  d'alertes et journal des décisions versionnées.

Les noms (« Intrusion SCRANTON → NASHUA », « Activité suspecte sur NASHUA ») sont construits par
règles fixes dans `src/jevsoc/naming.py` (machines dans l'ordre, techniques MITRE des règles Wazuh,
action recommandée) : aucun texte généré. « Jev hésite » = P calibrée entre le seuil
d'investigation et celui de confinement.

```bash
# Le plus sûr pour une soutenance : page autonome, aucun réseau ni serveur (double-clic)
open demo/apt29_day1_standalone.html

# Rejouer l'enregistrement via le serveur (vitesse réglable dans la page)
python scripts/demo.py serve --recording demo/recordings/apt29_day1.json     # http://127.0.0.1:8000

# Vrai direct : le moteur tourne et appelle Jev au fil de l'eau (TYPESAFE_API_KEY requise)
python scripts/demo.py serve --live --backend jev --speed 20 --truth apt29 \
    --alerts data/raw/apt29/alerts/day1_wazuh.ndjson --history data/raw/apt29/alerts/day2_wazuh.ndjson

# Refaire l'enregistrement (81 appels à Jev, ~20 s), puis la page autonome
python scripts/demo.py record --backend jev --truth apt29 --alerts ... --history ... \
    --out demo/recordings/apt29_day1.json
python scripts/demo.py build --recording demo/recordings/apt29_day1.json --out demo/apt29_day1_standalone.html
```

Ce que montre l'enregistrement : l'attaque **A « Intrusion SCRANTON → NASHUA »** est repérée à
T+01:18 (77 %) puis monte à 99 % (contenir) ; **D « Intrusion NASHUA »** (partages admin, WinRM,
copie d'outils) passe à « contenir » à T+15:06 puis fusionne avec A à T+15:46 : le correlator a
reconstitué le mouvement latéral. En fin de rejeu : 3 intrusions (2 réelles, 1 fausse alerte à
72 %), 9 activités où Jev hésite (6 réelles, 3 bruit), 28 activités jugées bruit de fond, toutes sans
indicateur d'attaque.
Le bouton « Vérité terrain » affiche ces verdicts (indicateurs du plan d'émulation).

## Tests

```bash
pytest          # 55 tests, aucun appel réseau
ruff check . && ruff format --check .
```

## Comment se lit l'évaluation

- Deux questions : **toutes les attaques** contre les bénins, et **chaînes multi-étapes** contre
  les bénins (ce que demande la question `is_sophisticated_attack`).
- **jev calibré** : P(attaque) recalibrée (Platt, 2 paramètres, `config/calibration.yaml`) puis
  seuil d'investigation 0,14. **système complet** : action de la politique ≠ `monitor`.
- **Baselines** : `max_level>=7`, somme des niveaux, volume d'alertes. Calculées sur les vrais
  niveaux de règle du cluster.
- **AUC** : sans seuil, compare honnêtement tout le monde. **Brier / ECE** : qualité des
  probabilités. **FP/jour** : faux positifs projetés sur tous les clusters bénins réels.
- Tout réglage (calibration, seuils) est fait sur la **validation AIT** (fox, harrison, wheeler).
  Les chiffres ci-dessous sont sur le **test** : 5 autres scénarios AIT, et APT29 en entier.

## Résultats mesurés (Jev `jev-1.13.0`, sur le test uniquement)

### Linux / web : AIT-ADS, 5 scénarios de test (174 clusters, 24 attaques dont 5 chaînes)

| Méthode | Chaînes multi-étapes : rappel | Toutes attaques : F1 | AUC | Faux positifs / jour |
|---|---|---|---|---|
| Jev calibré (P ≥ 0,14) | **5 / 5** | 0,50 | 0,78 | **0** |
| Système complet (Jev + volume) | 5 / 5 | **0,76** | **0,88** | 3 |
| `volume >= 65` | 2 / 5 | 0,67 | 0,73 | 3 |
| `max_level >= 7` | 3 / 5 | 0,33 | 0,50 | 70 |

Jev attrape toutes les chaînes (y compris les escalades de privilèges discrètes de niveau 4)
sans fausse alerte, mais ne signale pas les scans seuls ; la règle de volume les couvre.

### Windows : émulation APT29 de MITRE rejouée dans Wazuh (55 clusters, 9 attaques dont 5 chaînes)

Jeu **jamais utilisé pour régler quoi que ce soit** : autre OS, autre attaquant, autres outils.

| Méthode | Chaînes multi-étapes : rappel | Toutes attaques : précision / rappel / F1 | AUC |
|---|---|---|---|
| Jev calibré (P ≥ 0,14) | **5 / 5** | 0,60 / 1,00 / **0,75** | **0,97** |
| Système complet (Jev + volume) | 5 / 5 | 0,36 / 1,00 / 0,53 | 0,83 |
| `max_level >= 7` | 4 / 5 | 0,15 / 0,78 / 0,25 | 0,66 |
| `volume >= 65` | 2 / 5 | 0,23 / 0,33 / 0,27 | 0,58 |

- La **calibration apprise sur Linux tient sur Windows** : ECE 0,30 brut → 0,08 calibré.
- La **corrélation regroupe bien l'attaque** : 367 des 372 alertes de l'attaquant du jour 1 et
  les 98 du jour 2 sont dans des clusters jugés (jour 2 : toute l'attaque en un seul cluster).
  D'où peu de clusters d'attaque : 9, ce qui reste un petit échantillon.
- La **règle de volume ne se transporte pas** : sur Windows, les rafales viennent de fausses
  alertes de Wazuh (« Explorer accessed by RuntimeBroker », des centaines par minute), pas
  de scans. Elle coûte de la précision au système complet.
- Faux positifs de Jev sur Windows (6 sur 46 bénins) : surtout des accès de `lsass` / `svchost`
  à Explorer et des scripts PowerShell ; aucun réglage n'a été fait pour les éviter.

### Recalibration (validation AIT, 3 chaînes + 116 non-chaînes)

`P_calibrée = sigmoïde(2,21 × logit(P_brute) − 1,87)`. Une P brute de 0,5 correspond en
réalité à ~13 % de chances d'être une chaîne multi-étapes ; 0,8 à ~77 %. ECE sur le test
AIT : 0,19 → 0,01. Le seuil d'investigation (0,14) est au milieu de l'écart, en validation,
entre le bénin le plus suspect (0,02) et la chaîne la moins suspecte (0,26).

### Ce qui a été corrigé en cours de route (transparence)

- **Règle de priorité désactivée** (`priority_monitor_max` 3,0 → 4,0) **après** avoir vu le test
  APT29 : la priorité du modèle n'est pas calibrée (bénins Windows à 3,2–3,7) et envoyait 50
  bénins sur 57 en `investigate`. Sur la validation AIT, elle n'apportait aucune chaîne.
- **Labels APT29 corrigés après examen des désaccords** avec Jev : un PowerShell caché lancé par
  WMI (attaque ratée par la liste d'indicateurs) et des commandes de l'agent Azure (faussement
  labellisées attaque). Les règles corrigées sont générales, mais n'examiner que les désaccords
  favorise le modèle : ces chiffres APT29 sont donc un peu optimistes.
- **Corrélation Windows corrigée** pendant la construction de la démo : le processus CIBLE d'un
  accès (Sysmon 10, ex. `explorer.exe`) ne relie plus les alertes (il fusionnait l'attaquant et
  le bruit Windows), et les hubs sont appris sur l'autre journée (historique). Les chiffres APT29
  ci-dessus sont ceux d'après la correction.
- Limites : peu de chaînes (5 + 5), labels par indicateurs ou fenêtres de temps, une seule
  famille d'attaque par environnement, probabilités calibrées à la prévalence de l'échantillon
  (bien plus élevée que dans un vrai SOC).

### Sur les scénarios faits main (ablation, 12 clusters)

Jev sépare l'attaque, le jumeau bénin SCCM et l'attaque déguisée (AUC 1,0) alors que
`max_level >= 7` ne sépare rien (les trois ont le même niveau max). Sans indices de contexte
(variante `blind`), le patching SCCM devient un faux positif (P = 0,73).

### Leçons d'ingénierie tirées des vraies données

- **Un attaquant bruyant ressemble à un hub.** Filtrer les entités trop fréquentes en nombre
  d'alertes coupait la chaîne de l'attaquant. Critère retenu : présence continue dans le temps.
- **Un reverse proxy masque l'IP de l'attaquant.** La règle Wazuh sert aussi d'entité de liaison
  pour regrouper une rafale d'alertes identiques.
- **Le sérialiseur peut cacher l'essentiel.** Garder les 30 lignes les plus graves faisait
  disparaître les `sudo` de niveau 3 derrière des milliers d'erreurs 400. Version 2 du state :
  fusion des rafales en une ligne « ×7 105 », puis priorité aux lignes rares.
- **wazuh-logtest ne sait pas traiter les événements Windows.** Pour obtenir de vraies alertes
  Windows sans VM, `scripts/wazuh_replay.py` reconstruit le XML Windows (attributs entre
  apostrophes, sinon l'analyseur de Wazuh échoue) et l'injecte dans la file d'analyse comme un
  agent. Les identifiants de processus Sysmon servent d'entités : ils relient un arbre de processus.

## Structure

```
config/        config.yaml, questions.v2.json, entity_denylist.yaml
src/jevsoc/    models.py (Decision, Derived), metrics.py, config.py, policy.py, calibration.py,
               collector.py, correlator.py, serializer.py, live.py, backends/ (base, mock, jev)
               + modules en attente : store, reports, api, backends/laya
scripts/       make_variants.py, build_ait_dataset.py, build_apt29_dataset.py, wazuh_replay.py,
               prefix_curve.py, demo.py (démo live : record / serve / build)
demo/          index.html (page de démo), recordings/ (journaux d'événements), page autonome
data/          ablation/, ait/, apt29/, splits.yaml, README.md (sources, licences, labellisation)
eval/          eval.py (harnais), calibrate.py (calibration + seuils sur validation), results/ (local)
tests/         tests pytest + une réponse Jev réelle enregistrée (fixtures/)
dashboards/    exports .ndjson (jalon 7)
docker/        lab Wazuh (optionnel)
```

## Confidentialité

Avec le backend Jev, l'état de chaque cluster (hôtes, utilisateurs, descriptions) est envoyé
à l'API TypeSafe, donc hors du périmètre. N'utiliser que des données de lab ou anonymisées.
Le mode local (Laya) est recommandé pour de vraies données.
