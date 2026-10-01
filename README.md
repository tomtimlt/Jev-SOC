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
| 2. Jeu de clusters labellisés | fait autrement : 293 clusters issus de **vraies alertes Wazuh** (AIT-ADS) + 12 scénarios faits main |
| 3. Sérialiseur + correlator | version hors ligne faite ; version incrémentale (démo live) à faire |
| Politique de décision (`policy.py`) | faite, seuils calibrés sur la validation AIT |
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

## Tests

```bash
pytest          # 36 tests, aucun appel réseau
ruff check . && ruff format --check .
```

## Comment se lit l'évaluation

- **P(attaque)** = réponse `is_sophisticated_attack` du modèle, seuil 0,5.
- **Baselines à battre :** `max_level>=7` (au moins une alerte de niveau 7) et
  `sum_levels` (somme des niveaux). Elles utilisent les vrais niveaux de règle du cluster,
  même dans la variante `no_level` où on les cache au modèle.
- **AUC :** probabilité qu'une attaque ait un score plus haut qu'un bénin. Elle ne dépend
  d'aucun seuil, donc compare honnêtement modèle et baselines.
- **Brier / ECE :** qualité des probabilités (calibration). Seulement pour le modèle.
- Moins de 20 clusters : le script le signale, les chiffres sont indicatifs.

## Résultats mesurés

### Sur vraies alertes Wazuh (AIT-ADS, Jev `jev-1.13.0`)

293 clusters : 53 attaques (8 chaînes multi-étapes avec reverse shell / escalade de
privilèges, 45 scans seuls) et 240 bénins tirés au hasard parmi 14 940 réels.

**Le cas qui justifie le projet : les chaînes multi-étapes.**

| Méthode | Chaînes multi-étapes trouvées | Scans seuls trouvés | Faux positifs / jour estimés |
|---|---|---|---|
| Jev, P ≥ 0,5 | **7 / 8** | 6 / 45 | **0** |
| `max_level >= 7` | 4 / 8 | 18 / 45 | 58 |
| `alert_count >= 100` | 3 / 8 | 30 / 45 | 0 |

- Toutes les chaînes multi-étapes ont une P(attaque) (0,48 à 0,82) plus haute que tous les
  bénins échantillonnés (max 0,33).
- Les 3 chaînes **discrètes** (niveau max 4 : `su` vers un compte, `sudo` root depuis le dossier
  d'upload WordPress) sont toutes vues par Jev et toutes ratées par `max_level >= 7`.
- Jev ne signale pas les **scans seuls** : la question posée (« intrusion multi-étapes
  coordonnée ? ») n'y répond pas oui, à raison. Une règle bête sur le volume d'alertes les
  attrape mieux : les deux sont **complémentaires**.

**Comparaison équitable sur toutes les attaques** (seuil de chaque méthode choisi sur les
scénarios de validation, mesuré sur les 5 scénarios de test) : Jev F1 0,68 et AUC 0,78,
contre F1 0,68–0,70 et AUC 0,73 pour les baselines de volume. Sur cette tâche mixte, Jev ne
fait pas mieux qu'une règle de volume : son apport est sur les chaînes, pas sur les scans.

**Politique** (`priority_monitor_max` recalibré à 3,0 sur la validation) : 239 bénins sur 240
en `monitor`, les 5 chaînes multi-étapes les plus nettes en `contain`.

Limites honnêtes : 8 chaînes multi-étapes seulement, issues du même plan d'attaque rejoué
dans 8 environnements ; labels par fenêtres de temps ; environnement Linux/web. Les
probabilités de Jev sont mal calibrées (une P de 0,5 correspond en réalité à une attaque
quasi certaine) : il faut un seuil ou une recalibration choisis sur la validation.

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

## Structure

```
config/        config.yaml, questions.v2.json, entity_denylist.yaml
src/jevsoc/    models.py (Decision, Derived), metrics.py, config.py, policy.py,
               collector.py, correlator.py, serializer.py, backends/ (base, mock, jev)
               + modules en attente : store, reports, api, backends/laya
scripts/       make_variants.py (ablation), build_ait_dataset.py (vraies alertes), prefix_curve.py
data/          ablation/, ait/, splits.yaml, README.md (sources, licence, labellisation)
eval/          eval.py (harnais), results/ (sorties locales, ignorées par git)
tests/         tests pytest + une réponse Jev réelle enregistrée (fixtures/)
dashboards/    exports .ndjson (jalon 7)
docker/        lab Wazuh (optionnel)
```

## Confidentialité

Avec le backend Jev, l'état de chaque cluster (hôtes, utilisateurs, descriptions) est envoyé
à l'API TypeSafe, donc hors du périmètre. N'utiliser que des données de lab ou anonymisées.
Le mode local (Laya) est recommandé pour de vraies données.
