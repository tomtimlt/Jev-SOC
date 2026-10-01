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
| 2. Jeu de 20 clusters labellisés | à faire (aujourd'hui : 3 scénarios × 4 variantes) |
| 3. Sérialiseur + correlator | à faire (modules en attente dans `src/jevsoc/`) |
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

# Évaluer un backend sur les clusters labellisés
python eval/eval.py                    # backend de config/config.yaml (mock par défaut)
python eval/eval.py --backend jev      # API TypeSafe : les states quittent le périmètre !
python eval/eval.py --backend jev --split test --out eval/results/jev.json
```

Le choix du backend, les seuils et les paramètres de corrélation sont dans
[`config/config.yaml`](config/config.yaml). Les questions typées sont dans
`config/questions.v2.json` ; la version (`v2`) est enregistrée dans chaque décision.

## Tests

```bash
pytest          # 18 tests, aucun appel réseau
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

## Premiers résultats mesurés (jalon 1, Jev `jev-1.13.0`, 12 clusters)

| Méthode | Précision | Rappel | F1 | AUC | Brier | ECE |
|---|---|---|---|---|---|---|
| Jev | 0,89 | 1,00 | 0,94 | 1,00 | 0,05 | 0,12 |
| `max_level>=7` | 0,67 | 1,00 | 0,80 | 0,50 | – | – |
| `sum_levels>=30` | 0,67 | 1,00 | 0,80 | 0,25 | – | – |

Lecture honnête :
- Les trois scénarios ont tous `max_level = 7` : la baseline ne sépare rien (AUC 0,5),
  alors que Jev classe toutes les attaques au-dessus de tous les bénins.
- La seule erreur est `benign-blind` (P = 0,73, P3,5) : sans indices de contexte, le patching
  SCCM ressemble à une attaque. Le sérialiseur devra fournir ce contexte (allowlist d'hôtes
  d'admin, inventaire des comptes de stockage, binaire signé).
- L'attaque déguisée (`adversarial`) reste détectée même en `blind` (0,95).
- **12 clusters issus de 3 scénarios ne prouvent rien sur la calibration** : les variantes
  d'un même scénario ne sont pas indépendantes. Le jeu de 20 clusters du jalon 2 est
  nécessaire avant toute conclusion.

## Structure

```
config/        config.yaml, questions.v2.json, entity_denylist.yaml
src/jevsoc/    models.py (Decision), metrics.py, config.py, backends/ (base, mock, jev)
               + modules en attente : collector, correlator, serializer, policy, store, reports, api
scripts/       make_variants.py (matrice d'ablation)
data/          ablation/ (12 clusters labellisés), splits.yaml (split fixé par scénario)
eval/          eval.py (harnais), results/ (sorties locales, ignorées par git)
tests/         tests pytest + une réponse Jev réelle enregistrée (fixtures/)
dashboards/    exports .ndjson (jalon 7)
docker/        lab Wazuh (optionnel)
```

## Confidentialité

Avec le backend Jev, l'état de chaque cluster (hôtes, utilisateurs, descriptions) est envoyé
à l'API TypeSafe, donc hors du périmètre. N'utiliser que des données de lab ou anonymisées.
Le mode local (Laya) est recommandé pour de vraies données.
