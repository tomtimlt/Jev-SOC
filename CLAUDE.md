# Jev-SOC : triage corrélé d'alertes SIEM pour attaques multi-étapes

> Brief de projet pour Claude Code. Lis tout ce fichier avant d'écrire du code.
> Langue : explications et commentaires en français, noms de code (variables, fonctions, clés JSON) en anglais.

## 1. Contexte et objectif

Un SIEM génère beaucoup d'alertes unitaires. Une attaque avancée (APT, living-off-the-land, multi-étapes) produit souvent des alertes isolées de gravité faible à moyenne, qui passent sous le radar. Seule la **corrélation temporelle et contextuelle** révèle la menace.

**Objectif :** un module qui (1) récupère les alertes Wazuh, (2) les regroupe en **clusters** (fenêtre temporelle + entités communes), (3) envoie chaque cluster à un modèle de décision « System One » (Jev ou Laya), (4) stocke une décision structurée (sophistication, étape de kill chain, priorité, action recommandée, probabilités), (5) l'affiche dans Wazuh et génère des rapports.

**Contexte humain :** projet d'un étudiant ingénieur en cybersécurité (CESI Nancy), profil ops/infra/sécurité, peu porté sur le développement. Conséquences pour toi :
- Code **simple, lisible, commenté**, peu de dépendances, pas de sur-ingénierie.
- Le projet doit rester réaliste pour un étudiant (pas un produit enterprise).
- Quand tu fais un choix d'architecture, explique-le en 2 ou 3 phrases.
- Propose toujours une façon de **tester** ce que tu viens d'écrire.

## 2. Comprendre les modèles de décision (important)

Jev et Laya sont des **classifieurs, pas des générateurs**. Ils prennent un `state` (texte ou JSON) et des **questions typées**, et renvoient des réponses typées avec des probabilités, en une seule passe, sans génération de texte.

Trois primitives :

| Type | Réponse | Usage |
|---|---|---|
| `noul` | probabilité P(vrai) entre 0 et 1 | questions oui/non |
| `choice` | un label + probabilité par option + confiance | catégorie, un seul choix |
| `score` | valeur attendue sur une échelle ordonnée (2 à 10 niveaux), fractionnaire | priorité, gravité |

Conséquences à respecter :
1. **Pas de justification en prose.** La justification affichée à l'analyste est construite **de façon déterministe** à partir des features du cluster et des probabilités, par exemple : « 8 alertes, 2 hôtes, 214 min ; T1566.001 → T1059.001 → T1003.001 → T1021.002 ; P(sophistiqué)=0,97 ».
2. **`confidence_overall` n'est pas une question.** On le dérive des probabilités (probabilité max, marge ou entropie).
3. **Les techniques MITRE ne passent pas par le modèle.** Elles viennent de `rule.mitre.id` dans les alertes Wazuh, mappées de façon déterministe.
4. **Les questions sont indépendantes.** Rien ne garantit la cohérence entre les réponses. Le backend doit contrôler la cohérence (ex. `furthest_stage` = exfiltration alors que `unauthorized_exfiltration` est bas) et marquer le cluster « incohérent » au lieu de faire confiance aveuglément.
5. **Piloter la décision par seuils sur `noul` et `score`, pas par l'argmax d'un `choice`.** Deux actions non exclusives (contain, escalate) ne vont pas dans un même `choice`.

### Backends supportés (interface commune obligatoire)

Écris une interface `DecisionBackend` avec une méthode `decide(state: dict) -> Decision`, et trois implémentations interchangeables :

- **`LayaBackend` (priorité, local)** : `pip install laya`, `agent = laya.load("convaiinnovations/laya")`, `agent.predict(state, questions)`. Apache 2.0, une passe d'environ 33 à 38 ms sur GPU. **Vérifie le schéma exact des questions dans la doc de la version installée** avant de coder. Le modèle de base Laya est un point de départ à spécialiser (fine-tuning), pas un moteur zero-shot fiable : ses probabilités sont à valider et recalibrer sur nos données.
- **`JevBackend` (API TypeSafe)** : `POST https://api.typesafe.ai/v1/systemone`, SDK Python `typesafe_sdk` (`pip install typesafe-sdk`), modèle `jev-latest`. Les données quittent le périmètre : à documenter comme argument pour le mode local.
- **`MockBackend`** : réponses déterministes pour les tests unitaires et le dev hors ligne (aucun appel réseau).

Le choix du backend se fait par configuration (`config.yaml`), jamais en dur.

## 3. Architecture

```
Wazuh Indexer (wazuh-alerts-*)
        │  requêtes OpenSearch (fenêtre glissante)
        ▼
Collector ──► Correlator (union-find) ──► Cluster Builder ──► Serializer (state compact)
                                                                     │
                                                                     ▼
                                                        DecisionBackend (Laya / Jev / Mock)
                                                                     │
                                                                     ▼
                                              Decision Store (index jev-decisions-*)
                                                   │                       │
                                                   ▼                       ▼
                                     Dashboards natifs Wazuh        Reports (JSON + PDF)
```

### Choix d'architecture déjà tranchés

- **Ingestion :** requête directe sur l'indexeur (`wazuh-alerts-*`) avec le client Python OpenSearch. Pas d'intégration `ossec.conf` custom. Un mode fichier (JSON/NDJSON) sert aux tests et au jeu de données.
- **Stockage :** index `jev-decisions-*` dans OpenSearch avec un mapping explicite (voir section 7).
- **Interface :** **dashboards natifs** (saved searches, visualisations, dashboard) dans l'interface Wazuh. **Pas de plugin React au départ** : un plugin doit être compilé contre la version exacte du Wazuh Dashboard et casse à chaque mise à jour. Le plugin est un stretch goal, à ne démarrer que si tout le reste est fini.
- **Mode shadow :** le système ne bloque jamais le workflow existant, il écrit seulement des décisions. C'est « shadow » par construction : à documenter comme tel.
- **Rapports PDF :** Jinja2 → HTML → WeasyPrint, dans le backend.
- **API :** FastAPI (simple, typage Pydantic, doc auto).

## 4. Corrélation (le cœur technique)

Regrouper les alertes dans une fenêtre temporelle configurable (30 min, 1 h, 4 h) selon des **entités communes** : `agent.id`, `data.win.eventdata.user`/`user`, `data.srcip`, `data.dstip`, `process.name` ou `data.win.eventdata.image`, hash de fichier, etc.

Algorithme recommandé : **union-find** sur le graphe alerte ↔ entité, limité à la fenêtre.

**Piège principal : les entités « hub ».** Le manager Wazuh, le contrôleur de domaine, le DNS, `svchost.exe`, `SYSTEM`, etc. relient tout et produisent un cluster géant. Mesures obligatoires :
- liste de **denylist d'entités** configurable (YAML) ;
- pondération **IDF** : une entité présente dans plus de X % des alertes ne crée aucun lien ;
- **taille maximale** de cluster, avec découpage au-delà ;
- un cluster ne vaut jugement que s'il contient au moins N alertes ou 2 hôtes/utilisateurs (paramétrable).

Gérer aussi les chaînes lentes (jusqu'à 4 h entre étapes) : la fenêtre doit être **glissante** et un cluster ouvert peut être étendu et **re-décidé** quand de nouvelles alertes arrivent (versionner la décision, ne pas écraser).

## 5. Sérialisation du state (là où se gagne la précision)

Ne jamais envoyer le JSON brut des alertes (bruit, limite de contexte du modèle). Envoyer un **résumé compact, trié par temps** :

```json
{
  "cluster_id": "clu-0042",
  "window_minutes": 214,
  "hosts": ["WS-FIN-07", "SRV-FILE-02"],
  "users": ["j.martin", "svc_backup"],
  "alert_count": 8,
  "max_rule_level": 7,
  "timeline": [
    {"t": "+0m", "host": "WS-FIN-07", "level": 5, "mitre": "T1566.001", "desc": "OUTLOOK.EXE spawned WINWORD.EXE opening Facture_Q3.docm"},
    {"t": "+1m", "host": "WS-FIN-07", "level": 6, "mitre": "T1059.001", "desc": "WINWORD.EXE spawned powershell.exe"}
  ]
}
```

Règles :
- descriptions tronquées et normalisées (pas de GUID, pas de bruit) ;
- **enrichissement contextuel** quand la source existe : allowlist d'hôtes d'administration (ex. serveurs SCCM), inventaire des comptes de stockage cloud, premier-vu d'un couple source/destination, binaire signé ou non. C'est ce contexte qui sépare un patching légitime d'une attaque déguisée ;
- le sérialiseur est une **fonction pure et testée** ; toute évolution du format se versionne (`state_version`).

## 6. Questions typées (v2, validées dans le playground Jev)

Ce jeu de questions est la référence. Les instructions restent **en anglais** (les tests ont été faits en anglais ; changer de langue fausserait les comparaisons).

La définition de référence est dans `config/questions.v2.json` (versionnée) ; la version utilisée est enregistrée dans chaque décision.

Questions : `is_sophisticated_attack` (noul), `furthest_stage` (choice, avec l'option `none_benign`), `priority` (score P0 à P4), `unauthorized_exfiltration` (noul), `should_contain_now` (noul), `should_escalate_to_ir` (noul).

### Politique de décision (dans le backend, pas dans le modèle)

Une fonction `policy(decision) -> RecommendedAction` applique des **seuils configurables** :
- `is_sophisticated_attack` < 0,3 et `priority` ≤ 2 → `monitor` ;
- `is_sophisticated_attack` entre 0,3 et 0,7, ou `priority` entre 2 et 3 → `investigate` ;
- `should_contain_now` élevé → `contain` ;
- `should_escalate_to_ir` élevé (indépendamment de `contain`) → `escalate`.

Les valeurs seuils sont des **valeurs initiales à calibrer** sur le jeu de validation, pas des vérités. Ajoute les drapeaux : `inconsistent` (réponses contradictoires), `low_confidence`.

## 7. Schéma de stockage (`jev-decisions-*`)

Un document par version de décision de cluster, avec au minimum : `cluster_id`, `version`, `created_at`, `window_start`, `window_end`, `agents[]`, `users[]`, `alert_ids[]`, `alert_count`, `max_rule_level`, `mitre_techniques[]` (déterministe), `state_version`, `questions_version`, `backend` (laya/jev/mock) et `model_name`, `answers` (probabilités brutes de chaque question), `derived` (`confidence_overall`, flags, `recommended_action`, `justification` construite), `latency_ms`, et `analyst_feedback` (nul au départ, pour le stretch goal). Mapping explicite (pas de dynamic mapping) ; index quotidiens ou mensuels.

## 8. Interface Wazuh (dashboards natifs)

Vue « Jev Correlation » construite avec saved searches et visualisations OpenSearch Dashboards, **exportées en `.ndjson` et versionnées dans le dépôt** (`dashboards/`) pour une installation reproductible :
- liste des clusters triable (sophistication, priorité, étape, action) ;
- timeline des alertes d'un cluster ;
- probabilités + justification déterministe ;
- filtres : priorité, étape, période, agent ;
- un lien depuis un cluster vers les alertes Wazuh d'origine.

## 9. Rapports

- Rapport automatique JSON + PDF pour chaque cluster dont la priorité dépasse un seuil.
- Rapport périodique (quotidien/hebdo) des clusters sophistiqués.
- Contenu : résumé, timeline, techniques MITRE, probabilités, justification, action recommandée, version du modèle et des questions.

## 10. Données et évaluation (livrable central)

### Jeu de données

- **Attaques :** chaînes Atomic Red Team ou profils Caldera exécutés sur un agent Windows avec Sysmon, collectés dans Wazuh. Une exécution = un cluster positif labellisé. Varier le rythme (dont des chaînes lentes sur 4 h).
- **Bruit bénin :** administration normale, patching SCCM, scans de vulnérabilités, installeurs bruyants, sauvegardes, tâches de rétention de logs.
- **Hard negatives :** clusters bénins qui **imitent** une attaque (même niveau de règle, mêmes techniques).
- **Adversariaux :** attaques déguisées en activité d'administration (LOTL avec compte de service SCCM, exfiltration vers un compte de stockage cloud contrôlé par l'attaquant).
- Un format de label simple : `label` (attack/benign), `kill_chain_stage` atteint, `notes`.

### Ce qui existe déjà : tests playground Jev (résultats observés)

Deux clusters (attaque / jumeau bénin SCCM), tous deux à `max_rule_level = 7` :

| Question | Attaque | Bénin |
|---|---|---|
| `is_sophisticated_attack` | 97 % | 20 % |
| `priority` | 3,98 / 4 | 1,93 / 4 |
| `unauthorized_exfiltration` (ancienne version `data_left_perimeter`) | 85 % | 48 % |

Leçons : le modèle sépare deux clusters que la sévérité seule ne distingue pas ; mais `furthest_stage` sans option `none_benign` donnait « exfiltration » à 95 % sur un backup bénin (corrigé en v2). **Un seul exemple par classe ne prouve rien** sur la calibration.

### Script `make_variants.py` et matrice d'ablation

Génère 3 clusters (attack, benign, adversarial) × 4 variantes : `full`, `no_mitre`, `no_level`, `blind` (descriptions sans indices contextuels). Interprétation :
- attack reste haut partout → le modèle suit la chaîne causale ;
- benign monte en `blind` → mesure la dépendance au contexte (le sérialiseur doit donc fournir ce contexte) ;
- adversarial : si bas en `full`, le modèle ne fait que du pattern matching sur les noms ; si haut en `full` mais effondré en `blind`, la détection dépend des indices (limite à documenter honnêtement).

### Harnais `eval.py` (à construire tôt)

Charge un dossier de clusters labellisés, interroge le backend choisi avec les mêmes questions, et calcule :
- précision / rappel / F1 **au niveau cluster** ;
- **Brier score** et **ECE** (tableau de fiabilité à 5 bins) ;
- latence p50/p95 ;
- **baselines à battre :** `max_rule_level >= 7` et `somme des niveaux`. Si le modèle ne bat pas une heuristique d'une ligne, il faut le savoir et le dire ;
- comparaison Laya zero-shot, Laya fine-tuné (+ calibration par température sur un split de validation), Jev API.

Split train/validation/test **fixe et documenté** ; pas de fuite entre variantes d'un même scénario (toutes les variantes d'un scénario vont dans le même split).

### Fine-tuning de Laya

Prévu dès le départ, car Laya zero-shot ne sera probablement pas fiable sur du JSON de clusters Wazuh. Les clusters labellisés du jeu de données sont le matériel d'entraînement. Reste réaliste : petit jeu, validation stricte, recalibrage par température, rapport honnête des limites.

## 11. Structure de dépôt proposée

```
jev-soc/
├── CLAUDE.md                 # ce fichier
├── README.md                 # installation et utilisation
├── config/
│   ├── config.yaml           # fenêtre, seuils, backend, connexion indexeur
│   ├── questions.v2.json
│   └── entity_denylist.yaml
├── src/jevsoc/
│   ├── collector.py          # lecture indexeur / fichier
│   ├── correlator.py         # union-find, fenêtre, hubs
│   ├── serializer.py         # state compact (fonction pure)
│   ├── backends/             # base.py, laya_backend.py, jev_backend.py, mock_backend.py
│   ├── policy.py             # seuils, flags, justification
│   ├── store.py              # écriture jev-decisions-*
│   ├── reports.py            # JSON + PDF
│   └── api.py                # FastAPI
├── dashboards/               # exports .ndjson
├── data/                     # clusters labellisés + générateurs
├── eval/                     # eval.py, calibration, résultats
├── scripts/make_variants.py
├── docker/                   # lab Wazuh (optionnel)
└── tests/
```

## 12. Ordre de réalisation (jalons)

1. **Squelette + `MockBackend` + `eval.py` minimal** (le harnais d'abord).
2. **Jeu de 20 clusters à la main** (10 attaques, 10 bénins en miroir) + matrice d'ablation via Jev playground/API.
3. **Sérialiseur + correlator** sur fichiers NDJSON, avec tests (dont le cas hub).
4. **LayaBackend zero-shot** vs baselines.
5. **Lab Wazuh + génération de données** (Atomic Red Team / Caldera + bruit).
6. **Fine-tuning + calibration**, évaluation finale.
7. **Stockage `jev-decisions-*` + dashboards natifs.**
8. **Rapports JSON/PDF.**
9. Stretch : feedback analyste, ATT&CK Navigator, plugin React.

À chaque jalon : code, tests, mise à jour du README, et un court résumé des résultats mesurés.

## 13. Critères de succès

- Détection d'une chaîne multi-étapes là où les alertes individuelles restent sous le radar, **mesurée** face aux baselines.
- Décisions exploitables : probabilités calibrées (ECE rapporté) + actions concrètes + justification déterministe.
- Intégration propre dans Wazuh (dashboards importables en une commande).
- Code propre, documenté, démontrable ; installation reproductible.

## 14. Contraintes et règles de travail

- Le modèle de décision reste **Jev ou Laya** (pas un LLM génératif classique). Les LLM ne servent pas à décider.
- **Confidentialité :** Laya local est le mode recommandé ; avec Jev API, les états de cluster quittent le périmètre. Ne jamais envoyer de vraies données sensibles à l'API ; utiliser des données de lab ou anonymisées.
- Pas de secrets dans le dépôt (clés API, mots de passe Wazuh) : variables d'environnement et `.env` ignoré par git.
- Ne jamais présenter une probabilité comme fiable sans la valider sur un jeu labellisé. Si un résultat est faible, le dire.
- Ne pas inventer de schéma d'API : vérifier dans la doc de la version installée (Laya, `typesafe_sdk`, Wazuh/OpenSearch).
- Les alertes d'un lab de test ne doivent jamais être mélangées aux données de production.

## 15. Notes de mise en œuvre (tenues à jour)

- Commandes : `pip install -e ".[dev,jev]"`, `pytest`, `ruff check . && ruff format --check .`,
  `python scripts/make_variants.py`, `python eval/eval.py [--backend jev]`.
- `typesafe_sdk` 0.7.2 vérifié : `TypeSafeClient(model=..., timeout=...)` lit `TYPESAFE_API_KEY` ;
  `client.system_one(state=<dict>, questions=<dict>)`. Réponses : `noul` → `{"noul": p}`,
  `choice` → `{"choice", "confidence", "probabilities"}`, `score` → `{"score", "confidence",
  "legend", "probabilities"}`. `JevBackend` les convertit vers `jevsoc.models`.
- Clusters labellisés (`data/ablation/*.json`, `data/ait/*.json`) : `{scenario, variant, label,
  kill_chain_stage, notes, rule_levels, state}`. `rule_levels` = vrais niveaux, utilisés par les
  baselines même quand le `state` les cache (variante `no_level`).
- Split fixé par scénario dans `data/splits.yaml`. AIT : fox, harrison, wheeler = validation
  (choix des seuils) ; les 5 autres = test. Ne jamais régler un seuil sur le test.
- Vraies données : AIT-ADS (CC-BY 4.0), voir `data/README.md`. Bruts dans `data/raw/` (ignoré).
- Correlator : les hubs sont les entités présentes en continu dans le TEMPS (pas en nombre
  d'alertes, sinon un attaquant bruyant devient un hub) ; la règle Wazuh est aussi une entité
  (rafales derrière un proxy). Sérialiseur `state_version` 2 : rafales fusionnées, lignes rares
  prioritaires.
- Windows : `scripts/wazuh_replay.py` rejoue des journaux Windows/Sysmon (format NXLog d'OTRF)
  dans un vrai wazuh-manager de LAB, en injectant {"Message", "Event": XML} dans
  queue/sockets/queue (file "f", comme un agent). XML avec attributs entre APOSTROPHES (sinon
  l'analyseur XML de Wazuh échoue). wazuh-logtest ne gère pas l'eventchannel.
- Entités Windows : ProcessGuid / ParentProcessGuid (arbres de processus), fichiers (dépôt puis
  exécution), comptes Windows. Hubs repérés par tranches de 3 min pour les enregistrements courts.
- Calibration : `eval/calibrate.py` (Platt, cible = chaîne multi-étapes) sur la validation AIT,
  écrit `config/calibration.yaml` ; la politique l'applique avant les seuils. Seuils actuels :
  sophisticated_low 0,14 (échelle calibrée), volume_min_alerts 65, règle de priorité désactivée.
- Résultats (README) : AIT test 5/5 chaînes à 0 FP/jour ; APT29 (Windows, jamais réglé dessus)
  11/11 chaînes, F1 0,79 vs 0,42 pour max_level >= 7, ECE 0,30 -> 0,05 ; la règle de volume aide
  sur Linux (scans) mais nuit sur Windows (rafales de fausses alertes Wazuh).
- Prochaines tâches : correlator incrémental + démo live (rejoueur + page web), `LayaBackend`,
  règle de volume moins naïve (ex. rafales d'une même règle bruyante connue), plus de chaînes.
