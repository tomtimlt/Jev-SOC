"""Lance les 12 variantes sur Jev (api.typesafe.ai) et affiche la grille.

Usage:
  python eval.py            # appelle l'API (nécessite TYPESAFE_API_KEY)
  python eval.py --dry-run  # affiche seulement les requêtes, sans appel réseau

Les réponses brutes sont écrites dans ./results/<nom>.json : le format de
réponse n'a pas encore été observé, l'extraction de la grille est donc
tolérante (elle cherche la clé de la question à n'importe quelle profondeur).
"""
import json, os, pathlib, sys, urllib.request, urllib.error

URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
KEYS = ("is_sophisticated_attack", "priority")   # relevés pour la grille
CLUSTERS = ("attack", "benign", "adversarial")
VARIANTS = ("full", "no_mitre", "no_level", "blind")

questions = json.loads(pathlib.Path("questions_v2.json").read_text())

def call(state: dict) -> dict:
    # "state" est une chaîne dans l'exemple de l'API : on y sérialise le JSON du cluster
    body = json.dumps({"state": json.dumps(state), "model": MODEL, "questions": questions}).encode()
    req = urllib.request.Request(URL, body, {
        "Authorization": f"Bearer {os.environ['TYPESAFE_API_KEY']}",
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"_error": e.code, "_body": e.read().decode(errors="replace")}

def scalar(v):
    """Réduit une réponse {type: noul|score, ...} à sa valeur numérique."""
    if isinstance(v, dict):
        return v.get(v.get("type"), v)
    return v

def find(obj, key):
    """Cherche `key` récursivement dans la réponse brute."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            if (r := find(v, key)) is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            if (r := find(v, key)) is not None:
                return r
    return None

dry = "--dry-run" in sys.argv
if not dry and not os.environ.get("TYPESAFE_API_KEY"):
    sys.exit("TYPESAFE_API_KEY absente de l'environnement")

out = pathlib.Path("results"); out.mkdir(exist_ok=True)
grid = {}
for c in CLUSTERS:
    for v in VARIANTS:
        state = json.loads(pathlib.Path(f"variants/{c}__{v}.json").read_text())
        if dry:
            print(f"[dry-run] {c}__{v}: {len(json.dumps(state))} car. d'état, {len(questions)} questions")
            continue
        resp = call(state)
        (out / f"{c}__{v}.json").write_text(json.dumps(resp, indent=2))
        grid[(c, v)] = {k: scalar(find(resp, k)) for k in KEYS}
        print(c, v, grid[(c, v)], flush=True)

if grid:
    for k in KEYS:
        print(f"\n## {k}\n| Variante | " + " | ".join(CLUSTERS) + " |\n|---|---|---|---|")
        for v in VARIANTS:
            print(f"| {v} | " + " | ".join(str(grid[(c, v)][k]) for c in CLUSTERS) + " |")
