# Pentaster — Design (MVP)

**Date:** 2026-07-23
**Statut:** Validé (design), en attente de plan d'implémentation

## Objectif

Framework d'orchestration pour pentest **web** automatisé, dans l'esprit d'Osmedeus :
enchaîner des outils existants selon des workflows déclaratifs, collecter les résultats
normalisés et produire un rapport. Cible d'usage : labs autorisés (ex. OWASP Juice Shop local).

## Décisions cadrées

| Sujet | Choix |
|---|---|
| Type de cible (MVP) | Web app (URL/domaine) |
| Exécution des outils | Un conteneur Docker éphémère **par outil** (images officielles, aucune install native) |
| Langage du moteur | Python 3.13 |
| Définition des workflows | YAML déclaratif |
| Interface | CLI (`typer` + `rich`) + rapport HTML autonome + résultats JSON |
| Garde-fou | Allowlist d'autorisation **obligatoire** (sécurisé par défaut) |
| Outils MVP | httpx, ffuf, nuclei |

## Contexte technique

- Hôte : macOS, Python 3.13, Node 24, Docker 28 dispo. Aucun outil pentest installé nativement.
- Projet existant : `~/dev/Pentaster` (git initialisé, branche `main`, README vide).
- Lab de test : OWASP Juice Shop v20 sur `localhost:3000` (conteneur Docker).

## Architecture

```
Pentaster/
├── pentaster/                  # moteur (package Python)
│   ├── __init__.py
│   ├── cli.py                  # point d'entrée (typer)
│   ├── engine.py               # exécuteur de workflow (DAG des étapes)
│   ├── workflow.py             # chargement + validation YAML (pydantic)
│   ├── runner.py               # wrapper d'exécution `docker run`
│   ├── scope.py                # garde-fou d'autorisation (allowlist)
│   ├── parsers.py              # normalise la sortie de chaque outil → Findings
│   ├── results.py              # stockage JSON des résultats d'un run
│   └── report.py               # génération du rapport HTML (jinja2)
├── workflows/
│   └── web-basic.yaml          # workflow web par défaut
├── templates/report.html.j2    # gabarit du rapport
├── wordlists/
│   └── common.txt              # wordlist courte par défaut (content discovery)
├── runs/                       # sorties horodatées par scan (gitignored)
├── tests/                      # tests unitaires (fixtures de sortie d'outils)
├── pyproject.toml
└── README.md
```

**Principe directeur :** le moteur ne connaît aucun outil en dur. Il lit un YAML, construit
un graphe d'étapes (via `depends_on`), lance chaque étape dans un conteneur Docker éphémère,
parse la sortie en *findings* normalisés, stocke le tout en JSON, puis génère un rapport HTML.
Ajouter un outil = ajouter un bloc `step` dans un YAML + (si besoin) un parser. Aucune modif du moteur.

## Composants (responsabilité unique)

- **cli.py** — parse les arguments (`pentaster run <workflow> --target <url> --authorized`),
  orchestre l'appel au moteur, affiche la progression (`rich`). Dépend de : engine, scope, report.
- **workflow.py** — modèle pydantic `Workflow`/`Step` ; charge et **valide** un fichier YAML
  (champs requis, images, `depends_on` référençant des ids existants, absence de cycle). Pur, testable.
- **scope.py** — `ScopeGuard` : charge `scope.txt` (une entrée hôte/domaine par ligne),
  expose `is_authorized(target) -> bool`. Le moteur refuse tout run hors allowlist. Pur, testable.
- **runner.py** — `DockerRunner.run(step, context) -> RunResult(stdout, stderr, exit_code)`.
  Construit et exécute la commande `docker run --rm -v <wordlists>:/wordlists <image> <args>`,
  avec templating `{{target}}`. Réécrit `localhost`/`127.0.0.1` → `host.docker.internal` pour
  atteindre un lab local depuis un conteneur. Isolé derrière une interface mockable.
- **engine.py** — `Engine.execute(workflow, target)` : vérifie le scope, ordonne les étapes
  (topologique via `depends_on`, parallélise celles sans dépendance), appelle le runner,
  passe chaque stdout au parser désigné, agrège les `Finding`. Dépend de : scope, runner, parsers.
- **parsers.py** — une fonction par format (`httpx`, `ffuf`, `nuclei`) : `parse(stdout) -> list[Finding]`.
  Sélection par le champ `parser` de l'étape. Pur, testable avec fixtures.
- **results.py** — `RunResults` : sérialise findings + métadonnées vers `runs/<ts>/results.json`.
- **report.py** — rend `templates/report.html.j2` avec les résultats → `runs/<ts>/report.html`.

## Format de workflow (YAML)

```yaml
name: web-basic
description: Évaluation web de base (probe → découverte → vulns)
target_type: url
steps:
  - id: probe
    tool: httpx
    image: projectdiscovery/httpx:latest
    args: ["-u", "{{target}}", "-json", "-tech-detect", "-sc", "-title"]
    parser: httpx

  - id: content
    tool: ffuf
    image: ghcr.io/ffuf/ffuf:latest
    depends_on: [probe]
    args: ["-u", "{{target}}/FUZZ", "-w", "/wordlists/common.txt", "-of", "json"]
    parser: ffuf

  - id: vulns
    tool: nuclei
    image: projectdiscovery/nuclei:latest
    depends_on: [probe]
    args: ["-u", "{{target}}", "-jsonl", "-severity", "low,medium,high,critical"]
    parser: nuclei
```

Champs d'une étape : `id` (unique), `tool` (label), `image` (Docker), `args` (liste, templating
`{{target}}`), `parser` (nom du parser), `depends_on` (liste d'ids, optionnel).

## Modèle d'exécution

1. **Autorisation** — le moteur appelle `ScopeGuard.is_authorized(target)`. Hors allowlist → arrêt
   immédiat, aucun conteneur lancé. La CLI exige aussi le flag explicite `--authorized`.
2. **Ordonnancement** — tri topologique des étapes ; les étapes prêtes (dépendances satisfaites)
   sont lancées en parallèle (pool borné).
3. **Exécution** — chaque étape → un `docker run` éphémère ; stdout capturé.
4. **Parsing** — stdout → `list[Finding]` via le parser désigné.
5. **Agrégation & sortie** — tous les findings → `results.json` ; puis `report.html`.

### Réseau (lab local)

Pour viser `localhost:3000` depuis un conteneur, le runner substitue `localhost`/`127.0.0.1`
par `host.docker.internal` dans `{{target}}`. Documenté et testé.

## Modèle de données

```python
@dataclass
class Finding:
    tool: str          # "nuclei"
    target: str        # url ciblée
    type: str          # "vulnerability" | "endpoint" | "tech" | ...
    severity: str      # "info|low|medium|high|critical"
    name: str          # libellé court
    evidence: str      # extrait / preuve
    raw: dict          # objet brut de l'outil
```

Le rapport HTML : en-tête (cible, workflow, horodatage, durée), tableau des findings trié par
sévérité, section par étape (statut, nb de findings), technos détectées.

## Garde-fou d'autorisation

- Fichier `scope.txt` à la racine du run (ou chemin `--scope`), une entrée par ligne
  (hôte ou domaine ; `localhost` et `127.0.0.1` autorisés par défaut pour le lab).
- `ScopeGuard.is_authorized(target)` extrait l'hôte de l'URL et vérifie l'appartenance
  (correspondance exacte d'hôte ou sous-domaine d'une entrée).
- La CLI refuse de lancer sans le flag `--authorized` **et** sans cible dans le scope.
- Objectif : impossible de pointer l'outil sur une cible non autorisée par accident.

## Périmètre

**MVP :** 3 outils (httpx, ffuf, nuclei), workflow `web-basic`, CLI + rapport HTML, garde-fou,
testé contre Juice Shop local.

**Hors MVP (évolutions) :** sqlmap/dalfox, workflow infra (subfinder/naabu/nmap), notifications
(Slack/Discord), dashboard web (FastAPI), reprise de scan, parallélisme avancé/distribué.

## Stratégie de test (TDD)

- **workflow.py** — parsing/validation YAML : champs manquants, `depends_on` invalide, cycle détecté.
- **scope.py** — autorisé / refusé, sous-domaine, URL malformée.
- **parsers.py** — chaque parser avec fixtures de vraie sortie (httpx JSON, ffuf JSON, nuclei JSONL).
- **report.py** — rendu HTML non vide contenant les findings attendus.
- **runner.py** — construction de la commande `docker run` (Docker mocké ; aucun conteneur en test).

Aucun test ne nécessite Docker ni réseau : le runner est isolé derrière une interface mockable.

## Risques / points d'attention

- **Images Docker** : vérifier les tags/args exacts (`ghcr.io/ffuf/ffuf`, options `-of json`).
  À confirmer au moment de l'implémentation de chaque parser.
- **host.docker.internal** : comportement macOS ; alternative = attacher au réseau Docker du lab.
- **ffuf & wordlist** : monter la wordlist en volume ; fournir un `common.txt` court par défaut.
