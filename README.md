# Pentaster

Framework d'orchestration pour **pentest web automatisé**, dans l'esprit d'Osmedeus :
il enchaîne des outils existants (httpx, ffuf, nuclei) selon des **workflows YAML
déclaratifs**, chaque outil tournant dans un **conteneur Docker éphémère** (aucune
install native), normalise les résultats en *findings*, et produit un **rapport HTML**
autonome + un JSON.

> ⚠️ **Usage légal uniquement.** Pentaster ne doit viser que des cibles que vous
> possédez / hébergez ou pour lesquelles vous avez une autorisation écrite. Un
> **garde-fou d'autorisation** (allowlist `scope.txt` + flag `--authorized`) empêche
> de scanner une cible hors périmètre par accident.

---

## Prérequis

- Python ≥ 3.13, Docker (les outils tournent en conteneurs, rien à installer d'autre)
- Un lab autorisé, ex. OWASP Juice Shop : `docker run --rm -p 3000:3000 bkimminich/juice-shop`

## Installation

```bash
pip install -e .          # installe la commande `pentaster` + les dépendances
# (ou : pip install -e ".[dev]" pour les tests)
```

## Lancer un scan (1 commande)

```bash
pentaster run web-basic --target http://localhost:3000 --authorized
```

- `web-basic` = nom du workflow (résolu vers `workflows/web-basic.yaml`) ou un chemin YAML.
- `--target` : l'URL du lab.
- `--authorized` : **obligatoire** — confirme que tu es autorisé à tester la cible.

Options : `--scope <fichier>` (allowlist, défaut `scope.txt`), `--wordlists <dir>`,
`--out <dir>` (défaut `runs/<timestamp>/`).

Sorties dans `runs/<timestamp>/` : `results.json` + `report.html`.

Tester uniquement le garde-fou, sans rien scanner :

```bash
pentaster scope-check http://localhost:3000   # ✔ AUTORISÉE
pentaster scope-check http://exemple.com       # ✘ REFUSÉE (exit 2)
```

## Garde-fou d'autorisation

`scope.txt` liste une entrée (hôte ou domaine) par ligne ; `localhost` et `127.0.0.1`
sont autorisés par défaut pour le lab. `ScopeGuard.is_authorized(target)` extrait l'hôte
de l'URL et vérifie la correspondance exacte **ou** en sous-domaine. La CLI refuse de
lancer **sans le flag `--authorized`** *et* **sans cible dans le scope** → impossible de
pointer l'outil sur une cible non autorisée par accident.

## Architecture

```
pentaster/
  cli.py        # point d'entrée typer/rich (run, scope-check)
  engine.py     # ordonnance les étapes (DAG depends_on), exécute, agrège les findings
  workflow.py   # modèles pydantic + chargement/validation YAML + tri topologique
  runner.py     # wrapper `docker run` éphémère (+ localhost → host.docker.internal)
  scope.py      # ScopeGuard : allowlist d'autorisation
  parsers.py    # httpx / ffuf / nuclei → Finding normalisé
  results.py    # sérialisation JSON du run
  report.py     # rapport HTML (jinja2)
workflows/web-basic.yaml     # workflow web par défaut
templates/report.html.j2     # gabarit du rapport
wordlists/common.txt         # wordlist courte (content discovery)
scope.txt                    # allowlist
runs/                        # sorties horodatées (gitignored)
tests/                       # tests unitaires (aucun Docker/réseau requis)
```

**Principe :** le moteur ne connaît aucun outil en dur. Ajouter un outil = ajouter un
bloc `step` dans un YAML (+ un parser si nouveau format). Aucune modif du moteur.

## Format d'un workflow

```yaml
name: web-basic
target_type: url
steps:
  - id: probe
    tool: httpx
    image: projectdiscovery/httpx:latest
    args: ["-u", "{{target}}", "-json", "-tech-detect", "-status-code", "-title"]
    parser: httpx
  - id: vulns
    tool: nuclei
    image: projectdiscovery/nuclei:latest
    depends_on: [probe]
    args: ["-u", "{{target}}", "-jsonl", "-severity", "low,medium,high,critical"]
    parser: nuclei
```

Champs : `id` (unique), `tool` (label), `image` (Docker), `args` (templating
`{{target}}`), `parser` (`httpx`|`ffuf`|`nuclei`), `depends_on` (optionnel). Les étapes
sans dépendance entre elles s'exécutent en parallèle.

## Modèle d'exécution

1. **Autorisation** — `ScopeGuard` ; hors allowlist → arrêt immédiat, aucun conteneur.
2. **Ordonnancement** — tri topologique via `depends_on` (vagues parallèles).
3. **Exécution** — chaque étape → un `docker run --rm` éphémère ; stdout capturé.
4. **Parsing** — stdout → `list[Finding]` via le parser désigné.
5. **Sortie** — findings → `results.json`, puis `report.html`.

## Tests

```bash
pytest            # tout est mocké : aucun Docker ni réseau nécessaire
```

## Périmètre & évolutions

**MVP :** httpx + ffuf + nuclei, workflow `web-basic`, CLI + rapport HTML, garde-fou,
testé contre Juice Shop local.

**Hors MVP :** sqlmap/dalfox, workflow infra (subfinder/naabu/nmap), notifications
(Slack/Discord), dashboard web (FastAPI), reprise de scan, scoring CVSS, export SARIF.

## Licence des outils orchestrés

httpx / nuclei (MIT), ffuf (MIT) — tous open-source, gratuits et activement maintenus.
