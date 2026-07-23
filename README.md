# Pentaster

Framework d'orchestration pour **pentest web automatisé**. Enchaîne des outils
(httpx, ffuf, nuclei) dans des conteneurs Docker éphémères, pilotés par des
workflows YAML, avec garde-fou d'autorisation, résultats JSON et rapport HTML.

## Prérequis

- Python 3.13, Docker.
- Installation :

  ```bash
  python3 -m pip install -e ".[dev]"
  ```

## Usage

### Lister les workflows disponibles

```bash
pentaster list-workflows
# ou en indiquant un autre dossier :
pentaster list-workflows --dir chemin/vers/workflows
```

### Vérifier le garde-fou de périmètre sur une cible (sans lancer de scan)

```bash
pentaster scope-check http://localhost:3000
```

### Lancer un scan

```bash
pentaster run web-basic --target http://localhost:3000 --authorized
```

- `workflow` (argument positionnel) : nom court d'un workflow présent dans
  `workflows/` (ex. `web-basic`) ou chemin vers un fichier `.yaml`.
- `--target` / `-t` (obligatoire) : URL ou hôte cible.
- `--authorized` (obligatoire) : confirme explicitement que tu es autorisé à
  tester la cible.
- `--scope` / `-s` (optionnel) : fichier d'allowlist. Par défaut, `scope.txt`
  à la racine du projet.
- `--wordlists` / `-w` (optionnel) : dossier de wordlists monté dans les
  conteneurs. Par défaut, `wordlists/`.
- `--out` / `-o` (optionnel) : dossier de sortie. Par défaut,
  `runs/<horodatage>/`.
- `--templates` (optionnel) : dossier des templates de rapport. Par défaut,
  `templates/`.

Les résultats sont écrits dans le dossier de sortie :
- `results.json` — findings et issues d'exécution, au format JSON.
- `report.html` — rapport HTML autonome (ouvrable dans un navigateur).

### Codes de sortie de `pentaster run`

| Code | Signification |
|------|----------------|
| `0`  | Scan terminé avec succès |
| `2`  | Flag `--authorized` manquant |
| `3`  | Cible hors périmètre (absente de l'allowlist) |
| `1`  | Autre erreur (ex. workflow introuvable) |

## Garde-fou d'autorisation

Aucun scan n'est lancé sans :

1. Le flag explicite `--authorized` sur la ligne de commande, **et**
2. Un hôte cible présent dans l'allowlist (`scope.txt` par défaut, ou le
   fichier passé via `--scope`).

`localhost` et `127.0.0.1` sont autorisés par défaut, pour les labs locaux
(ex. OWASP Juice Shop sur `http://localhost:3000`). Ajoute une cible dans
`scope.txt` (une entrée par ligne, hôte ou domaine) uniquement si tu es
autorisé à la tester.

## Ajouter un outil

Édite un workflow YAML (`workflows/*.yaml`) : ajoute une étape (`id`, `tool`,
`image`, `args`, `parser`, `depends_on` optionnel). Si le format de sortie de
l'outil est nouveau, ajoute un parser correspondant dans
`pentaster/parsers.py`.

## ⚠️ Usage légal

À n'utiliser que sur des cibles que tu possèdes ou pour lesquelles tu
disposes d'une autorisation écrite explicite (lab personnel, mission
contractuelle, programme de bug bounty). Tester une cible sans autorisation
est illégal dans la plupart des juridictions.
