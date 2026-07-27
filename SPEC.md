# mcpwall — spécification projet

Document de référence. Mis à jour à mesure que les décisions sont prises.
Les sections marquées **[révisé]** ont changé depuis le brief initial ; le
journal des décisions en fin de document dit pourquoi.

Dernière mise à jour : 2026-07-27.

---

## 1. Ce qu'on construit

Un pare-feu applicatif local pour agents de code. Il s'intercale entre les clients MCP
(Claude Code, Cursor, Codex) et les serveurs MCP, journalise tout le trafic JSON-RPC,
et bloque les appels dangereux selon une politique locale.

Analogie de référence : **Little Snitch, mais pour les appels d'outils d'agents IA.**

Le cas d'usage central à garder en tête en permanence : un utilisateur lance son agent en
mode auto-accept ; un contenu externe (issue GitHub, page web, e-mail) contient une
injection de prompt ; l'agent lit un secret local puis tente de l'envoyer vers un outil
réseau. mcpwall doit repérer ça et interrompre.

## 2. Non-objectifs (à refuser explicitement si la conversation dérive)

- Pas de multi-utilisateur, pas d'OAuth, pas de RBAC, pas de déploiement Kubernetes.
  Le marché entreprise est déjà pris (Lunar MCPX, MCPProxy, ContextForge). On fait
  le produit mono-poste, local-first, interactif.
- Pas de télémétrie, pas d'analytics, pas de compte utilisateur, aucune requête réseau
  sortante hors vérification de mise à jour Sparkle.
- Pas d'analyse LLM des appels. Tout est déterministe et lisible.
- Pas de support Windows en v1.

## 3. Stack

- **Core (shim + daemon)** : Rust. **Binaire unique**, statique, sans dépendance runtime.
  Crates : `tokio`, `serde_json`, `rusqlite`, `clap`, `tracing`, `memchr`.
  Justification : le shim est dans le chemin critique de chaque appel d'outil, et le core
  doit rester portable Linux pour plus tard.
- **UI** : SwiftUI + AppKit, macOS 14+. Application `LSUIElement` (pas d'icône Dock).
- **IPC** : socket Unix, JSON délimité par retour ligne, dans `~/.mcpwall/`.
- **Stockage** : SQLite (`~/.mcpwall/journal.db`), WAL activé, `synchronous = NORMAL`.

Un seul repo, deux dossiers de premier niveau : `core/` (Rust) et `app/` (Swift).

Toolchain épinglée dans `rust-toolchain.toml`. Édition 2024.

## 4. Architecture **[révisé]**

```
Client MCP  <--stdio/http-->  shim mcpwall  <--stdio/http-->  serveur MCP amont
                                   |
                            socket Unix (verdict)
                                   |
                          mcpwall daemon
                          (policy, taint, journal)
                                   |
                        +----------+----------+
                   app menu bar            journal SQLite
```

- Un processus shim par serveur MCP (lancé par le client, pas par nous).
- **Un seul** daemon pour toute la machine, lancé par `mcpwall daemon`.
- Il n'y a **pas** de binaire `mcpwalld` séparé. Un binaire unique avec sous-commandes :
  un seul artefact à embarquer dans `Contents/Resources/`, un seul lien symbolique, et
  surtout aucune dérive de version possible entre shim et daemon.
  Au démarrage, le daemon réécrit `argv[0]` en `mcpwall-daemon` pour rester lisible dans
  Activity Monitor.
- L'app SwiftUI **ne réimplémente pas** le daemon : elle lance et supervise
  `mcpwall daemon` comme processus enfant. Une seule source de vérité pour la politique
  et le taint, et la portabilité Linux reste intacte.
- Le shim est volontairement bête : parser, relayer, demander un verdict, appliquer.
  Toute la logique est dans le daemon.

### Handshake de version IPC

Le binaire unique ne garantit pas que le processus qui tourne est celui pointé par la
config : un shim lancé par un client resté ouvert depuis avant une mise à jour est un
vieux binaire face à un daemon neuf.

Premier message sur le socket :

```json
{"mcpwall_ipc": 1, "build": "<git sha>"}
```

Incompatibilité → le shim passe en **fail-open** et écrit un avertissement visible.

### Règle de disponibilité (critique)

Si le daemon est injoignable (app fermée, crash), le shim **laisse passer** et écrit dans
un fichier de log de rattrapage. Un mode `fail_closed: true` existe en configuration mais
n'est pas le défaut. Raison : si fermer l'app casse tous les serveurs MCP de l'utilisateur,
le produit est désinstallé dans l'heure.

Budget de latence en passthrough autorisé : **< 5 ms p99**. À mesurer, pas à supposer.

### Journal : deux chemins **[révisé]**

Tous les événements ne se valent pas.

- **volume** — appels autorisés. Canal borné (4096 au départ, à mesurer), drop en cas de
  saturation, compteur de pertes exposé.
- **décisions** — `deny`, `ask`, dérive de description, alerte taint. Rare par nature.
  **Écriture garantie**, quitte à bloquer brièvement le relais. Un outil d'audit qui perd
  l'événement justifiant son existence n'a plus de raison d'être.

Réduction de pression à la source plutôt que gestion de la saturation : WAL,
`synchronous = NORMAL` (pas `FULL`), et batching de la tâche d'écriture par transactions
de N entrées ou 200 ms, au premier des deux atteint. Les drops doivent rester théoriques ;
le compteur est un signal de bug, pas un comportement normal.

Le compteur est visible : `mcpwall log --stats` en M0, badge dans l'UI en M2.
« 47 entrées perdues aujourd'hui » est une information que l'utilisateur a le droit d'avoir.

## 5. Protocole **[révisé]**

MCP transporte du JSON-RPC 2.0. Révision de spec courante : **`2025-11-25`**.

**Le batch JSON-RPC est retiré** depuis la révision `2025-06-18` (changement majeur n°1,
PR #416). Une frame = un message. Une frame commençant par `[` est une violation à
journaliser, pas un cas à supporter.

Deux transports à gérer :

- **stdio** : JSON délimité par `\n` sur stdin/stdout du processus enfant. Le shim fait
  un fork du serveur amont et relaie. `stderr` de l'amont est relayé tel quel.
  La spec impose UTF-8 et interdit les retours ligne internes ; les serveurs réels
  violent parfois les deux, le découpeur doit se resynchroniser sans planter.
- **Streamable HTTP** : POST + réponse SSE. À implémenter en M3 seulement.

### Passthrough d'octets

On ne réémet **jamais** le JSON reformaté. Deux raisons : ça casserait tout amont sensible
aux octets exacts, et en HTTP ça invaliderait `Content-Length`. Le relais copie les octets
d'origine ; une copie de la frame part au journal.

### Deux ensembles, pas un

L'ensemble intercepté est scindé, et la séparation est structurelle pour qu'un futur
contributeur ne puisse pas la défaire par inadvertance.

| Ensemble | Méthodes | Traitement |
| --- | --- | --- |
| **DECIDE** | `tools/call`, `resources/read`, `sampling/createMessage`, `elicitation/create` | évaluation policy complète, verdict allow/deny/ask |
| **OBSERVE** | `initialize`, `notifications/initialized`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, `prompts/get`, `roots/list`, `notifications/roots/list_changed` | journalisation enrichie, **jamais bloquable** |
| passthrough | tout le reste | relais immédiat, journalisation sommaire |

**`initialize` n'est jamais soumis au point de décision.** Le bloquer ne protège de rien
et casse la session entière. Un test (`initialize_is_never_decidable`) casse la CI si
quelqu'un le déplace vers DECIDE.

`tools/list` reste par ailleurs soumis au hash SHA-256 des descriptions pour la détection
de rug pull (M3).

### Identification de la méthode

Scan bon marché sur les `METHOD_SCAN_WINDOW` (200) premiers octets, **avec repli explicite**
sur une passe complète. Une fenêtre épuisée ne peut jamais produire « pas de méthode » :
un `id` textuel long ou un sérialiseur plaçant `params` avant `method` suffit à repousser
la clé hors fenêtre, et c'est du trafic ordinaire.

Le scan n'est pas une recherche de sous-chaîne mais un automate suivant la profondeur des
accolades : `method` n'est retenu que comme clé de l'**objet racine**. Sans ça,
`{"params":{"method":"x"},"method":"tools/call"}` extrairait `x`.

Les échappements sont traversés correctement. Un scan qui renonce sur le premier `\`
classe la frame en `Unparsable` donc en OBSERVE, donc hors du point de décision — un
`tools/call` dont l'`id` contient `\"` contournerait alors toute la politique.

Frame incomprise → OBSERVE. Jamais DECIDE, jamais silencieusement passthrough.

### Ce qu'on capture à l'`initialize`

Côté **requête client** : `protocolVersion` demandée, `clientInfo.name` et `.version`,
présence de `capabilities.roots` et de son `listChanged`.

Côté **réponse serveur** : `serverInfo.name` et `.version`, clés de `capabilities`, et
surtout `protocolVersion` — **c'est la réponse du serveur qui porte la version négociée**,
pas la requête du client. C'est ce champ qu'on stocke.

⚠️ **L'`initialize` ne contient aucun chemin ni cwd.** Voir §6bis.

### Points à instruire avant M1

- **`elicitation` a deux sous-capacités**, `form` et `url`. Le `url` — faire ouvrir une URL
  à l'utilisateur — est un vecteur de phishing bien plus direct que le formulaire. La
  distinction se fait sur le contenu de `params`, donc dans le moteur de politique, pas
  dans le classement des méthodes.
- **Capacité `tasks`** (nouvelle en `2025-11-25`) : requêtes augmentées incluant
  `tools/call`, `sampling/createMessage`, `elicitation/create`. Si un `tools/call` peut
  être différé en tâche, le résultat ne revient pas par le flux supposé ici. À lire avant
  d'écrire le moteur de politique.

### Forme d'un blocage

Ne jamais fermer la connexion, ne jamais renvoyer une erreur JSON-RPC de protocole.
Renvoyer un `result` valide avec `isError: true` et un contenu texte du type :

```
blocked by mcpwall: tainted local data in outbound argument (rule: taint_exfil)
```

L'agent doit le lire comme un échec d'outil ordinaire, s'adapter, et continuer.

## 6. Moteur de politique

Fichier `~/.mcpwall/policy.yaml`, rechargé à chaud.

```yaml
default: allow          # allow | ask | deny
fail_closed: false
ask_timeout_seconds: 60 # expiration -> deny

rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env", "~/.ssh/**", "~/.aws/**", "**/id_rsa"]
    action: ask
    severity: high

  - id: outside_project_write
    when:
      tool_matches: ["*write*", "*edit*", "*delete*"]
      path_outside_cwd: true
    action: ask

  - id: taint_exfil
    when:
      arg_contains_tainted: true
      tool_is_outbound: true
    action: deny
    severity: critical

  - id: secret_pattern
    when:
      arg_matches_secret: true   # AWS keys, ghp_, sk-, BEGIN PRIVATE KEY
    action: ask

  - id: tool_description_changed
    when: { tool_description_drift: true }
    action: ask

overrides:                 # écrit par l'UI, pas par l'humain
  - scope: project:/Users/marc/monrepo
    tool: postgres.query
    action: allow
    until: session         # once | session | forever
```

Verdicts : `allow`, `deny`, `ask`. Portées : `once`, `session`, `forever`.

## 6bis. Provenance du scope **[nouveau]**

Le scoping par projet n'est pas un confort d'affichage, c'est un contrôle de sécurité :
si le scope est faux, un « toujours autoriser pour ce projet » fuit vers un autre projet.

L'`initialize` ne transporte pas le cwd. Deux sources candidates échouent, mais pas sur
les mêmes cas — d'où une chaîne de précédence.

| Rang | Source | Pourquoi / limite |
| --- | --- | --- |
| 1 | `--project <path>` injecté par `mcpwall init` | Au moment où `init` réécrit `~/monrepo/.mcp.json`, il sait de quel projet il s'agit. Déterministe, indépendant du protocole, identique sur tous les clients. Passé en **argument**, pas en variable d'environnement : les args sont préservés verbatim, l'env est parfois filtré. |
| 2 | `roots` observé passivement | Sémantiquement juste, mais capacité optionnelle et requête serveur→client : le shim ne la reçoit pas, il la voit passer, et seulement si un serveur amont pense à demander. |
| 3 | cwd hérité, **canonicalisé** | Correct depuis Claude Code, sans rapport avec un projet depuis Claude Desktop. Canonicalisation obligatoire (`/tmp` → `/private/tmp` sur macOS) sinon les clés ne correspondent pas d'une session à l'autre. |
| 4 | `unknown` | Sentinelle explicite. On ne devine jamais. |

Le cas qui force cette structure : un serveur configuré globalement dans `~/.claude.json`
est utilisé depuis dix projets différents. `init` ne peut pas y écrire de `--project` ;
ce serveur descendra en 2 ou 3.

**Conséquences, toutes obligatoires :**

- La **source du scope est stockée** avec chaque entrée de journal et chaque override.
- **`forever` n'est offert par l'UI que si la provenance est de rang 1 ou 2.** En `cwd` ou
  `unknown`, seuls `once` et `session` sont proposés.
- `roots` est un **ensemble**, pas un chemin : trier, dédupliquer, et clé sur l'ensemble
  complet — un monorepo peut légitimement en exposer plusieurs.
- `notifications/roots/list_changed` **remplace** l'ensemble, ne le fusionne pas.
- Le scope peut **monter** en fiabilité en cours de session. Chaque entrée de journal fige
  la provenance du moment ; on ne réécrit pas le passé.
- La **provenance n'entre pas dans la clé de scope**. Une session qui monte de `cwd` à
  `roots` sur le même chemin retombe sur les mêmes overrides au lieu d'en créer un jeu
  parallèle invisible. La provenance contrôle l'écriture de la permission, pas sa lecture.
- Une racine dont l'URI n'est pas comprise (schéma non-`file`, hôte distant, encodage
  malformé) est **ignorée** — la chaîne redescend d'un maillon. Une racine incomprise ne
  devient jamais une clé de permission.

### Taint tracking

C'est la fonctionnalité différenciante, à ne pas rogner.

1. Toute réponse à une lecture locale (`resources/read`, outil dont le nom matche
   `*read*`/`*file*`/`*exec*`) est découpée en shingles (n-grammes de mots, n=8),
   hachés, stockés en mémoire avec TTL de 10 minutes et l'origine (chemin, timestamp).
2. Avant tout appel vers un outil considéré comme sortant (liste configurable :
   noms matchant `*post*`, `*send*`, `*create*`, `*fetch*`, `*http*`, ou serveur
   déclaré `outbound: true`), on hache les arguments et on cherche un recouvrement.
3. Recouvrement au-dessus d'un seuil → règle `taint_exfil`.

La v1 peut être approximative. Un faux négatif est acceptable, un faux positif bruyant
ne l'est pas : règle le seuil haut.

## 7. La zone aveugle à couvrir

Un proxy MCP ne voit que le trafic MCP. Les outils intégrés de Claude Code
(`Read`, `Edit`, `Bash`, `WebFetch`) ne passent **pas** par MCP — c'est-à-dire l'essentiel
de la surface d'attaque. Il faut brancher un hook `PreToolUse` de Claude Code sur le même
daemon, avec la même politique et le même journal.

**Vérifier la documentation à jour des hooks Claude Code avant d'implémenter** : le schéma
d'entrée sur stdin et le format de la décision de permission en sortie changent.

Codex n'a pas d'équivalent propre (son modèle de sécurité passe par le sandbox) : on
couvre MCP uniquement, et on l'écrit noir sur blanc dans le README. L'honnêteté sur la
couverture est un argument de crédibilité, pas une faiblesse.

## 8. Onboarding — c'est là que le produit se gagne ou se perd

Commande `mcpwall init` (et son équivalent dans l'UI au premier lancement) :

1. Découvre les configurations existantes : `~/.claude.json`, `.mcp.json` du projet
   courant et des projets récents, `~/.codex/config.toml`, `~/.cursor/mcp.json`.
2. Sauvegarde chaque fichier en `.bak.<timestamp>`.
3. Réécrit chaque entrée de serveur pour envelopper la commande d'origine dans le shim,
   en conservant `env`, `args` et le reste à l'identique, et en injectant `--project`
   quand le fichier réécrit appartient à un projet identifiable (§6bis rang 1).
4. Installe le hook Claude Code.
5. Affiche un diff avant d'écrire quoi que ce soit.

`mcpwall restore` remet tout en état à partir des sauvegardes, en une commande.

Le binaire est embarqué dans `Contents/Resources/` de l'app, et l'app crée au premier
lancement un lien symbolique stable vers `~/.mcpwall/bin/mcpwall`. Les configs pointent
vers ce lien, jamais vers le chemin du bundle — sinon déplacer l'app casse tout.

**Critère de réussite : zéro terminal requis.**

## 9. UI macOS

- `NSStatusItem` avec un SF Symbol en template image (inversion clair/sombre automatique).
  État gris au repos, badge chiffré quand il y a des blocages du jour.
- Clic gauche : `NSPopover` avec compteurs (appels / bloqués / serveurs actifs, plus le
  compteur d'entrées de journal perdues), les 10 dernières entrées, boutons
  « Tout bloquer », « Journal », réglages.
- **Prompt de décision** : surtout pas un `NSPopover` (il se ferme à la perte de focus et
  ne s'affiche pas au-dessus d'un terminal plein écran). Utiliser un `NSPanel` avec
  `level = .statusBar`, `collectionBehavior` incluant `.canJoinAllSpaces` et
  `.fullScreenAuxiliary`, et `becomesKeyOnlyIfNeeded = true`.
  Le panneau affiche : outil, serveur, extrait des arguments, règle déclenchée, origine
  du taint le cas échéant, le projet **et sa provenance**, et trois boutons
  (Bloquer / Autoriser une fois / Toujours autoriser).
  Le bouton « Toujours autoriser » est masqué si la provenance du scope est de rang 3 ou 4.
- Fenêtre Journal : timeline filtrable par projet, serveur, verdict ; détail JSON déroulant ;
  export JSONL.

Discrétion par défaut : au repos, mcpwall ne demande rien. Seules les règles à haute
confiance déclenchent un `ask`. La fatigue d'alerte est ce qui tue ce genre d'outil.

## 10. Jalons

Travailler jalon par jalon. Ne pas commencer le suivant sans que le précédent tourne
sur une machine réelle.

**M0 — observation seule** *(fait)*
`mcpwall wrap -- <commande>` en stdio, relais transparent, journal SQLite,
`mcpwall log --tail`, `mcpwall log --stats`. Aucun blocage, aucune UI.
Critère : envelopper un serveur filesystem réel dans Claude Code, mener une session
complète sans rien casser, et retrouver tous les appels dans le journal.

- [x] `frame.rs` — découpage, plafond 32 Mo, resynchronisation
- [x] `mcp.rs` — scan de méthode, OBSERVE/DECIDE, point de décision, capture `initialize`
- [x] `scope.rs` — chaîne de provenance, clé de scope, URI de racine
- [x] `wrap.rs` — pompes de relais, voie de retour des blocages
- [x] `session.rs` — fork amont, signaux, EOF, code de sortie
- [x] journal SQLite, deux chemins
- [x] CLI `wrap` / `log --tail` / `log --stats`
- [x] serveurs MCP factices + tests d'intégration sur vrais processus
- [x] benchmark de latence en CI

Latence mesurée en `--release` : **p99 3,4 µs** sur frame courte, 6,1 µs quand la méthode
est repoussée hors fenêtre, 70 µs sur une frame de 100 Ko. Budget 5 ms.

**M1 — daemon + politique** *(fait)*
Daemon avec socket Unix et handshake de version, `policy.yaml`, verdicts allow/deny/ask
(le `ask` répond automatiquement `deny` en attendant l'UI), blocage propre via `isError`,
`mcpwall init` et `restore`.
Critère : une règle bloque une lecture de `.env` sans que la session de l'agent ne casse.

- [x] `ipc.rs` — protocole + handshake de version
- [x] `daemon.rs` — socket Unix, un seul par machine, socket en 0600
- [x] `client.rs` — `DecisionPoint` par-dessus le socket, fail-open par défaut
- [x] `policy.rs` — `policy.yaml`, rechargement à chaud, détection de secrets
- [x] `setup.rs` — `init` avec diff et sauvegardes, `restore`

**M2 — app macOS** *(fait, sauf signature)*
Menu bar, popover, panneau de décision, fenêtre journal, onboarding graphique,
supervision de `mcpwall daemon`, lien symbolique, `.dmg` signé et notarisé, Sparkle.
Critère : installation complète depuis un `.dmg` sur une machine vierge, sans terminal.

- [x] flux de confirmation dans le core : le daemon sait demander, pas seulement refuser
- [x] `NSStatusItem` + popover, badge chiffré uniquement s'il y a des blocages
- [x] panneau de décision en `NSPanel` (voir §9), retrait automatique à l'expiration
- [x] fenêtre Journal filtrable, export JSONL
- [x] onboarding graphique avec diff avant écriture et restauration en un clic
- [x] supervision de `mcpwall daemon` comme processus enfant, avec recul croissant
- [x] lien symbolique refait à chaque lancement
- [x] assemblage du bundle et du `.dmg` sans Xcode (`scripts/build-app.sh`)
- [ ] **signature et notarisation** — script écrit (`scripts/sign-app.sh`) mais
      **jamais exécuté** : aucune identité « Developer ID » disponible. À traiter
      comme non testé tant que quelqu'un ne l'aura pas fait tourner.
- [ ] **Sparkle** — non intégré. `SUFeedURL` est laissé vide dans l'`Info.plist` :
      une URL morte provoquerait une erreur de mise à jour à chaque lancement.
      À brancher quand un flux existera, avec une paire de clés EdDSA.

Le critère de sortie n'est donc **pas atteint** : sans notarisation, Gatekeeper
impose un clic droit → Ouvrir, c'est-à-dire exactement la friction que §8 interdit.

**M3 — profondeur**
Hook Claude Code, taint tracking, détection de dérive des descriptions d'outils,
transport HTTP streamable, export JSONL.

## 11. Tests

- Serveurs MCP factices en Rust pour les tests d'intégration : un normal, un lent,
  un qui renvoie du JSON malformé, un qui mute ses descriptions d'outils entre deux
  `tools/list`.
- Tests de fuzzing sur le parseur de frames : messages coupés en deux, unicode,
  charges utiles de plusieurs mégaoctets. Les modules `frame`, `mcp` et `scope` sont
  sans I/O précisément pour rester fuzzables sans runtime.
- Benchmark de latence en passthrough, dans la CI, avec seuil d'échec.
- Un scénario d'intégration reproduisant l'attaque complète : lecture d'un `.env` puis
  tentative d'envoi via un outil sortant, avec assertion sur le blocage.

## 12. Conventions

- Rust : `#![forbid(unsafe_code)]` dans le core. `clippy -D warnings` en CI.
- Aucun `unwrap()` dans le chemin du shim. Une panique du shim = session d'agent cassée.
- Journalisation structurée via `tracing`. Le journal ne doit jamais contenir la valeur
  d'un secret détecté : on stocke le type et un préfixe tronqué.
- Licence MIT. Pas de GPL, ça freine l'adoption en entreprise qui est la trajectoire
  de sortie naturelle.
- Toute étiquette persistée en base (`ScopeSource::as_str`, identifiants de règles) est un
  contrat : la changer exige une migration.
- README : les trois premières lignes doivent répondre à « mon client me demande déjà
  la permission, pourquoi j'aurais besoin de ça ? ». Réponse : les permissions du client
  sont au niveau de l'outil et disparaissent en auto-accept ; mcpwall filtre au niveau
  du contenu des arguments, persiste un audit entre sessions, et couvre les serveurs
  tiers déjà approuvés une fois pour toutes.

## 13. Consignes de travail

- Avant d'implémenter quoi que ce soit qui touche à la spec MCP, aux hooks Claude Code,
  ou au format des fichiers de configuration des clients : vérifier la documentation
  courante en ligne. Ces formats ont changé récemment et changeront encore.
- Ne pas coder plus de deux fichiers sans s'arrêter pour montrer et faire tourner.
- Si une décision d'architecture a plusieurs options défendables, les exposer avec
  leurs coûts au lieu de choisir silencieusement.

---

## Journal des décisions

**2026-07-27 — Binaire unique.** `mcpwalld` supprimé au profit de `mcpwall daemon`.
Motif : la dérive de version shim/daemon est une classe de bugs réelle, et le lien
symbolique unique simplifie l'onboarding. Compensé par un handshake de version IPC, parce
qu'un client resté ouvert peut faire tourner un vieux shim contre un daemon neuf.

**2026-07-27 — L'app supervise le daemon, ne le réimplémente pas.** Une seule source de
vérité pour politique et taint ; la portabilité Linux reste intacte.

**2026-07-27 — Journal à deux chemins.** Les `deny` et les alertes ne sont jamais jetés :
c'est la ligne que l'utilisateur exportera dans un ticket de sécurité.

**2026-07-27 — Passthrough d'octets, mais point de décision présent dès M0.** Écrire M0
comme « je copie et je parse ailleurs » aurait fait de M1 une réécriture.

**2026-07-27 — Batch JSON-RPC : confirmé retiré** (`2025-06-18`, PR #416). Hypothèse
vérifiée en ligne, pas retenue de mémoire.

**2026-07-27 — L'`initialize` ne porte pas le cwd.** Vérification de la spec
`basic/lifecycle` : `params` contient `protocolVersion`, `capabilities`, `clientInfo`, et
`clientInfo` n'a aucun champ de chemin. Le scoping par projet du brief initial reposait
sur un champ inexistant. D'où la chaîne de provenance §6bis.

**2026-07-27 — `forever` conditionné à la provenance.** Une ligne de code, une classe
entière de bugs de sécurité silencieux évitée.

**2026-07-27 — La provenance n'entre pas dans la clé de scope.** L'alternative produirait
le comportement absurde où l'utilisateur autorise quelque chose, un serveur demande
`roots/list`, et son autorisation disparaît.

**2026-07-27 — OBSERVE et DECIDE séparés structurellement.** `initialize` dans OBSERVE,
verrouillé par un test. Le bloquer ne protège de rien et tue la session entière.

**2026-07-27 — Échappements traversés dans le scan de méthode.** Première version
abandonnait sur le premier `\` ; un `id` contenant `\"` suffisait alors à sortir un
`tools/call` du point de décision. Évasion de politique à un octet.

**2026-07-27 — `Oversize` resynchronise, ne tue pas la connexion.** Le découpeur signale
et repart ; la décision de fatalité appartient à la couche transport. C'est le même
mécanisme qui absorbe un serveur violant la règle du retour ligne.

**2026-07-27 — Le plafond de frame ne s'appliquait qu'en l'absence de délimiteur.** Une
frame surdimensionnée arrivant d'un seul `read()` passait donc au travers : la valeur
effective du plafond dépendait du découpage des lectures. Trouvé par un test d'invariant
rejoué sur plusieurs tailles de morceaux, pas par un test de cas.

**2026-07-27 — Le point de décision est faillible.** `DecisionPoint::decide` rend un
`Result`. Sans ça, un client de socket ne pourrait signaler « daemon injoignable »
qu'en mentant `Allow` ou en paniquant. Tout `Err` devient un `Allow` journalisé, sauf
`fail_closed` explicite.

**2026-07-27 — Le client du daemon vit sur un thread système, pas sur l'exécuteur.**
Retenir une frame impose un verdict synchrone, appelé depuis une pompe async. Si l'I/O du
socket partageait l'exécuteur, l'attente du verdict bloquerait la tâche censée le
produire — interblocage garanti sur un runtime mono-thread.

**2026-07-27 — Une politique vide est refusée.** Tous les champs ayant un défaut, un
fichier vide se désérialisait en `default: allow` sans aucune règle : un `policy.yaml`
tronqué désactivait le pare-feu en silence. Découvert parce qu'un test partageant un
répertoire temporaire est devenu instable.

**2026-07-27 — `init` n'injecte `--project` que là où le projet est connu.** Sous
`projects.<dir>` de `~/.claude.json` et dans un `.mcp.json`, oui. À la racine d'un fichier
global, non : ce serveur est utilisé depuis dix projets, et lui inventer un projet
mentirait sur la provenance — donc débloquerait `forever` à tort.

**2026-07-27 — Le daemon calcule `forever_allowed` et le transmet.** L'UI n'a pas à
refaire le raisonnement sur la provenance, et ne peut donc pas se tromper en le refaisant.

**2026-07-27 — Protocole IPC passé en version 2.** Le flux de confirmation change la
forme des messages, désormais étiquetés par un champ `type`. Rien n'étant publié,
personne n'en souffre — et c'est le mécanisme qui protégera les mises à jour suivantes.

**2026-07-27 — L'UI est un client, pas une autorité.** Le daemon rétrograde une portée
`forever` demandée sur un scope de provenance faible, même si l'interface l'a envoyée.
Une interface compromise ou boguée ne doit pas pouvoir accorder plus que la provenance
ne le permet.

**2026-07-27 — Le shim dérive son délai de celui annoncé par le daemon.** Défaut le plus
grave de M2, et invisible tant que l'interface n'existait pas : le shim abandonnait après
5 s de délai de socket pendant que le daemon attendait le clic. Or **abandonner laisse
passer** — toute règle `ask` se dégradait en `allow` dès que la personne réfléchissait
plus de cinq secondes. Le `Hello` du daemon porte maintenant `ask_timeout_seconds`.

**2026-07-27 — `FileHandle` remplacé par les appels système côté Swift.** Son écriture
bloquait indéfiniment sur un socket Unix : quarante octets qui ne partaient jamais, sans
erreur ni trace. `FileHandle` est conçu pour les fichiers et les tubes.

**2026-07-27 — L'abonnement est écrit sur le chemin du handshake.** Le faire passer par
la file d'écriture le perdait, et l'app tournait sans jamais recevoir de demande — le
daemon refusait alors chaque `ask` en expliquant qu'aucune interface n'était là.

**2026-07-27 — Le bundle est assemblé à la main, sans projet Xcode.** Construction
identique en CI et sur une machine n'ayant que les Command Line Tools. Le build universel
exige néanmoins Xcode : le script dégrade en architecture native avec un avertissement,
et la CI vérifie que les binaires publiés sont bien universels.
