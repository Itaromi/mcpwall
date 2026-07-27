# mcpwall

**« Mon client me demande déjà la permission, pourquoi j'aurais besoin de ça ? »**
Parce que les permissions de votre client sont au niveau de l'outil et disparaissent en
auto-accept. mcpwall filtre au niveau du **contenu des arguments**, persiste un **audit
entre sessions**, et couvre les **serveurs tiers déjà approuvés** une fois pour toutes.

Un pare-feu applicatif local pour agents de code. Little Snitch, mais pour les appels
d'outils d'agents IA.

---

## Le problème

Vous lancez votre agent en auto-accept. Une issue GitHub, une page web ou un e-mail
contient une injection de prompt. L'agent lit un secret local, puis tente de l'envoyer
vers un outil réseau. Votre client ne voit qu'une suite d'appels d'outils déjà autorisés.

mcpwall s'intercale entre les clients MCP et les serveurs MCP, journalise tout le trafic
JSON-RPC, et bloque selon une politique locale.

## Couverture — ce que mcpwall voit, et ce qu'il ne voit pas

L'honnêteté sur la couverture est un argument de crédibilité.

| | Couvert |
| --- | --- |
| Serveurs MCP en stdio | oui |
| Serveurs MCP en HTTP streamable | prévu (M3) |
| Outils intégrés de Claude Code (`Read`, `Edit`, `Bash`, `WebFetch`) | via hook `PreToolUse` (M3) |
| Outils intégrés de Codex | **non** — son modèle de sécurité passe par le sandbox |
| Cursor | trafic MCP uniquement |

Un proxy MCP ne voit que le trafic MCP. Pour Claude Code, les outils intégrés
représentent l'essentiel de la surface d'attaque : c'est le hook qui les couvre, pas le
proxy.

## État

Jalons M0, M1 et M2 faits : relais stdio, journal, daemon de politique,
`init`/`restore`, et l'application macOS — barre de menus, panneau de décision,
fenêtre journal, installation graphique.

**Il n'y a pas encore de version distribuable.** Le `.dmg` n'est ni signé ni
notarisé, donc Gatekeeper impose un clic droit → Ouvrir. Sparkle n'est pas
branché. Voir [SPEC.md](SPEC.md) §10 pour ce qui reste, et pour l'architecture
et les décisions prises avec leurs raisons.

## Construire et essayer

```sh
# L'application, avec le core embarqué
./scripts/build-app.sh
open build/mcpwall.app
```

L'app lance le daemon, crée le lien symbolique vers le binaire, et propose
l'installation dans vos clients MCP au premier lancement — avec le diff de ce
qui va changer, avant d'écrire quoi que ce soit.

En ligne de commande seule, sans interface :

```sh
cargo build --release

# 1. le daemon, qui écrit une politique par défaut au premier lancement
./target/release/mcpwall daemon &

# 2. voir ce qu'init ferait à vos configurations — rien n'est écrit sans --apply
./target/release/mcpwall init

# 3. l'appliquer, puis redémarrer vos clients MCP
./target/release/mcpwall init --apply

# 4. regarder passer le trafic
./target/release/mcpwall log --follow
./target/release/mcpwall log --stats
```

`mcpwall restore` remet toutes les configurations en état depuis les sauvegardes.

La politique vit dans `~/.mcpwall/policy.yaml` et se recharge à chaud.
Par défaut elle laisse tout passer sauf l'accès aux chemins de secrets et les
identifiants repérés dans les arguments.

Sans l'application, une règle `ask` **bloque** au lieu de demander : personne
n'est là pour confirmer. Le message renvoyé à l'agent le dit explicitement.

## Principes

- **Local-first.** Aucune télémétrie, aucun compte, aucune requête sortante hors
  vérification de mise à jour.
- **Déterministe.** Pas d'analyse LLM des appels. La politique est un fichier lisible.
- **Disponible par défaut.** Si le daemon est injoignable, le trafic passe. Casser tous
  les serveurs MCP de l'utilisateur parce qu'on a fermé une app est un défaut, pas une
  posture de sécurité.
- **Discret.** Seules les règles à haute confiance interrompent. La fatigue d'alerte tue
  ce genre d'outil.

## Développement

```sh
cargo test                                    # 167 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --release --test bench -- --nocapture   # latence, seuil 5 ms p99

cd app && swift build                         # l'application
```

Le build universel de l'app exige Xcode ; avec les seuls Command Line Tools,
`scripts/build-app.sh` dégrade en architecture native et vous prévient. La CI
vérifie que les binaires publiés sont bien universels.

## Licence

MIT.
