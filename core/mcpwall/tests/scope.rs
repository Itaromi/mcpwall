//! Tests de résolution de scope.
//!
//! Le test qui compte est [`forever_refuse_en_provenance_faible`] : c'est lui
//! qui empêche une permission permanente de fuir d'un projet à l'autre.

use mcpwall::scope::{Scope, ScopeResolver, ScopeSource, canonicalize_for_scope, parse_root_uri};
use std::path::PathBuf;

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

// --- Chaîne de précédence ---

#[test]
fn injected_bat_tout() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/tmp/ailleurs"));
    r.observe_roots([p("/home/u/roots")]);
    r.set_injected(p("/home/u/monrepo"));

    let s = r.resolve();
    assert_eq!(s.source(), ScopeSource::Injected);
    assert_eq!(s.paths(), [p("/home/u/monrepo")]);
}

#[test]
fn roots_bat_le_cwd() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/tmp/ailleurs"));
    r.observe_roots([p("/home/u/projet")]);

    let s = r.resolve();
    assert_eq!(s.source(), ScopeSource::Roots);
    assert_eq!(s.paths(), [p("/home/u/projet")]);
}

#[test]
fn cwd_en_dernier_recours() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/home/u/quelquepart"));
    assert_eq!(r.resolve().source(), ScopeSource::Cwd);
}

#[test]
fn aucun_signal_donne_unknown_pas_une_supposition() {
    let s = ScopeResolver::new().resolve();
    assert_eq!(s.source(), ScopeSource::Unknown);
    assert!(s.paths().is_empty());
    assert_eq!(s.key(), "unknown");
}

#[test]
fn le_scope_peut_monter_en_cours_de_session() {
    // Serveur configuré globalement dans ~/.claude.json : `init` n'a pas pu y
    // écrire de --project. On démarre en cwd, puis un serveur amont demande
    // roots/list et on monte au maillon 2.
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/home/u/quelquepart"));

    let avant = r.resolve();
    assert_eq!(avant.source(), ScopeSource::Cwd);
    assert!(!avant.allows_forever());

    r.observe_roots([p("/home/u/vrai-projet")]);

    let apres = r.resolve();
    assert_eq!(apres.source(), ScopeSource::Roots);
    assert!(apres.allows_forever());
    assert!(
        apres.source().rank() < avant.source().rank(),
        "la provenance doit monter, jamais descendre"
    );
}

#[test]
fn list_changed_remplace_au_lieu_de_fusionner() {
    // Fusionner ferait couvrir au scope des répertoires que le client n'expose
    // plus.
    let mut r = ScopeResolver::new();
    r.observe_roots([p("/a"), p("/b")]);
    r.observe_roots([p("/c")]);
    assert_eq!(r.resolve().paths(), [p("/c")]);
}

#[test]
fn roots_vides_ne_masquent_pas_le_cwd() {
    let mut r = ScopeResolver::new();
    r.set_cwd(p("/home/u/projet"));
    r.observe_roots(Vec::new());
    assert_eq!(r.resolve().source(), ScopeSource::Cwd);
}

// --- La garde `forever` ---

#[test]
fn forever_refuse_en_provenance_faible() {
    // Le contrôle de sécurité central : en cwd ou unknown, la sémantique du
    // chemin dépend du client, donc `forever` fuirait vers d'autres projets.
    assert!(!Scope::new(ScopeSource::Cwd, [p("/x")]).allows_forever());
    assert!(!Scope::unknown().allows_forever());

    assert!(Scope::new(ScopeSource::Injected, [p("/x")]).allows_forever());
    assert!(Scope::new(ScopeSource::Roots, [p("/x")]).allows_forever());
}

#[test]
fn ordre_de_precedence_stable() {
    assert!(ScopeSource::Injected.rank() < ScopeSource::Roots.rank());
    assert!(ScopeSource::Roots.rank() < ScopeSource::Cwd.rank());
    assert!(ScopeSource::Cwd.rank() < ScopeSource::Unknown.rank());
}

#[test]
fn etiquettes_de_provenance_persistees() {
    // Ces chaînes partent en base. Les changer sans migration casse les
    // overrides existants.
    assert_eq!(ScopeSource::Injected.as_str(), "injected");
    assert_eq!(ScopeSource::Roots.as_str(), "roots");
    assert_eq!(ScopeSource::Cwd.as_str(), "cwd");
    assert_eq!(ScopeSource::Unknown.as_str(), "unknown");
}

// --- Normalisation de l'ensemble ---

#[test]
fn les_racines_sont_triees_et_dedupliquees() {
    // roots est un ensemble : l'ordre d'arrivée ne doit pas changer la clé.
    let a = Scope::new(ScopeSource::Roots, [p("/b"), p("/a"), p("/b")]);
    let b = Scope::new(ScopeSource::Roots, [p("/a"), p("/b")]);
    assert_eq!(a.key(), b.key());
    assert_eq!(a.paths(), [p("/a"), p("/b")]);
}

#[test]
fn clef_lisible_pour_une_racine_unique() {
    let s = Scope::new(ScopeSource::Injected, [p("/Users/marc/monrepo")]);
    assert_eq!(s.key(), "project:/Users/marc/monrepo");
}

#[test]
fn monorepo_multi_racines() {
    let s = Scope::new(
        ScopeSource::Roots,
        [p("/repos/frontend"), p("/repos/backend")],
    );
    assert_eq!(s.paths().len(), 2);
    assert_eq!(s.display(), "/repos/backend, /repos/frontend");
    assert_ne!(
        s.key(),
        Scope::new(ScopeSource::Roots, [p("/repos/backend")]).key(),
        "un sous-ensemble ne doit pas collisionner avec l'ensemble"
    );
}

#[test]
fn provenance_absente_de_la_clef() {
    // Une session qui monte de cwd à roots doit retomber sur les mêmes règles,
    // pas en créer un jeu parallèle.
    let cwd = Scope::new(ScopeSource::Cwd, [p("/home/u/projet")]);
    let roots = Scope::new(ScopeSource::Roots, [p("/home/u/projet")]);
    assert_eq!(cwd.key(), roots.key());
    assert_ne!(cwd.allows_forever(), roots.allows_forever());
}

#[test]
fn provenance_sans_chemin_retombe_sur_unknown() {
    let s = Scope::new(ScopeSource::Injected, Vec::new());
    assert_eq!(s.source(), ScopeSource::Unknown);
    assert!(!s.allows_forever());
}

// --- URI de racine ---

#[test]
fn uri_file_nominale() {
    // Forme exacte de la spec, client/roots.
    assert_eq!(
        parse_root_uri("file:///home/user/projects/myproject"),
        Some(p("/home/user/projects/myproject"))
    );
}

#[test]
fn uri_avec_espaces_encodes() {
    assert_eq!(
        parse_root_uri("file:///Users/marc/Mon%20Projet"),
        Some(p("/Users/marc/Mon Projet"))
    );
}

#[test]
fn uri_utf8_encode() {
    assert_eq!(
        parse_root_uri("file:///Users/marc/caf%C3%A9"),
        Some(p("/Users/marc/café"))
    );
}

#[test]
fn schema_insensible_a_la_casse() {
    assert_eq!(parse_root_uri("FILE:///a/b"), Some(p("/a/b")));
}

#[test]
fn autorite_localhost_acceptee() {
    assert_eq!(parse_root_uri("file://localhost/a/b"), Some(p("/a/b")));
}

#[test]
fn hote_distant_refuse() {
    // Une racine sur une autre machine n'est pas un chemin local et ne doit pas
    // devenir une clé de permission.
    assert_eq!(parse_root_uri("file://ailleurs.example/a/b"), None);
}

#[test]
fn schemas_non_file_refuses() {
    for uri in [
        "https://example.com/a",
        "git+ssh://host/repo",
        "s3://bucket/key",
        "/pas/une/uri",
        "",
    ] {
        assert_eq!(parse_root_uri(uri), None, "{uri}");
    }
}

#[test]
fn barre_finale_normalisee() {
    // Sinon la même racine donne deux clés de scope selon le client.
    assert_eq!(
        parse_root_uri("file:///home/u/projet/"),
        parse_root_uri("file:///home/u/projet")
    );
    assert_eq!(parse_root_uri("file:///"), Some(p("/")));
}

#[test]
fn encodage_malforme_refuse() {
    for uri in ["file:///a/%zz", "file:///a/%2", "file:///a/%"] {
        assert_eq!(parse_root_uri(uri), None, "{uri}");
    }
}

#[test]
fn octet_nul_encode_refuse() {
    assert_eq!(parse_root_uri("file:///a/%00/b"), None);
}

#[test]
fn requete_et_fragment_ignores() {
    assert_eq!(parse_root_uri("file:///a/b?x=1"), Some(p("/a/b")));
    assert_eq!(parse_root_uri("file:///a/b#frag"), Some(p("/a/b")));
}

// --- Canonicalisation ---

#[test]
fn canonicalisation_resout_les_liens_symboliques() {
    // Sur macOS /tmp est un lien vers /private/tmp. Sans canonicalisation, les
    // clés de scope ne correspondent pas d'une session à l'autre.
    let tmp = p("/tmp");
    if tmp.exists() {
        let canon = canonicalize_for_scope(&tmp);
        assert!(canon.is_absolute());
        assert_eq!(
            canon,
            canonicalize_for_scope(&p("/tmp/../tmp")),
            "deux écritures du même répertoire doivent donner la même clé"
        );
    }
}

#[test]
fn canonicalisation_dun_chemin_inexistant_ne_panique_pas() {
    // Dégrader le regroupement est acceptable ; casser la session de l'agent ne
    // l'est pas.
    let absent = p("/ce/chemin/nexiste/pas/j/espere");
    assert_eq!(canonicalize_for_scope(&absent), absent);
}
