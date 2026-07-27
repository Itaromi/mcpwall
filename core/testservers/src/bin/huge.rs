//! Serveur qui répond une charge utile de 8 Mo.
//!
//! Vérifie l'absence d'interblocage par contre-pression : le shim doit drainer
//! ce flux sans que l'autre direction cesse de progresser.

fn main() {
    while let Some(line) = testservers::read_line() {
        let Some(v) = testservers::parse(&line) else {
            continue;
        };
        let Some(id) = v.get("id").cloned() else {
            continue;
        };
        let blob = "z".repeat(8 * 1024 * 1024);
        testservers::write_line(
            &serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [{ "type": "text", "text": blob }] }
            })
            .to_string(),
        );
    }
}
