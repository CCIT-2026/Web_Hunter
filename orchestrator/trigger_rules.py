"""
trigger_rules.py — tabella dichiarativa di attivazione condizionale dei moduli.

Contratto di lettura: ogni predicato riceve il dict caricato da
schemas/detected_stack.schema.json (detected_stack.json) e restituisce bool.
Nessun runner reimplementa la propria detection: il gating vive TUTTO qui, come
dati, non come if/else sparsi nei runner.

Uso tipico dall'orchestratore:

    stack = json.load(open("reports/<svc>/detected_stack.json"))
    for name in modules_to_run(stack):
        run_module(name)

Regole:
- I moduli in ALWAYS_RUN girano sempre (nessun gating): mapping, semgrep, ripgrep.
  Il mapping in particolare gira SEMPRE per primo perche' produce gli artefatti
  (endpoints_map.json + detected_stack.json) su cui si basa tutto il resto.
- jwt_tool e' un caso speciale: si attiva solo se ESISTE almeno una verifica JWT
  marcata looks_weak nel detected_stack. Se tutte robuste, il modulo NON gira e
  il suo runner scrive comunque un report status='skipped' con skip_reason che
  cita file:riga della verifica robusta ("skip: verifica JWT robusta, vedi ...").
- nosqli si attiva solo su NoSQL puro (has_nosql AND NOT has_sql_queries): se c'e'
  SQL si preferiscono sqlmap/ghauri.
- I runner "generic_category" coprono categorie della payload library senza tool
  dedicato (SSRF, GraphQL, XPath, Directory Traversal, LDAP): stesso pattern di
  gating, guidato dai rispettivi *_locations nel detected_stack.

Tutti gli accessi usano .get(..., default) cosi' un detected_stack privo di un
flag futuro non fa crashare l'orchestratore (fallisce chiuso: modulo non gira).
"""

# Moduli senza condizione di gating: girano sempre.
# (mapping produce i contratti dati, quindi va schedulato per primo dall'orchestratore.)
ALWAYS_RUN = (
    "mapping",
    "semgrep",
    "ripgrep",
)


def _any_weak_jwt(stack):
    return any(
        loc.get("looks_weak", False)
        for loc in stack.get("jwt_verification_locations", [])
    )


# Tabella trigger -> predicato(stack) -> bool.
# Chiave = nome modulo/runner, coincide con il campo "module" del report prodotto.
TRIGGERS = {
    # --- lang/stack specific ---
    "phpggc":     lambda s: s.get("has_php", False),
    "symfony":    lambda s: s.get("has_symfony_twig", False),
    "fickling":   lambda s: s.get("language") == "python" and s.get("has_eval_on_input", False),
    "nodejsscan": lambda s: s.get("language") == "javascript",
    "grpcurl":    lambda s: s.get("has_grpc", False),

    # --- upload & file ---
    # slipit: qualsiasi upload. exiftool: upload di file eseguibili (accepts_executable).
    # polyglot: complemento sempre disponibile quando c'e' upload.
    "slipit":     lambda s: s.get("has_file_upload", False),
    "exiftool":   lambda s: s.get("has_file_upload", False)
                            and any(loc.get("accepts_executable", False)
                                    for loc in s.get("file_upload_locations", [])),
    "polyglot":   lambda s: s.get("has_file_upload", False),

    # --- injection: SQL / NoSQL ---
    "sqlmap":     lambda s: s.get("has_sql_queries", False),
    "ghauri":     lambda s: s.get("has_sql_queries", False),
    "nosqli":     lambda s: s.get("has_nosql", False) and not s.get("has_sql_queries", False),

    # --- injection: template / command (complemento tool-based, guidati dal mapping) ---
    # sstimap/commix non hanno un flag booleano dedicato nello stack: si attivano
    # se il mapping ha trovato endpoint con parametri, e pescano payload mirati.
    # Restano gestiti dai loro runner via payload library; qui NON forziamo gating
    # falso: si abilitano solo se esiste almeno un endpoint con parametri.
    # (l'orchestratore passa endpoints_map ai runner; il gating fine sta nel runner)

    # --- auth ---
    "jwt_tool":   lambda s: s.get("uses_jwt", False) and _any_weak_jwt(s),

    # --- discovery gated ---
    "trufflehog": lambda s: s.get("db_present_in_domain", False),
    "gitleaks":   lambda s: s.get("db_present_in_domain", False),

    # --- categorie payload library senza tool dedicato (generic_category_runner) ---
    "ssrf_generic":       lambda s: s.get("has_outbound_request_on_input", False),
    "graphql_generic":    lambda s: s.get("has_graphql_endpoint", False),
    "xpath_generic":      lambda s: s.get("has_xpath_parser", False),
    "directory_traversal": lambda s: s.get("has_file_path_from_input", False),
    "ldap_generic":       lambda s: s.get("has_ldap_query", False),
}


# Discovery non gated che gira comunque quando disponibile ma non e' "core":
# jsluice e nuclei girano sempre (ricognizione generica), quindi vivono in
# ALWAYS_RUN-like ma li teniamo separati perche' NON producono lo stack.
# Li elenchiamo esplicitamente per l'orchestratore.
UNGATED_DISCOVERY = (
    "jsluice",
    "nuclei",
    "xxeexploiter",  # gira sempre: complemento payload library per XXE, gating fine nel runner
)


def modules_to_run(stack):
    """Ritorna l'elenco ordinato dei moduli da eseguire per un dato detected_stack.

    Ordine: ALWAYS_RUN (mapping per primo) -> discovery ungated -> moduli gated
    che passano il predicato. L'orchestratore applica poi il proprio scheduling
    parallelo/lock; questo elenco e' solo l'insieme "cosa e' pertinente".
    """
    selected = list(ALWAYS_RUN) + list(UNGATED_DISCOVERY)
    selected += [name for name, pred in TRIGGERS.items() if pred(stack)]
    return selected


def skipped_modules(stack):
    """Moduli gated il cui predicato e' falso: l'orchestratore ne traccia il
    motivo (audit). Ritorna dict {modulo: 'skip: trigger non soddisfatto'}."""
    return {
        name: "skip: trigger non soddisfatto (detected_stack)"
        for name, pred in TRIGGERS.items()
        if not pred(stack)
    }
