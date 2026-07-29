use duckdb::{Connection, types::Value};

/// A Splunk-inspired v1 search grammar (Milestone 12) — whitespace-separated
/// terms, implicit `AND`, explicit `OR`, `NOT`/`-` negation, `field=value` /
/// `field:value` for exact filters, `field~value` for regex, quoted phrases,
/// bare words as free text against `message` and `raw`. Left-associative,
/// no parentheses, no operator precedence — see the `search-grammar-roadmap`
/// project note for what's deliberately deferred to a later milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Level,
    Source,
    Tag,
    Message,
    Raw,
}

impl Field {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "level" => Some(Self::Level),
            "source" | "sourcetype" => Some(Self::Source),
            "tag" => Some(Self::Tag),
            "message" => Some(Self::Message),
            "raw" => Some(Self::Raw),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TermKind {
    /// Bare word or quoted phrase without a recognized `field=`/`field:`/
    /// `field~` prefix — substring match against `message` OR `raw`. Also
    /// the fallback when a `word=...` prefix doesn't match a known field
    /// name, so a typo degrades to "search for this literally" rather than
    /// a hard parse error.
    FreeText(String),
    Field {
        field: Field,
        value: String,
        is_regex: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    /// Connector joining this term to the accumulated result of every term
    /// before it. Ignored for the first term.
    pub connector: Connector,
    pub negate: bool,
    pub kind: TermKind,
}

/// A parsed query: a flat, left-associative sequence of [`Term`]s.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Query {
    pub terms: Vec<Term>,
}

impl Query {
    pub fn parse(input: &str) -> Self {
        let mut terms = Vec::new();
        let mut connector = Connector::And;
        let mut negate = false;

        for token in tokenize(input) {
            match token.to_ascii_uppercase().as_str() {
                "OR" => {
                    connector = Connector::Or;
                    continue;
                }
                "AND" => {
                    connector = Connector::And;
                    continue;
                }
                "NOT" => {
                    negate = true;
                    continue;
                }
                _ => {}
            }

            let (negate_prefix, raw) = match token.strip_prefix('-') {
                Some(rest) if !rest.is_empty() => (true, rest),
                _ => (false, token.as_str()),
            };

            terms.push(Term {
                connector,
                negate: negate || negate_prefix,
                kind: parse_term_kind(raw),
            });
            connector = Connector::And;
            negate = false;
        }

        Self { terms }
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }
}

/// Splits `input` on whitespace, treating `"..."` as one token (quotes
/// dropped, spaces inside preserved) — so `field="a b"` and `"a b"` each
/// become a single raw token.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in input.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parse_term_kind(raw: &str) -> TermKind {
    if let Some((idx, sep)) = raw
        .char_indices()
        .find(|(_, c)| matches!(c, '=' | ':' | '~'))
    {
        let field_str = &raw[..idx];
        let value = &raw[idx + sep.len_utf8()..];
        if let Some(field) = Field::parse(field_str) {
            return TermKind::Field {
                field,
                value: value.to_string(),
                is_regex: sep == '~',
            };
        }
    }
    TermKind::FreeText(raw.to_string())
}

fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

struct CompiledQuery {
    from: String,
    where_clause: Option<String>,
    params: Vec<Value>,
}

impl Query {
    fn compile(&self) -> CompiledQuery {
        let needs_sources_join = self.terms.iter().any(|t| {
            matches!(
                t.kind,
                TermKind::Field {
                    field: Field::Source,
                    ..
                }
            )
        });

        let mut from = "log_entries AS le".to_string();
        if needs_sources_join {
            from.push_str(" JOIN sources AS s ON le.event_id_source = s.source_file_id");
        }

        let mut params = Vec::new();
        let mut where_clause: Option<String> = None;
        for term in &self.terms {
            let (mut fragment, term_params) = compile_term_kind(&term.kind);
            if term.negate {
                fragment = format!("NOT ({fragment})");
            }
            where_clause = Some(match where_clause {
                None => fragment,
                Some(prev) => {
                    let op = match term.connector {
                        Connector::And => "AND",
                        Connector::Or => "OR",
                    };
                    format!("({prev}) {op} ({fragment})")
                }
            });
            params.extend(term_params);
        }

        CompiledQuery {
            from,
            where_clause,
            params,
        }
    }
}

/// `EXISTS` subquery rather than a `JOIN import_tags`: one entry can have
/// several tags, and a join would fan out into duplicate rows per matching
/// tag. `sources` is safe to `JOIN` instead since `source_file_id` is its
/// primary key — at most one match per entry, no fan-out possible.
fn compile_term_kind(kind: &TermKind) -> (String, Vec<Value>) {
    match kind {
        TermKind::FreeText(text) => {
            let pattern = Value::Text(format!("%{}%", escape_like(text)));
            (
                "(le.message LIKE ? ESCAPE '\\' OR le.raw LIKE ? ESCAPE '\\')".to_string(),
                vec![pattern.clone(), pattern],
            )
        }
        TermKind::Field {
            field: Field::Tag,
            value,
            is_regex,
        } => {
            let predicate = if *is_regex {
                "regexp_matches(it.tag_value, ?)"
            } else {
                "it.tag_value = ?"
            };
            (
                format!(
                    "EXISTS (SELECT 1 FROM import_tags AS it \
                     WHERE it.event_id_source = le.event_id_source \
                     AND it.event_id_seq = le.event_id_seq AND {predicate})"
                ),
                vec![Value::Text(value.clone())],
            )
        }
        TermKind::Field {
            field,
            value,
            is_regex,
        } => {
            let column = match field {
                Field::Level => "le.level",
                Field::Source => "s.sourcetype",
                Field::Message => "le.message",
                Field::Raw => "le.raw",
                Field::Tag => unreachable!("handled above"),
            };
            if *is_regex {
                (
                    format!("regexp_matches({column}, ?)"),
                    vec![Value::Text(value.clone())],
                )
            } else {
                match field {
                    Field::Level | Field::Source => {
                        (format!("{column} = ?"), vec![Value::Text(value.clone())])
                    }
                    Field::Message | Field::Raw => (
                        format!("{column} LIKE ? ESCAPE '\\'"),
                        vec![Value::Text(format!("%{}%", escape_like(value)))],
                    ),
                    Field::Tag => unreachable!("handled above"),
                }
            }
        }
    }
}

/// One row as shown in the timeline table.
pub struct DisplayRow {
    pub timestamp_utc: String,
    pub level: String,
    pub message: String,
}

/// Distinct, non-null `level` values currently in `log_entries` — used to
/// populate the quick level-filter buttons with whatever this particular
/// loaded source actually uses (AUL's `LogType` names vs. a text log's
/// ERROR/WARN/INFO have nothing in common).
pub fn distinct_levels(conn: &Connection) -> anyhow::Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT DISTINCT level FROM log_entries WHERE level IS NOT NULL ORDER BY level")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn count_matching(conn: &Connection, query: &Query) -> anyhow::Result<usize> {
    let compiled = query.compile();
    let sql = match &compiled.where_clause {
        Some(w) => format!("SELECT COUNT(*) FROM {} WHERE {w}", compiled.from),
        None => format!("SELECT COUNT(*) FROM {}", compiled.from),
    };
    let count: i64 = conn.query_row(&sql, duckdb::params_from_iter(&compiled.params), |row| {
        row.get(0)
    })?;
    Ok(count as usize)
}

pub fn fetch_window(
    conn: &Connection,
    query: &Query,
    offset: usize,
    limit: usize,
) -> anyhow::Result<Vec<DisplayRow>> {
    let compiled = query.compile();
    let where_sql = compiled
        .where_clause
        .as_deref()
        .map(|w| format!("WHERE {w}"))
        .unwrap_or_default();
    let sql = format!(
        "SELECT le.timestamp_utc, le.level, le.message
         FROM {}
         {where_sql}
         ORDER BY le.timestamp_utc, le.event_id_source, le.event_id_seq
         LIMIT ? OFFSET ?",
        compiled.from
    );

    let mut params = compiled.params;
    params.push(Value::BigInt(limit as i64));
    params.push(Value::BigInt(offset as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(duckdb::params_from_iter(&params), |row| {
        let timestamp_utc: chrono::NaiveDateTime = row.get(0)?;
        let level: Option<String> = row.get(1)?;
        let message: Option<String> = row.get(2)?;
        Ok(DisplayRow {
            timestamp_utc: timestamp_utc.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            level: level.unwrap_or_default(),
            message: message.unwrap_or_default(),
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_words_are_free_text_anded_together() {
        let query = Query::parse("hello world");
        assert_eq!(
            query.terms,
            vec![
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::FreeText("hello".to_string())
                },
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::FreeText("world".to_string())
                },
            ]
        );
    }

    #[test]
    fn quoted_phrase_is_one_free_text_term() {
        let query = Query::parse(r#"source=evtx "failed login""#);
        assert_eq!(
            query.terms,
            vec![
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::Field {
                        field: Field::Source,
                        value: "evtx".to_string(),
                        is_regex: false
                    }
                },
                Term {
                    connector: Connector::And,
                    negate: false,
                    kind: TermKind::FreeText("failed login".to_string())
                },
            ]
        );
    }

    #[test]
    fn field_filters_recognize_equals_and_colon() {
        assert_eq!(
            Query::parse("level=ERROR").terms[0].kind,
            TermKind::Field {
                field: Field::Level,
                value: "ERROR".to_string(),
                is_regex: false
            }
        );
        assert_eq!(
            Query::parse("level:ERROR").terms[0].kind,
            TermKind::Field {
                field: Field::Level,
                value: "ERROR".to_string(),
                is_regex: false
            }
        );
    }

    #[test]
    fn tilde_means_regex() {
        assert_eq!(
            Query::parse("message~^ERROR.*").terms[0].kind,
            TermKind::Field {
                field: Field::Message,
                value: "^ERROR.*".to_string(),
                is_regex: true
            }
        );
    }

    #[test]
    fn unrecognized_field_name_falls_back_to_free_text() {
        assert_eq!(
            Query::parse("bogus=foo").terms[0].kind,
            TermKind::FreeText("bogus=foo".to_string())
        );
    }

    #[test]
    fn dash_prefix_and_not_keyword_both_negate() {
        let query = Query::parse("-level=INFO NOT tag=noise");
        assert!(query.terms[0].negate);
        assert!(query.terms[1].negate);
    }

    #[test]
    fn or_keyword_sets_the_next_terms_connector() {
        let query = Query::parse("level=ERROR OR level=FATAL");
        assert_eq!(query.terms[0].connector, Connector::And);
        assert_eq!(query.terms[1].connector, Connector::Or);
    }

    #[test]
    fn empty_query_has_no_terms() {
        assert!(Query::parse("   ").is_empty());
    }

    #[test]
    fn compiling_escapes_like_wildcards_in_free_text() {
        let compiled = Query::parse("50%").compile();
        assert!(compiled.where_clause.unwrap().contains("ESCAPE"));
        assert_eq!(compiled.params[0], Value::Text("%50\\%%".to_string()));
    }

    #[test]
    fn tag_filter_compiles_to_an_exists_subquery_not_a_join() {
        let compiled = Query::parse("tag=auth_failure").compile();
        assert!(!compiled.from.contains("import_tags"));
        assert!(compiled.where_clause.unwrap().contains("EXISTS"));
    }

    #[test]
    fn source_filter_adds_a_sources_join() {
        let compiled = Query::parse("source=evtx").compile();
        assert!(compiled.from.contains("JOIN sources"));
    }

    #[test]
    fn left_associative_and_or_is_explicitly_parenthesized() {
        let compiled = Query::parse("level=ERROR level=WARN OR level=INFO").compile();
        let where_sql = compiled.where_clause.unwrap();
        // (a) AND (b), then wrapped again for the OR: ((a) AND (b)) OR (c)
        assert!(where_sql.starts_with('('));
        assert!(where_sql.contains(") OR ("));
    }

    mod against_real_data {
        use super::*;
        use crate::db::timeline_schema::setup_timeline_schema;
        use crate::model::event_id::{EventId, SequenceCounter, SourceFileId};
        use chrono::Utc;

        fn open_test_db() -> Connection {
            let conn = Connection::open_in_memory().unwrap();
            setup_timeline_schema(&conn).unwrap();
            conn
        }

        fn insert_source(conn: &Connection, source_file_id: SourceFileId, sourcetype: &str) {
            conn.execute(
                "INSERT INTO sources (source_file_id, path, sourcetype, original_tz, parser_config)
                 VALUES (?, '/evidence/test.log', ?, NULL, NULL)",
                duckdb::params![source_file_id.to_string(), sourcetype],
            )
            .unwrap();
        }

        fn insert_entry(
            conn: &Connection,
            event_id: EventId,
            level: &str,
            message: &str,
            raw: &str,
        ) {
            conn.execute(
                "INSERT INTO log_entries
                    (event_id_source, event_id_seq, timestamp_utc, level, message, raw, fields)
                 VALUES (?, ?, ?, ?, ?, ?, '{}')",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    Utc::now().naive_utc(),
                    level,
                    message,
                    raw,
                ],
            )
            .unwrap();
        }

        fn insert_tag(conn: &Connection, event_id: EventId, tag_value: &str) {
            conn.execute(
                "INSERT INTO import_tags (event_id_source, event_id_seq, rule_name, tag_value, applied_at)
                 VALUES (?, ?, 'rule', ?, ?)",
                duckdb::params![
                    event_id.source_file_id.to_string(),
                    event_id.sequence_number.value() as i64,
                    tag_value,
                    Utc::now().naive_utc(),
                ],
            )
            .unwrap();
        }

        #[test]
        fn free_text_matches_message_or_raw() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "connection refused",
                "raw line one",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "all good",
                "raw line two",
            );

            let query = Query::parse("refused");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
            let rows = fetch_window(&conn, &query, 0, 10).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].message, "connection refused");
        }

        #[test]
        fn level_filter_is_exact_match() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "a",
                "a",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERRORISH",
                "b",
                "b",
            );

            let query = Query::parse("level=ERROR");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn source_filter_matches_via_join() {
            let conn = open_test_db();
            let aul_source = SourceFileId::new_random();
            let evtx_source = SourceFileId::new_random();
            insert_source(&conn, aul_source, "aul");
            insert_source(&conn, evtx_source, "evtx");
            insert_entry(
                &conn,
                EventId {
                    source_file_id: aul_source,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "INFO",
                "a",
                "a",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id: evtx_source,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "INFO",
                "b",
                "b",
            );

            let query = Query::parse("source=evtx");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn tag_filter_matches_and_does_not_duplicate_multi_tagged_entries() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "aul");
            let event_id = EventId {
                source_file_id,
                sequence_number: SequenceCounter::new().next_sequence_number(),
            };
            insert_entry(&conn, event_id, "ERROR", "a", "a");
            insert_tag(&conn, event_id, "auth_failure");
            insert_tag(&conn, event_id, "reviewed");

            let query = Query::parse("tag=auth_failure");
            assert_eq!(
                count_matching(&conn, &query).unwrap(),
                1,
                "multiple tags on one entry must not duplicate it"
            );
        }

        #[test]
        fn not_excludes_matching_entries() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "ERROR",
                "a",
                "a",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "b",
                "b",
            );

            let query = Query::parse("NOT level=ERROR");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn empty_query_matches_everything() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: SequenceCounter::new().next_sequence_number(),
                },
                "INFO",
                "a",
                "a",
            );

            let query = Query::parse("");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }

        #[test]
        fn regex_field_filter_matches() {
            let conn = open_test_db();
            let source_file_id = SourceFileId::new_random();
            insert_source(&conn, source_file_id, "text_config");
            let mut counter = SequenceCounter::new();
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "user42 logged in",
                "raw",
            );
            insert_entry(
                &conn,
                EventId {
                    source_file_id,
                    sequence_number: counter.next_sequence_number(),
                },
                "INFO",
                "no digits here",
                "raw",
            );

            let query = Query::parse(r"message~user\d+");
            assert_eq!(count_matching(&conn, &query).unwrap(), 1);
        }
    }
}
