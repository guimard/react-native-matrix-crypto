//! A response that is neither a success nor a conforming Matrix error must
//! not open the bootstrap gate.
//!
//! Task 1 refused the two shapes the Matrix specification defines: a standard
//! error body, which must carry a top-level `errcode`, and a user-interactive
//! authentication challenge, which carries `flows` instead. That covers every
//! conforming Matrix error and nothing else, and a probe against the vendored
//! crate then measured what still got through. This file is that measured
//! list, one case at a time.
//!
//! For `/keys/query`, which is the endpoint the bootstrap gate reads:
//! `{}`, a completely empty body, a gateway's own JSON error carrying no
//! `errcode` such as `{"error":"Bad Gateway"}`, and a JSON **array** were all
//! accepted and all lifted the gate. The array is the one reasoning gets
//! wrong: serde reads a struct from a sequence positionally, and every field
//! of that response is `#[serde(default)]`, so `[]` deserialises into a
//! flawless empty success.
//!
//! For `signing_keys_upload` and `to_device`, whose response types are
//! `Response {}` with no fields, ruma emits no body parse at all, so
//! literally every one of those bodies was accepted, HTML error pages and
//! `not json at all !!!` included. Accepting one marks the account's identity
//! *published* when the server holds nothing.
//!
//! A later review then defeated the gate a third way, and that case is act 1
//! below: `{"message":"Internal server error"}`, which is AWS API Gateway's
//! default error body, carries no marker of any kind, so every negative rule
//! above passes it through and serde reads it as a fully defaulted success.
//! Measured: it set the gate and `bootstrap_identity` minted. So did
//! `{"detail":...}`, `{"status":"error","code":502}` and Cloudflare's
//! `{"success":false,...}`.
//!
//! # What the rule is now, and what it necessarily leaves
//!
//! A body is accepted when it is shaped like that endpoint's response: an
//! object with no keys, or an object carrying at least one field the response
//! type really declares. `session::refuse_a_non_response` states that rule
//! and its consequences once; this file drives it rather than restating it.
//!
//! What that leaves through is not a list of literals, and the acts below are
//! written to show both halves rather than to enumerate a residue. The member
//! that matters is the object with no keys: it is the whole success response
//! of the signing-keys upload, and nothing in those bytes separates it from a
//! 502 that carried none. That is what `mark_request_failed` is for, and act
//! 2 is its test.
//!
//! **`{}` used to be described here as the genuine `/keys/query` answer for
//! an account the server knows no identity for, and it is not.** Measured
//! against three homeservers, all of them name the account even when they
//! have nothing to report about it, so the bootstrap gate now requires an
//! answer that does (`session::answer_speaks_about`, and
//! `tests/identity_bootstrap_silent_body.rs`). That narrows this file's
//! residue for the key query rather than widening it, and act 2 says which
//! of its rows still discriminates because of it.
//!
//! Its own process, for the reason `tests/pump_eviction.rs` gives: the
//! machine registry and the pump's bookkeeping are process-wide. The acts run
//! in one test and in this order because a refusal changes no state, so every
//! rejection can be driven against the same still-pending request before the
//! one accepted body finally lifts the gate.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, identity_status, mark_request_failed, mark_request_sent,
    take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest, SessionError,
};

const ACCOUNT: &str = "@alice:example.org";

/// A gateway's own JSON error. Not a Matrix error: no `errcode`, so Task 1's
/// check cannot see it. Measured as accepted, and it lifted the gate.
const GATEWAY_JSON: &str = r#"{"error":"Bad Gateway"}"#;

/// A JSON array. Measured as accepted for `/keys/query`, because serde reads
/// a struct from a sequence positionally and every field is defaulted. Both
/// shapes, because an empty sequence and a non-empty one take different paths
/// through that deserialiser.
const JSON_ARRAY_EMPTY: &str = "[]";
const JSON_ARRAY_NONEMPTY: &str = r#"[{"device_keys":{}}]"#;

/// Bodies with no JSON object anywhere in them. All measured as accepted for
/// `signing_keys_upload`, which has no body parse behind this check at all.
const HTML_502: &str = "<html><body>502 Bad Gateway</body></html>";
const GARBAGE: &str = "not json at all !!!";
const WHITESPACE_ONLY: &str = "   ";
const BARE_STRING: &str = r#""nope""#;
const JSON_NULL: &str = "null";
const JSON_NUMBER: &str = "42";

/// Error bodies real infrastructure emits that carry **no marker at all**:
/// no `errcode`, no `error`, no `flows`, and nothing else a negative rule
/// could key on. Each was measured opening the gate before the positive rule
/// existed. `AWS_GATEWAY` is AWS API Gateway's default and several service
/// meshes'; `CLOUDFLARE` is Cloudflare's; `ENVOY` and `STATUS_CODE` are
/// shapes an ingress or a service mesh produces.
const AWS_GATEWAY: &str = r#"{"message":"Internal server error"}"#;
const CLOUDFLARE: &str = r#"{"success":false,"errors":[{"code":1000}]}"#;
const ENVOY: &str = r#"{"detail":"upstream connect error"}"#;
const STATUS_CODE: &str = r#"{"status":"error","code":502}"#;

/// The body that cannot be refused, in its three spellings. All three are an
/// object with no keys by the time anything looks: ruma substitutes `{}` for
/// a completely empty body before parsing, and JSON allows the surrounding
/// whitespace. It is a real `/keys/query` success meaning "the server
/// answered and knows no identity for this account", and it is the entire
/// success response of the signing-keys upload. It is here to be reported
/// through `mark_request_failed`, which is the only thing that can tell it
/// from the answer it is identical to.
const EMPTY_OBJECT: &str = "{}";
const EMPTY_BODY: &str = "";
const PADDED_EMPTY_OBJECT: &str = "  {}  ";

/// A real `/keys/query` answer. Correct for that endpoint, and wrong for
/// every other: it is driven against the signing-keys upload to show the
/// declared field list is consulted per kind rather than pooled.
const NO_IDENTITY_ANSWER: &str = r#"{"device_keys":{}}"#;

/// A real answer carrying a field a later specification might add. The rule
/// is not `deny_unknown_fields`: an unrecognised key **alongside** a declared
/// one must still be accepted, or every future spec revision breaks this
/// library. This is the half of the positive rule that has to be right.
const REAL_ANSWER_WITH_UNKNOWN_FIELD: &str = r#"{"one_time_key_counts":{},"next_spec_field":1}"#;

/// **Hybrids: a real declared field carried alongside an error marker.**
/// These are the only bodies the `errcode`/`error`/`flows` rule catches that
/// the positive rule does not, which makes them the whole reason that rule
/// still exists as its own step. Each carries `device_keys`, so the shape
/// test passes them, and each is a failure. Deleting the marker block leaves
/// the rest of this file green and lets the first of these mint an identity.
///
/// Not hypothetical: a homeserver behind a gateway that merges its own error
/// envelope into an upstream 200 body produces exactly this, and so does a
/// partial response an intermediary annotated rather than replaced.
const HYBRID_ERRCODE: &str = r#"{"device_keys":{},"errcode":"M_LIMIT_EXCEEDED"}"#;
const HYBRID_ERROR: &str = r#"{"device_keys":{},"error":"Bad Gateway"}"#;
const HYBRID_FLOWS: &str =
    r#"{"device_keys":{},"flows":[{"stages":["m.login.password"]}],"session":"s"}"#;

/// A real `/keys/query` success whose per-server `failures` map carries both
/// an `errcode` and an `error` **nested** inside it, once per unreachable
/// server. This must be accepted: only the top level is inspected, and
/// refusing this would break every key query that touches a server that is
/// down. This is the half of the new `error` rule that has to be right.
///
/// `device_keys` names this account, because that is what a real homeserver
/// sends and because the gate now reads it. It was `{"device_keys":{}}` when
/// this constant was written, which named nobody: the answer below would be
/// accepted, as it must be, and would then lift the gate on a body whose
/// only substance is that some *other* server did not answer. See
/// `session::answer_speaks_about`.
const FAILURE_WITH_NESTED_ERROR: &str = r#"{"device_keys":{"@alice:example.org":{}},"failures":{"example.org":{"errcode":"M_UNKNOWN","error":"boom"}}}"#;

#[test]
fn a_body_that_is_not_a_response_cannot_open_the_bootstrap_gate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // --- Act 1: the key query, where a wrong accept mints an identity ---

        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let query = find(&batch, "keys_query", names_the_account);

        for (body, what) in [
            (
                GATEWAY_JSON,
                "a gateway's own JSON error carries no `errcode`, so the Matrix error rule \
                 cannot see it. No success shape of any endpoint here declares a top-level \
                 `error`, so refusing it costs nothing",
            ),
            (
                JSON_ARRAY_EMPTY,
                "a JSON array is not a response body. serde reads a struct from a sequence \
                 positionally and every field of this one is defaulted, so `[]` deserialises \
                 into a flawless empty success and lifts the gate",
            ),
            (
                JSON_ARRAY_NONEMPTY,
                "same, with a non-empty sequence, which takes a different path through that \
                 deserialiser",
            ),
            (
                AWS_GATEWAY,
                "AWS API Gateway's default error body carries no `errcode`, no `error` and no \
                 `flows`. Every rule that asks \"does this look like an error\" passes it, and \
                 serde reads it as a fully defaulted success. This is the case a review found \
                 opening the gate after the first fix round, and it is why the last rule asks \
                 \"does this look like this endpoint's response\" instead",
            ),
            (
                CLOUDFLARE,
                "Cloudflare's error body, same reason: `success` and `errors` are not fields \
                 this endpoint declares, and neither is a marker any negative rule can key on",
            ),
            (
                ENVOY,
                "an ingress or service mesh's `detail` body, same reason",
            ),
            (
                STATUS_CODE,
                "a hand-rolled `{\"status\":\"error\"}` body, same reason. Note `code` is a \
                 number here and nothing keys on it: the rule is about which fields the \
                 response type declares, not about spotting an error",
            ),
            (
                HYBRID_ERRCODE,
                "a real `device_keys` carried alongside an `errcode`. The shape rule passes \
                 this, because `device_keys` is a field this endpoint declares, so the marker \
                 rule is the only thing that refuses it. Accepted, it is read as a successful \
                 key query naming no identity and the account is minted a second one",
            ),
            (
                HYBRID_ERROR,
                "the same hybrid with the non-conformant `error` key, which is the half of \
                 the marker rule that can be dropped on its own without any other test in \
                 this crate noticing",
            ),
            (
                HYBRID_FLOWS,
                "the same hybrid with a challenge's `flows`. A 401 whose body an intermediary \
                 merged into a partial answer is still a 401",
            ),
        ] {
            assert_eq!(
                mark_request_sent(&query.id, body).await,
                Err(SessionError::MalformedPayload),
                "reported for a key query, {what}"
            );
            assert!(
                !identity_status()
                    .await
                    .expect("reading the identity status must not fail")
                    .account_keys_fetched,
                "a refused body must leave the gate exactly as closed as it was, for {body:?}"
            );
            assert_eq!(
                bootstrap_identity().await,
                Err(MachineError::AccountKeysNotFetched),
                "this is the assertion the file exists for: served here, {body:?} mints a \
                 second identity for the account and silently invalidates every verification \
                 anyone has ever made of it"
            );
        }

        // --- Act 3, driven early: the same rules on a still-pending id ------
        //
        // These were already refused for this endpoint before this task,
        // because `/keys/query` has fields and its own parse rejects them.
        // Asserted anyway: the check that now refuses them is a different one,
        // and a rule that used to be enforced downstream must not quietly stop
        // being enforced when it moves upstream.
        for body in [
            HTML_502,
            GARBAGE,
            WHITESPACE_ONLY,
            BARE_STRING,
            JSON_NULL,
            JSON_NUMBER,
        ] {
            assert_eq!(
                mark_request_sent(&query.id, body).await,
                Err(SessionError::MalformedPayload),
                "{body:?} is not a key query response and must stay refused"
            );
        }

        // --- Act 2: reporting a refusal must never answer the query --------
        //
        // The first three are an object with no keys by the time anything
        // looks. **They no longer lift this gate through `mark_request_sent`
        // either**, because no measured homeserver answers a key query that
        // way and the gate now requires an answer that names this account
        // (`session::answer_speaks_about`). They are still driven, because
        // `mark_request_failed`'s contract is the same for every body and a
        // 503 that carried nothing is still the shape a product meets most
        // often -- but on their own they would now pass this act even if
        // this call did nothing at all.
        //
        // What still discriminates is not a row here. `mark_request_failed`
        // takes an id and a status and no body at all, so the bodies in this
        // loop are narrative and could not be otherwise. The discrimination
        // is across the file: this act reports a failure against `query.id`
        // and asserts the gate stays shut and the entry stays pending, and
        // the last act reports a real answer against **that same id** and
        // asserts the gate lifts. Delete this call's effect and the last act
        // still passes; delete this act and nothing shows the failure report
        // left the request resolvable.
        for (body, status) in [
            (EMPTY_OBJECT, 502u16),
            (EMPTY_BODY, 503u16),
            (PADDED_EMPTY_OBJECT, 504u16),
        ] {
            mark_request_failed(&query.id, status).await.expect(
                "a product that received this body with a non-2xx status must be able to say \
                 so; before this call existed its only option was to report it as a success",
            );
            assert!(
                !identity_status()
                    .await
                    .expect("reading the identity status must not fail")
                    .account_keys_fetched,
                "reporting a refusal must not answer the query. The body was {body:?}, which \
                 is byte-identical to a real answer, so only the status this call carries \
                 distinguishes them"
            );
            assert_eq!(
                bootstrap_identity().await,
                Err(MachineError::AccountKeysNotFetched),
                "a refused key query must leave the gate closed, whatever its body looked like"
            );
        }

        // The misuse the library *can* see, and the only one: the pair
        // swapped. A refusal changes no state, so accepting a 2xx here would
        // let that confusion stand with nothing to show for it.
        assert_eq!(
            mark_request_failed(&query.id, 200).await,
            Err(SessionError::NotAFailureStatus),
            "a 2xx is not a refusal. A caller passing one has confused this call with \
             `mark_request_sent`, and that is the one misuse of the pair this library can \
             detect for itself"
        );
        assert_eq!(
            mark_request_failed(&query.id, 600).await,
            Err(SessionError::NotAFailureStatus),
            "600 is not an HTTP status"
        );

        // The three boundaries of the accepted range, driven either side.
        // A range written as `300..=599` is one keystroke from `200..=599`,
        // and that keystroke is the difference between catching the swapped
        // pair and not.
        assert_eq!(
            mark_request_failed(&query.id, 299).await,
            Err(SessionError::NotAFailureStatus),
            "299 is a success, and the last one: the range must not reach down into 2xx"
        );
        mark_request_failed(&query.id, 300)
            .await
            .expect("300 is the first status a refused request can carry");
        mark_request_failed(&query.id, 599)
            .await
            .expect("599 is the last status a refused request can carry");

        // The id is checked before the status, which the doc comment states
        // and nothing pinned. A bogus id with a bogus status must answer for
        // the id, or a caller holding a superseded id is sent to inspect an
        // argument that is not their problem.
        assert_eq!(
            mark_request_failed("not-a-request-this-machine-issued", 200).await,
            Err(SessionError::UnknownRequest),
            "both arguments are wrong here, and the answer must be the id: that ordering is \
             documented, and it decides which of the two a caller goes and looks at"
        );

        // A transport failure carries no status at all. Inventing a plausible
        // 5xx to satisfy the argument would be worse than saying what
        // happened, so `0` is accepted and means exactly that.
        mark_request_failed(&query.id, 0)
            .await
            .expect("a dropped connection has no status and must still be reportable");

        // Same id rule as `mark_request_sent`, and for the same reason. Three
        // ways an id can fail to name something outstanding, not one: a
        // review found only the first pinned, and the other two are the ones
        // a real product actually meets.
        assert_eq!(
            mark_request_failed("not-a-request-this-machine-issued", 502).await,
            Err(SessionError::UnknownRequest),
            "an id this machine never handed out is unknown here too"
        );

        // Superseded: a fresh drain mints a new key query and retires the id
        // the previous one handed out. A product holding the older id must be
        // told, not silently absorbed, or it would believe it had reported a
        // failure it had not.
        let superseded = query.id.clone();
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let query = find(&batch, "keys_query", names_the_account);
        assert_ne!(
            query.id, superseded,
            "a second drain must mint a fresh key query id, or this assertion proves nothing"
        );
        assert_eq!(
            mark_request_failed(&superseded, 502).await,
            Err(SessionError::UnknownRequest),
            "an id superseded by a later drain is no longer outstanding, and reporting a \
             failure against it must say so"
        );

        // --- The other half of the positive rule, on a second kind ---------
        //
        // Driven on the key upload from the same batch rather than on the key
        // query: accepting a real answer consumes the entry and lifts the
        // gate, and this control has to run while both are still untouched.
        // It also puts the marker-free error body against a second endpoint,
        // whose declared field list is a different one.
        let upload = find(&batch, "keys_upload", |_| true);
        assert_eq!(
            mark_request_sent(&upload.id, AWS_GATEWAY).await,
            Err(SessionError::MalformedPayload),
            "the rule is per endpoint, and `message` is not a field the key upload declares \
             either"
        );
        mark_request_sent(&upload.id, REAL_ANSWER_WITH_UNKNOWN_FIELD)
            .await
            .expect(
                "an unrecognised field alongside a declared one must be accepted. The rule is \
                 \"carries at least one field this endpoint declares\", not \"carries only \
                 fields this endpoint declares\": refusing this would break the library on \
                 every future specification revision, which is a worse bug than the one the \
                 rule exists for",
            );

        // --- The half that has to be right: no false refusal ---------------

        mark_request_sent(&query.id, FAILURE_WITH_NESTED_ERROR)
            .await
            .expect(
                "a success whose `failures` map carries a nested `errcode` and `error` must be \
                 accepted; refusing it would break every key query that touches an unreachable \
                 server, which is a worse bug than the one being fixed",
            );

        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "a real answer must still lift the gate. If this fails the cure is worse than the \
             disease: no product could ever bootstrap"
        );

        bootstrap_identity()
            .await
            .expect("bootstrapping after a real answer must be served");

        // --- Act 4: the fieldless kind, where this check is the only one ---
        //
        // `signing_keys_upload`'s success response is `Response {}`, so ruma
        // emits no body parse and nothing downstream of this check exists.
        // Every one of these was measured as accepted, and accepting one marks
        // the identity published while the server holds nothing.
        //
        // Its declared field list is empty, which is what makes the positive
        // rule bite hardest here: no key can match, so the only object it
        // accepts is one with no keys. That is the correct rule and not an
        // accident of an empty list, so the marker-free error bodies and a
        // body shaped like a *different* endpoint's answer are both driven
        // against it below.

        let published = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let upload = find(&published, "signing_keys_upload", |_| true);

        for body in [
            HTML_502,
            GARBAGE,
            WHITESPACE_ONLY,
            BARE_STRING,
            JSON_NULL,
            JSON_NUMBER,
            JSON_ARRAY_EMPTY,
            JSON_ARRAY_NONEMPTY,
            GATEWAY_JSON,
            AWS_GATEWAY,
            CLOUDFLARE,
            ENVOY,
            STATUS_CODE,
            // A perfectly good `/keys/query` answer, reported for this
            // request. It carries a declared field, but not one *this*
            // endpoint declares, which is the whole point of the list being
            // per kind rather than shared.
            NO_IDENTITY_ANSWER,
        ] {
            assert_eq!(
                mark_request_sent(&upload.id, body).await,
                Err(SessionError::MalformedPayload),
                "{body:?} is not a signing keys upload response. This endpoint has no body \
                 parse at all, so accepting it marks the account's identity published while \
                 the server holds nothing, and nothing afterwards disagrees"
            );
        }

        // And the real success, which is an empty object, must still be taken:
        // the id survived every refusal above, by the same rule that makes the
        // authentication retry an ordinary second send.
        mark_request_sent(&upload.id, "{}")
            .await
            .expect("the endpoint's real success response is `{}` and must be accepted");
    });
}

/// The first request of `kind` matching `predicate`, or a failure naming what
/// was in the batch instead.
fn find<'a>(
    batch: &'a [OutgoingRequest],
    kind: &str,
    predicate: impl Fn(&str) -> bool,
) -> &'a OutgoingRequest {
    batch
        .iter()
        .find(|request| request.kind == kind && predicate(&request.body))
        .unwrap_or_else(|| {
            panic!(
                "no matching {kind} in the batch; got {:?}",
                batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
            )
        })
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
