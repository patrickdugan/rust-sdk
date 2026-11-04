use std::{
    collections::BTreeMap,
    io,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use rmcp::model::{CallToolResult, ContentBlock, JsonObject};
use rmcp_flowmesh::{
    Effect, FlowMesh, Identity, MeshConfig, MeshError, RouteSpec, RoutingSignals,
};
use serde_json::json;

fn args(value: serde_json::Value) -> JsonObject {
    value.as_object().unwrap().clone()
}

fn route(ttl: Duration) -> RouteSpec {
    RouteSpec::read_only("git-ci", "ci.inspect", "github", "get_job_logs", 5, ttl)
}

fn setup(ttl: Duration, config: MeshConfig) -> FlowMesh {
    FlowMesh::new(vec![route(ttl)], config)
}

fn identity() -> Identity {
    Identity::new("tenant-a", "user:scope-hash")
}

fn successful(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text)])
}

#[test]
fn routing_enforces_capability_budget_and_approval() {
    let mesh = FlowMesh::new(
        vec![
            route(Duration::from_secs(30)),
            RouteSpec::mutating("fix", "ci.fix", "github", "create_commit", 40),
        ],
        MeshConfig::default(),
    );
    let signal = RoutingSignals::default();
    assert_eq!(
        mesh.plan("absent", 100, false, &signal).unwrap_err(),
        MeshError::UnknownCapability("absent".into())
    );
    assert_eq!(
        mesh.plan("ci.fix", 100, false, &signal).unwrap_err(),
        MeshError::ApprovalRequired
    );
    assert_eq!(
        mesh.plan("ci.fix", 30, true, &signal).unwrap_err(),
        MeshError::BudgetExceeded
    );
    let plan = mesh.plan("ci.fix", 40, true, &signal).unwrap();
    assert_eq!(plan.route().effect, Effect::Mutating);
}

#[test]
fn affinity_only_reranks_eligible_routes() {
    let mesh = FlowMesh::new(
        vec![
            route(Duration::from_secs(30)),
            RouteSpec::read_only(
                "cache", "ci.inspect", "github", "cached_logs", 1, Duration::ZERO
            ),
            RouteSpec::mutating("danger", "ci.inspect", "github", "delete_logs", 0),
        ],
        MeshConfig::default(),
    );
    let mut signals = RoutingSignals {
        affinity: BTreeMap::new(),
    };
    assert_eq!(
        mesh.plan("ci.inspect", 100, false, &signals)
            .unwrap()
            .route()
            .id,
        "cache"
    );
    signals.affinity.insert("git-ci".into(), 4.0);
    signals.affinity.insert("danger".into(), 1_000.0);
    assert_eq!(
        mesh.plan("ci.inspect", 100, false, &signals)
            .unwrap()
            .route()
            .id,
        "git-ci"
    );
    signals.affinity.insert("git-ci".into(), f32::NAN);
    assert_eq!(
        mesh.plan("ci.inspect", 100, false, &signals)
            .unwrap()
            .route()
            .id,
        "cache"
    );
}

#[tokio::test]
async fn read_only_results_reuse_cache_without_reinvocation() {
    let mesh = setup(Duration::from_secs(60), MeshConfig::default());
    let plan = mesh
        .plan("ci.inspect", 10, false, &RoutingSignals::default())
        .unwrap();
    let request = args(json!({"job": 42, "nested": {"b": 2, "a": 1}}));
    let hits = AtomicUsize::new(0);
    let first = mesh
        .execute(&identity(), &plan, &request, || async {
            hits.fetch_add(1, Ordering::SeqCst);
            Ok::<_, io::Error>(successful("job logs"))
        })
        .await
        .unwrap();
    let second = mesh
        .execute(&identity(), &plan, &request, || async {
            hits.fetch_add(1, Ordering::SeqCst);
            Ok::<_, io::Error>(successful("unwanted"))
        })
        .await
        .unwrap();
    assert!(!first.cache_hit);
    assert!(second.cache_hit);
    assert_eq!(first.evidence_handle, second.evidence_handle);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let metrics = mesh.metrics().await;
    assert_eq!(metrics.tool_invocations, 1);
    assert_eq!(metrics.cache_hits, 1);
}

#[tokio::test]
async fn cache_and_evidence_are_partitioned_by_authorization() {
    let mesh = setup(Duration::from_secs(60), MeshConfig::default());
    let plan = mesh
        .plan("ci.inspect", 10, false, &RoutingSignals::default())
        .unwrap();
    let first_identity = identity();
    let second_identity = Identity::new("tenant-b", "user:scope-hash");
    let request = args(json!({"job": 42}));
    let one = mesh
        .execute(&first_identity, &plan, &request, || async {
            Ok::<_, io::Error>(successful("private evidence"))
        })
        .await
        .unwrap();
    let two = mesh
        .execute(&second_identity, &plan, &request, || async {
            Ok::<_, io::Error>(successful("private evidence"))
        })
        .await
        .unwrap();
    assert!(!two.cache_hit);
    assert_ne!(one.evidence_handle, two.evidence_handle);
    assert!(
        mesh.evidence(&second_identity, &one.evidence_handle)
            .await
            .is_none()
    );
    assert!(
        mesh.evidence(&first_identity, &one.evidence_handle)
            .await
            .is_some()
    );
    mesh.clear_identity(&first_identity).await;
    assert!(
        mesh.evidence(&first_identity, &one.evidence_handle)
            .await
            .is_none()
    );
    assert!(
        mesh.evidence(&second_identity, &two.evidence_handle)
            .await
            .is_some()
    );
}

#[tokio::test]
async fn writes_and_tool_errors_are_never_replayed() {
    let mesh = FlowMesh::new(
        vec![
            RouteSpec::mutating("commit", "git.write", "github", "create_commit", 10),
            route(Duration::from_secs(60)),
        ],
        MeshConfig::default(),
    );
    let read = mesh.plan("ci.inspect", 20, false, &RoutingSignals::default()).unwrap();
    let write = mesh.plan("git.write", 20, true, &RoutingSignals::default()).unwrap();
    let request = args(json!({"repo":"example"}));
    let first_read = mesh
        .execute(&identity(), &read, &request, || async {
            Ok::<_, io::Error>(successful("prior status"))
        })
        .await
        .unwrap();
    assert!(!first_read.cache_hit);
    for _ in 0..2 {
        let write_receipt = mesh
            .execute(&identity(), &write, &request, || async {
                Ok::<_, io::Error>(successful("commit created"))
            })
            .await
            .unwrap();
        assert!(!write_receipt.cache_hit);
    }
    let read_after_write = mesh
        .execute(&identity(), &read, &request, || async {
            Ok::<_, io::Error>(successful("new status"))
        })
        .await
        .unwrap();
    assert!(!read_after_write.cache_hit);
    for _ in 0..2 {
        let error_receipt = mesh
            .execute(&identity(), &read, &args(json!({"error":true})), || async {
                Ok::<_, io::Error>(CallToolResult::error(vec![
                    ContentBlock::text("failed")
                ]))
            })
            .await
            .unwrap();
        assert!(error_receipt.is_error);
        assert!(!error_receipt.cache_hit);
    }
}

#[tokio::test]
async fn long_utf8_results_are_compacted_and_fetched_in_chunks() {
    let mesh = setup(
        Duration::ZERO,
        MeshConfig {
            preview_bytes: 128,
            max_evidence: 2,
            max_cache_ttl: Duration::ZERO,
            max_read_bytes: 31,
        },
    );
    let plan = mesh.plan("ci.inspect", 10, false, &RoutingSignals::default()).unwrap();
    let receipt = mesh
        .execute(&identity(), &plan, &args(json!({"n":1})), || async {
            Ok::<_, io::Error>(successful("🦀".repeat(300)))
        })
        .await
        .unwrap();
    assert!(receipt.full_bytes > receipt.delivered_bytes);
    assert!(receipt.preview.len() <= 128);
    assert!(receipt.potential_context_bytes_avoided > 0);
    let chunk = mesh
        .evidence_chunk(&identity(), &receipt.evidence_handle, 17)
        .await
        .unwrap();
    assert!(chunk.text.len() <= 31);
    assert!(chunk.next_offset > chunk.offset);
    let full = mesh.evidence(&identity(), &receipt.evidence_handle).await.unwrap();
    assert_eq!(full.content[0].as_text().unwrap().text, "🦀".repeat(300));
}

#[tokio::test]
async fn evidence_store_evicts_old_entries_and_validates_identity() {
    let mesh = setup(
        Duration::ZERO,
        MeshConfig {
            max_evidence: 1,
            ..MeshConfig::default()
        },
    );
    let plan = mesh.plan("ci.inspect", 10, false, &RoutingSignals::default()).unwrap();
    let bad_identity = Identity::new("", "");
    let error = mesh
        .execute(&bad_identity, &plan, &args(json!({})), || async {
            Ok::<_, io::Error>(successful("not reached"))
        })
        .await
        .unwrap_err();
    assert_eq!(error, MeshError::InvalidIdentity);
    let first = mesh
        .execute(&identity(), &plan, &args(json!({"n":1})), || async {
            Ok::<_, io::Error>(successful("first"))
        })
        .await
        .unwrap();
    let second = mesh
        .execute(&identity(), &plan, &args(json!({"n":2})), || async {
            Ok::<_, io::Error>(successful("second"))
        })
        .await
        .unwrap();
    assert!(mesh.evidence(&identity(), &first.evidence_handle).await.is_none());
    assert!(mesh.evidence(&identity(), &second.evidence_handle).await.is_some());
}
