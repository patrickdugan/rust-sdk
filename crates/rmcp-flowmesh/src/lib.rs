//! FlowMesh is an opt-in, cost-aware MCP client execution layer.
//!
//! Hosts register trusted capability-to-tool routes. A deterministic or
//! advisory feature-informed policy chooses an authorised route within budget.
//! Responses remain in a tenant-scoped evidence store; models receive compact
//! receipts and can request exact evidence when needed.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt::Display,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use rmcp::{
    model::{CallToolRequestParams, CallToolResult, JsonObject},
    service::Peer,
    RoleClient,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

/// Trusted, non-secret authorization identity. Include the principal and
/// effective permissions in the authorization fingerprint; never store tokens.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub tenant: String,
    pub auth_scope: String,
}

impl Identity {
    pub fn new(tenant: impl Into<String>, auth_scope: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            auth_scope: auth_scope.into(),
        }
    }

    fn valid(&self) -> bool {
        !self.tenant.is_empty() && !self.auth_scope.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    ReadOnly,
    Mutating,
}

/// Route declarations come from the trusted host, never from untrusted
/// tool annotation hints or a model-proposed tool list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub id: String,
    pub capability: String,
    pub server: String,
    pub tool: String,
    pub effect: Effect,
    pub estimated_units: u64,
    pub cache_ttl: Duration,
}

impl RouteSpec {
    pub fn read_only(
        id: impl Into<String>,
        capability: impl Into<String>,
        server: impl Into<String>,
        tool: impl Into<String>,
        estimated_units: u64,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            id: id.into(),
            capability: capability.into(),
            server: server.into(),
            tool: tool.into(),
            effect: Effect::ReadOnly,
            estimated_units,
            cache_ttl,
        }
    }

    pub fn mutating(
        id: impl Into<String>,
        capability: impl Into<String>,
        server: impl Into<String>,
        tool: impl Into<String>,
        estimated_units: u64,
    ) -> Self {
        Self {
            id: id.into(),
            capability: capability.into(),
            server: server.into(),
            tool: tool.into(),
            effect: Effect::Mutating,
            estimated_units,
            cache_ttl: Duration::ZERO,
        }
    }
}

/// Optional learned or SAE-derived affinity scores. Only eligible candidates
/// are ranked. A nonfinite score is treated as zero.
#[derive(Clone, Debug, Default)]
pub struct RoutingSignals {
    pub affinity: BTreeMap<String, f32>,
}

#[derive(Clone, Debug)]
pub struct MeshConfig {
    pub preview_bytes: usize,
    pub max_evidence: usize,
    pub max_cache_ttl: Duration,
    pub max_read_bytes: usize,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            preview_bytes: 2_048,
            max_evidence: 512,
            max_cache_ttl: Duration::from_secs(300),
            max_read_bytes: 16 * 1_024,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MeshError {
    #[error("no trusted route for capability: {0}")]
    UnknownCapability(String),
    #[error("a mutating tool requires host-side approval")]
    ApprovalRequired,
    #[error("all eligible routes exceed the remaining budget")]
    BudgetExceeded,
    #[error("identity must include nonempty tenant and authorization scope")]
    InvalidIdentity,
    #[error("route is not registered in this FlowMesh")]
    UnregisteredRoute,
    #[error("MCP tool execution failed: {0}")]
    Invocation(String),
    #[error("failed to encode evidence: {0}")]
    Encoding(String),
}

/// Created by FlowMesh::plan. A host must resolve write permissions itself.
#[derive(Clone, Debug)]
pub struct PlannedRoute {
    route: RouteSpec,
    approved_mutation: bool,
}

impl PlannedRoute {
    pub fn route(&self) -> &RouteSpec {
        &self.route
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowReceipt {
    pub route_id: String,
    pub evidence_handle: String,
    pub preview: String,
    pub is_error: bool,
    pub cache_hit: bool,
    pub full_bytes: usize,
    pub delivered_bytes: usize,
    pub potential_context_bytes_avoided: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceChunk {
    pub text: String,
    pub offset: usize,
    pub next_offset: usize,
    pub total_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MeshMetrics {
    pub tool_invocations: u64,
    pub cache_hits: u64,
    pub bytes_returned_by_tools: u64,
    pub model_receipt_bytes: u64,
}

struct Evidence {
    identity: Identity,
    result: CallToolResult,
    json: String,
}

#[derive(Default)]
struct State {
    evidence: HashMap<String, Evidence>,
    insertion_order: VecDeque<String>,
    cache: HashMap<String, (String, Instant)>,
    metrics: MeshMetrics,
}

/// Cloneable host gateway. Keep a FlowMesh instance per independently
/// managed application instance; the current backing store is in memory.
#[derive(Clone)]
pub struct FlowMesh {
    routes: Arc<Vec<RouteSpec>>,
    config: MeshConfig,
    state: Arc<Mutex<State>>,
}

impl FlowMesh {
    pub fn new(routes: Vec<RouteSpec>, config: MeshConfig) -> Self {
        Self {
            routes: Arc::new(routes),
            config,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Cheapest eligible route wins by default. Learned scores can only
    /// rerank trusted, affordable and authorised candidates.
    pub fn plan(
        &self,
        capability: &str,
        budget_units: u64,
        allow_mutation: bool,
        signals: &RoutingSignals,
    ) -> Result<PlannedRoute, MeshError> {
        let matches: Vec<&RouteSpec> = self
            .routes
            .iter()
            .filter(|route| route.capability == capability)
            .collect();
        if matches.is_empty() {
            return Err(MeshError::UnknownCapability(capability.to_owned()));
        }
        let permitted: Vec<&RouteSpec> = matches
            .into_iter()
            .filter(|route| route.effect == Effect::ReadOnly || allow_mutation)
            .collect();
        if permitted.is_empty() {
            return Err(MeshError::ApprovalRequired);
        }
        let chosen = permitted
            .into_iter()
            .filter(|route| route.estimated_units <= budget_units)
            .max_by(|a, b| {
                let score = |route: &RouteSpec| {
                    signals
                        .affinity
                        .get(&route.id)
                        .copied()
                        .filter(|value| value.is_finite())
                        .unwrap_or(0.0)
                };
                score(a)
                    .total_cmp(&score(b))
                    .then_with(|| b.estimated_units.cmp(&a.estimated_units))
                    .then_with(|| b.id.cmp(&a.id))
            })
            .ok_or(MeshError::BudgetExceeded)?;
        Ok(PlannedRoute {
            route: chosen.clone(),
            approved_mutation: allow_mutation,
        })
    }

    /// Execute a planned route using the standard RMCP tool-call interface.
    ///
    /// The host should pass a closure calling RunningService::call_tool to
    /// preserve multi-round tool interaction handling. Never hold a mutex
    /// across the underlying network request. Writes always execute again.
    pub async fn execute<F, Fut, E>(
        &self,
        identity: &Identity,
        plan: &PlannedRoute,
        arguments: &JsonObject,
        invoke: F,
    ) -> Result<FlowReceipt, MeshError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CallToolResult, E>>,
        E: Display,
    {
        if !identity.valid() {
            return Err(MeshError::InvalidIdentity);
        }
        if !self.routes.contains(&plan.route)
            || (plan.route.effect == Effect::Mutating && !plan.approved_mutation)
        {
            return Err(MeshError::UnregisteredRoute);
        }
        let ttl = if plan.route.effect == Effect::ReadOnly {
            plan.route.cache_ttl.min(self.config.max_cache_ttl)
        } else {
            Duration::ZERO
        };
        let key = cache_key(identity, &plan.route, arguments)?;
        if !ttl.is_zero() {
            let mut state = self.state.lock().await;
            if let Some((handle, expires)) = state.cache.get(&key).cloned() {
                if expires > Instant::now() {
                    if let Some(evidence) = state.evidence.get(&handle) {
                        let receipt = make_receipt(&self.config, &plan.route, &handle, evidence, true)?;
                        state.metrics.cache_hits += 1;
                        state.metrics.model_receipt_bytes += receipt.delivered_bytes as u64;
                        return Ok(receipt);
                    }
                }
                state.cache.remove(&key);
            }
        }
        let result = invoke()
            .await
            .map_err(|error| MeshError::Invocation(error.to_string()))?;
        let json = serde_json::to_string(&result)
            .map_err(|error| MeshError::Encoding(error.to_string()))?;
        let handle = evidence_handle(identity, &json)?;
        let evidence = Evidence {
            identity: identity.clone(),
            result,
            json,
        };
        let receipt = make_receipt(&self.config, &plan.route, &handle, &evidence, false)?;
        let cacheable = !ttl.is_zero() && evidence.result.is_error != Some(true);
        let mut state = self.state.lock().await;
        state.metrics.tool_invocations += 1;
        state.metrics.bytes_returned_by_tools += evidence.json.len() as u64;
        state.metrics.model_receipt_bytes += receipt.delivered_bytes as u64;
        if plan.route.effect == Effect::Mutating {
            // Invalidate every cached read for this authorization identity.
            let invalidated: HashSet<_> = state
                .evidence
                .iter()
                .filter(|(_, value)| &value.identity == identity)
                .map(|(handle, _)| handle.clone())
                .collect();
            state.cache.retain(|_, (handle, _)| !invalidated.contains(handle));
        }
        if !state.evidence.contains_key(&handle) {
            state.insertion_order.push_back(handle.clone());
        }
        state.evidence.insert(handle.clone(), evidence);
        while state.evidence.len() > self.config.max_evidence.max(1) {
            if let Some(oldest) = state.insertion_order.pop_front() {
                state.evidence.remove(&oldest);
                state.cache.retain(|_, (value, _)| value != &oldest);
            } else {
                break;
            }
        }
        if cacheable {
            if let Some(expires) = Instant::now().checked_add(ttl) {
                state.cache.insert(key, (handle, expires));
            }
        }
        Ok(receipt)
    }

    /// Convenience helper for an ordinary tools/call request. For servers
    /// that use MRTR or tasks, pass the high-level client call into execute.
    pub async fn call_peer(
        &self,
        identity: &Identity,
        plan: &PlannedRoute,
        arguments: &JsonObject,
        peer: &Peer<RoleClient>,
    ) -> Result<FlowReceipt, MeshError> {
        let params = CallToolRequestParams::new(plan.route.tool.clone())
            .with_arguments(arguments.clone());
        self.execute(identity, plan, arguments, || peer.call_tool(params))
            .await
    }

    pub async fn evidence(&self, identity: &Identity, handle: &str) -> Option<CallToolResult> {
        let state = self.state.lock().await;
        state
            .evidence
            .get(handle)
            .filter(|evidence| &evidence.identity == identity)
            .map(|evidence| evidence.result.clone())
    }

    /// Return a bounded UTF-8 chunk of the complete serialized MCP result.
    /// A non-boundary offset moves forward to a valid UTF-8 boundary.
    pub async fn evidence_chunk(
        &self,
        identity: &Identity,
        handle: &str,
        offset: usize,
    ) -> Option<EvidenceChunk> {
        let state = self.state.lock().await;
        let evidence = state
            .evidence
            .get(handle)
            .filter(|evidence| &evidence.identity == identity)?;
        let raw = &evidence.json;
        if offset > raw.len() {
            return None;
        }
        let mut start = offset;
        while start < raw.len() && !raw.is_char_boundary(start) {
            start += 1;
        }
        let mut end = start
            .saturating_add(self.config.max_read_bytes.max(4))
            .min(raw.len());
        while end > start && !raw.is_char_boundary(end) {
            end -= 1;
        }
        Some(EvidenceChunk {
            text: raw[start..end].to_owned(),
            offset: start,
            next_offset: end,
            total_bytes: raw.len(),
        })
    }

    /// Remove scoped evidence and any cached reads pointing to that evidence.
    pub async fn clear_identity(&self, identity: &Identity) {
        let mut state = self.state.lock().await;
        state
            .evidence
            .retain(|_, evidence| &evidence.identity != identity);
        let live: HashSet<_> = state.evidence.keys().cloned().collect();
        state.insertion_order.retain(|handle| live.contains(handle));
        state.cache.retain(|_, (handle, _)| live.contains(handle));
    }

    pub async fn metrics(&self) -> MeshMetrics {
        self.state.lock().await.metrics
    }
}

fn cache_key(
    identity: &Identity,
    route: &RouteSpec,
    arguments: &JsonObject,
) -> Result<String, MeshError> {
    let bytes = serde_json::to_vec(&(
        &identity.tenant,
        &identity.auth_scope,
        &route.server,
        &route.tool,
        arguments,
    ))
    .map_err(|error| MeshError::Encoding(error.to_string()))?;
    Ok(sha256(&bytes))
}

fn evidence_handle(identity: &Identity, json: &str) -> Result<String, MeshError> {
    let bytes = serde_json::to_vec(&(&identity.tenant, &identity.auth_scope, json))
        .map_err(|error| MeshError::Encoding(error.to_string()))?;
    Ok(format!("sha256:{}", sha256(&bytes)))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn make_receipt(
    config: &MeshConfig,
    route: &RouteSpec,
    handle: &str,
    evidence: &Evidence,
    cache_hit: bool,
) -> Result<FlowReceipt, MeshError> {
    let limit = config.preview_bytes.max(128);
    let preview = if evidence.json.len() <= limit {
        evidence.json.clone()
    } else {
        let text = evidence
            .result
            .content
            .iter()
            .find_map(|block| block.as_text().map(|text| text.text.as_str()))
            .unwrap_or("[large structured, binary, or non-text result; fetch evidence by handle]");
        let mut excerpt = text.to_owned();
        if excerpt.len() > limit {
            let mut end = limit;
            while !excerpt.is_char_boundary(end) {
                end -= 1;
            }
            excerpt.truncate(end);
        }
        excerpt
    };
    let mut receipt = FlowReceipt {
        route_id: route.id.clone(),
        evidence_handle: handle.to_owned(),
        preview,
        is_error: evidence.result.is_error == Some(true),
        cache_hit,
        full_bytes: evidence.json.len(),
        delivered_bytes: 0,
        potential_context_bytes_avoided: 0,
    };
    // Byte accounting is an approximation of model-visible payload, not RUs.
    for _ in 0..3 {
        receipt.delivered_bytes = serde_json::to_vec(&receipt)
            .map_err(|error| MeshError::Encoding(error.to_string()))?
            .len();
        receipt.potential_context_bytes_avoided =
            receipt.full_bytes.saturating_sub(receipt.delivered_bytes);
    }
    Ok(receipt)
}
