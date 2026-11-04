# rmcp-flowmesh (experimental)

This opt-in MCP client gateway makes deterministic, budget-aware routing and compact evidence receipts available to Silico and other agent hosts. The existing rmcp protocol and SEP-2549 client response cache remain unchanged.

## Host wiring

Create FlowMesh with a trusted route registry and MeshConfig. An authenticated host maps each task to a typed capability, then calls plan(capability, budget_units, host_write_approval, routing_signals). Use execute(identity, plan, arguments, || client.call_tool(CallToolRequestParams::new(plan.route().tool.clone()).with_arguments(arguments.clone()))) to wrap the existing high-level RMCP call. Return the FlowReceipt to the model, and expose controlled evidence_chunk retrieval for additional detail.

Identity must contain a tenant identifier and a stable authorization fingerprint, never an actual token. Updates to principal or permissions must change the fingerprint. Host code must enforce write authorization and restrict direct access to the MCP transport.

Only explicitly registered read-only routes may reuse results. Cache keys contain tenant, authorization, server, tool and JSON arguments, with capped TTLs. Writes invalidate that identity's cached reads, and tool errors are not cached. The evidence store is bounded and ephemeral. Handles are hashes, not bearer capabilities; retrieval always rechecks identity.

## Mechanistic steering

RoutingSignals::affinity accepts optional SAE-derived or other learned scores for trusted route IDs. The default uses the lowest estimated-cost eligible route. Learned affinity only reorders candidates within the capability, permission and budget boundary. Compare with deterministic and metadata-only policies before enabling a learned policy as the host default.

## RU measurement

MeshMetrics counts invoked tools, local cache hits, raw MCP response bytes and receipt bytes. Receipt field potentialContextBytesAvoided is an approximate byte difference, not a direct token, GPU-hour or RU measurement. Compare cost per verified successful task using real billing records, including cache-read, cache-write, input, output and GPU usage.

## Test

Run cargo test -p rmcp-flowmesh. The CI workflow checks the crate separately from upstream RMCP conformance.
