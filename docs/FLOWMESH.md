# Silico FlowMesh implementation notes

The initial gateway resides in crates/rmcp-flowmesh and uses the existing rmcp client API. Silico should call FlowMesh on its default tool path while preserving the host's existing MCP server authentication and multi-round tool handling.

The host registers trusted capability-to-server/tool routes, costs, effect classes and short read TTLs. plan() chooses only eligible routes within budget. A feature-informed controller can supply advisory scores, but never approve writes or broaden the tool registry. execute() keeps full CallToolResult values in an authorization-scoped memory store and provides a compact FlowReceipt to the model. evidence_chunk() supports explicit bounded retrieval. The host remains responsible for real RU billing and permission revocation.

Quality gate: verified success per RU, token consumption broken out by cache writes and reads, latency, tool call count, evidence precision and task success. Test on matched GitHub CI triage and repository lookup workloads. Compare deterministic routing against metadata-only and SAE feature-informed policies.

Production gaps: this prototype uses an in-process store and cache. Persist with encryption, scoped ACLs and expiry only when appropriate. Invalidate from external mutations and MCP notifications. Add per-key singleflight for concurrent reads, a workflow DAG scheduler, idempotency keys for mutating calls, and real billing hooks. RunningService::call_tool should be used inside execute() for MRTR. The convenience call_peer() is for ordinary single tool calls. Protocol conformance remains the responsibility of rmcp; this is an opt-in application layer.
