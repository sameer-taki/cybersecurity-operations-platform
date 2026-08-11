# Common event schema

The canonical event is the plan's schema, extended only with its required retention/processing fields:

```json
{
  "event_id": "evt_01JABC", "tenant_id": "tenant_123",
  "observed_at": "2026-08-11T16:45:00Z", "ingested_at": "2026-08-11T16:45:03Z",
  "source": {"type":"firewall","vendor":"generic","product":"vpn","asset_id":"asset_456"},
  "actor": {"user_id":null,"username":null,"ip":"203.0.113.10"},
  "target": {"asset_id":"asset_789","hostname":"vpn.example","ip":"10.0.0.5"},
  "event_type":"authentication_failure","severity":"medium","confidence":0.94,
  "action":"login","outcome":"failure","raw_event_ref":"object://raw/evt_01JABC",
  "parser_name":"generic-syslog","parser_version":"1.0.0",
  "raw_event_sha256":"<64 lowercase hex>","retention_class":"security_event",
  "retention_until":"2027-08-11T00:00:00Z","processing_history":[]
}
```

`event_id` is stable; `tenant_id` is server-derived; timestamps are UTC; source identifies origin; actor/target are nullable context; `event_type`, action, and outcome are normalised strings; severity is `low|medium|high|critical`; confidence is 0–1; raw reference/hash prove provenance; parser fields identify reproducibility; retention fields drive policy; processing history records stage/version/status without secrets.

Parser input must be treated as untrusted, preserve the original bytes, return a schema-valid event or a structured parse failure, and be deterministic for the same parser version. The deduplication key is `(tenant_id, source connector, source event ID)` when present; otherwise SHA-256 of canonical raw bytes plus source and observed timestamp bucket. Replays retain the same event ID.

Schema versions are additive within a major version; breaking changes increment major and retain old parser versions for replay. Three normalisation examples:

```json
{"source":{"type":"firewall","vendor":"generic","product":"vpn","asset_id":"fw1"},"event_type":"authentication_failure","actor":{"ip":"203.0.113.10"},"target":{"hostname":"vpn.example"},"action":"login","outcome":"failure","severity":"medium"}
{"source":{"type":"identity","vendor":"Microsoft","product":"Entra ID","asset_id":null},"event_type":"authentication_success","actor":{"user_id":"u1","username":"user@example.com","ip":"198.51.100.8"},"target":{"asset_id":null,"hostname":null,"ip":null},"action":"login","outcome":"success","severity":"low"}
{"source":{"type":"endpoint","vendor":"Microsoft","product":"Windows Security","asset_id":"host1"},"event_type":"process_start","actor":{"user_id":null,"username":"alice","ip":null},"target":{"asset_id":"host1","hostname":"WS01","ip":null},"action":"powershell","outcome":"success","severity":"medium"}
```
