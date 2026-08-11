# Open decisions

| Decision | Options | Trade-offs | Recommendation | Blocks |
|---|---|---|---|---|
| Hosted region/data sovereignty | Fiji residency; AU/NZ cloud; customer-hosted | Residency/latency/cost and provider availability | Validate Fiji requirements; offer AU/NZ only with contract/consent; customer-hosted for restricted data | SaaS pilot, AI/export architecture |
| Search timing | Postgres-only; OpenSearch in Phase 2 | Simplicity vs search scale/operations | Start Postgres abstraction; define trigger metrics for OpenSearch | Event API/indexing |
| Queue | Redis Streams; NATS; Kafka | Fast start vs durability/scale/operations | Redis Streams Phase 1–3 behind interface | Worker contracts |
| LLM/provider and data egress | OpenAI-compatible provider; gateway; local model | Quality, residency, cost, governance | Provider abstraction; default no external log data until customer approves residency and DPA | AI phase |
| Retention defaults | 30/90/365 days by class; customer-selected | Cost vs investigations/legal needs | Propose reviewable defaults: raw 90d, events 365d, cases 7y; legal review required | Storage/cost model |
| Pricing/metering | Per asset; GB/day; platform + managed service | Predictability vs margin/telemetry variability | Hybrid platform + asset bands + ingestion fair-use; validate with pilots | Billing |
| Pilot deployment | Railway + Cloudflare; dedicated VM; customer-hosted | Speed vs sovereignty/control | Tentative Railway hosted pilot with Cloudflare DNS/WAF; no commitment before residency review | Pilot runbook |
| Customer-managed keys | DB/object only; all tenant secrets; HSM/KMS | Strong control vs operational complexity | Phase 6 DB/object encryption scope first; expand after customer requirements | Dedicated/customer-hosted |
| Windows collection | Build agent; WEF-only; both | Coverage/control vs installation burden | WEF-first; agent only where WEF gaps are demonstrated | Connector scope |
| SIEM positioning | SIEM of record; complement to existing SIEM | Procurement/retention expectations | Start as complementary cyber operations platform; revisit after pilots | Product messaging |

These are product decisions, not implementation assumptions. Record owner, date, evidence, and decision in ADRs before the blocked phase starts.
