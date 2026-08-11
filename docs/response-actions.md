# Response actions

## State machine

```text
proposed -> previewed -> permission_checked -> pending_approval
  -> approved -> executing -> verified
                  |             |
                  v             v
               failed       rollback_pending -> rolled_back|rollback_failed
pending_approval -> rejected|expired
```

Every transition records actor, time, target, requested scope, policy decision, result, and immutable audit entry. Destructive/high-impact actions are disabled by default.

Phase 7 starts with mock adapters for account disablement, endpoint isolation, firewall block, ticket creation, notification, and analyst assignment. Adapters implement `preview`, `execute`, `verify`, and `rollback`; live adapters are opt-in and least-privileged.

Permission requires incident scope, action-specific permission, target ownership/tenant scope, current credentials, and policy checks. Approval must be by an authorised human distinct from the requester for high-impact actions; step-up MFA, expiry, exact target, reason, risk, and rollback are required. Verification checks provider state and records evidence. Rollback uses the pre-action state where safe; irreversible actions require an explicit warning and compensating procedure.
