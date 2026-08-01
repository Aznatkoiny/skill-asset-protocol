export const KERNEL_SCHEMA_VERSION = 1;

export const SCHEMA_V1_SQL = String.raw`
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS policy_versions (
  id TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL,
  canonical_json TEXT NOT NULL,
  policy_hash TEXT NOT NULL UNIQUE,
  predecessor_hash TEXT,
  applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS spend_sessions (
  id TEXT PRIMARY KEY,
  adapter_id TEXT NOT NULL,
  wallet_address TEXT NOT NULL,
  policy_version_id TEXT NOT NULL REFERENCES policy_versions(id),
  state TEXT NOT NULL CHECK (state IN ('open','policy_blocked','closed')),
  created_at TEXT NOT NULL,
  closed_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS agent_enrollments (
  agent_instance_id TEXT PRIMARY KEY,
  credential_digest TEXT NOT NULL UNIQUE,
  enrollment_hash TEXT NOT NULL UNIQUE,
  agent_uid TEXT NOT NULL CHECK (
    agent_uid GLOB '[1-9]*' AND agent_uid NOT GLOB '*[^0-9]*'
  ),
  agent_gid TEXT NOT NULL CHECK (
    agent_gid GLOB '[1-9]*' AND agent_gid NOT GLOB '*[^0-9]*'
  ),
  state TEXT NOT NULL CHECK (state IN ('active','revoked')),
  enrolled_by_operator_hash TEXT NOT NULL,
  enrolled_at TEXT NOT NULL,
  revoked_by_operator_hash TEXT,
  revoked_at TEXT,
  UNIQUE(agent_instance_id, credential_digest),
  UNIQUE(agent_instance_id, credential_digest, enrollment_hash),
  CHECK (
    (state = 'active' AND revoked_by_operator_hash IS NULL AND revoked_at IS NULL) OR
    (state = 'revoked' AND revoked_by_operator_hash IS NOT NULL AND revoked_at IS NOT NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS isolation_attestations (
  id TEXT PRIMARY KEY,
  report_hash TEXT NOT NULL UNIQUE,
  enrollment_hash TEXT NOT NULL REFERENCES agent_enrollments(enrollment_hash),
  report_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('current','superseded')),
  imported_by_operator_hash TEXT NOT NULL,
  probed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  superseded_at TEXT,
  CHECK (
    (state = 'current' AND superseded_at IS NULL) OR
    (state = 'superseded' AND superseded_at IS NOT NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS agent_session_bindings (
  id TEXT PRIMARY KEY,
  agent_instance_id TEXT NOT NULL,
  credential_digest TEXT NOT NULL,
  enrollment_hash TEXT NOT NULL,
  session_id TEXT NOT NULL UNIQUE REFERENCES spend_sessions(id),
  state TEXT NOT NULL CHECK (state IN ('open','closed')),
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  closed_at TEXT,
  FOREIGN KEY(agent_instance_id, credential_digest, enrollment_hash)
    REFERENCES agent_enrollments(agent_instance_id, credential_digest, enrollment_hash)
) STRICT;

CREATE TABLE IF NOT EXISTS spend_intents (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  session_id TEXT NOT NULL REFERENCES spend_sessions(id),
  enrollment_hash TEXT NOT NULL REFERENCES agent_enrollments(enrollment_hash),
  route_id TEXT NOT NULL,
  method TEXT NOT NULL,
  request_url_hash TEXT NOT NULL,
  seller_origin TEXT NOT NULL,
  resource_path TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  header_allowlist_hash TEXT NOT NULL,
  ordinary_fingerprint TEXT NOT NULL,
  retry_matchable INTEGER NOT NULL DEFAULT 1 CHECK (retry_matchable IN (0,1)),
  purpose_label TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  wallet_address TEXT NOT NULL,
  intent_hash TEXT NOT NULL UNIQUE,
  challenge_projection_json TEXT,
  challenge_hash TEXT,
  challenge_received_at TEXT,
  state TEXT NOT NULL CHECK (state IN (
    'captured','challenged','approval_pending','authorized','reserved','signing',
    'signed','retrying','unresolved','terminal'
  )),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS policy_decisions (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  policy_version_id TEXT NOT NULL REFERENCES policy_versions(id),
  decision TEXT NOT NULL CHECK (decision IN ('allow','approval_required','deny')),
  reason_code TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  accepted_index INTEGER,
  quote_id TEXT,
  amount_ceiling_atomic TEXT NOT NULL CHECK (
    amount_ceiling_atomic = '0' OR
    (amount_ceiling_atomic GLOB '[1-9]*' AND amount_ceiling_atomic NOT GLOB '*[^0-9]*')
  ),
  decided_at TEXT NOT NULL,
  CHECK (
    (accepted_index IS NULL AND quote_id IS NULL) OR
    (accepted_index >= 0 AND quote_id IS NOT NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS budget_reservations (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  session_id TEXT NOT NULL REFERENCES spend_sessions(id),
  seller_origin TEXT NOT NULL,
  reserved_atomic TEXT NOT NULL CHECK (reserved_atomic = '0' OR
    (reserved_atomic GLOB '[1-9]*' AND reserved_atomic NOT GLOB '*[^0-9]*')),
  committed_atomic TEXT NOT NULL CHECK (committed_atomic = '0' OR
    (committed_atomic GLOB '[1-9]*' AND committed_atomic NOT GLOB '*[^0-9]*')),
  released_atomic TEXT NOT NULL CHECK (released_atomic = '0' OR
    (released_atomic GLOB '[1-9]*' AND released_atomic NOT GLOB '*[^0-9]*')),
  unresolved_atomic TEXT NOT NULL CHECK (unresolved_atomic = '0' OR
    (unresolved_atomic GLOB '[1-9]*' AND unresolved_atomic NOT GLOB '*[^0-9]*')),
  state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','unresolved')),
  committed_at TEXT,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL UNIQUE REFERENCES spend_intents(id),
  decision TEXT NOT NULL CHECK (
    decision IN ('pending','approved','denied','expired','cancelled','consumed')
  ),
  operator_id_hash TEXT,
  intent_hash TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  quote_id TEXT NOT NULL,
  accepted_index INTEGER NOT NULL CHECK (accepted_index >= 0),
  amount_ceiling_atomic TEXT NOT NULL CHECK (
    amount_ceiling_atomic = '0' OR
    (amount_ceiling_atomic GLOB '[1-9]*' AND amount_ceiling_atomic NOT GLOB '*[^0-9]*')
  ),
  wallet_address TEXT NOT NULL,
  policy_version_id TEXT NOT NULL REFERENCES policy_versions(id),
  expires_at TEXT NOT NULL,
  reason_code TEXT,
  decided_at TEXT,
  consumed_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS payment_attempts (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL UNIQUE REFERENCES spend_intents(id),
  state TEXT NOT NULL CHECK (state IN (
    'reserved','signing','signed','retrying','unresolved','settled','rejected'
  )),
  payment_required_projection_json TEXT NOT NULL,
  accepted_index INTEGER NOT NULL CHECK (accepted_index >= 0),
  payment_payload_json TEXT,
  payment_header TEXT,
  payment_hash TEXT,
  quote_id TEXT NOT NULL,
  nonce TEXT UNIQUE,
  valid_after TEXT CHECK (valid_after IS NULL OR valid_after = '0' OR
    (valid_after GLOB '[1-9]*' AND valid_after NOT GLOB '*[^0-9]*')),
  valid_before TEXT CHECK (valid_before IS NULL OR valid_before = '0' OR
    (valid_before GLOB '[1-9]*' AND valid_before NOT GLOB '*[^0-9]*')),
  settlement_json TEXT,
  transaction_id TEXT UNIQUE,
  reason_code TEXT,
  signing_claimed_at TEXT,
  signed_at TEXT,
  retry_started_at TEXT,
  settled_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS payment_reconciliation_candidates (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES payment_attempts(intent_id),
  transaction_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('pending','abandoned','rejected','confirmed')),
  evidence_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS execution_outcomes (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  state TEXT NOT NULL CHECK (state IN ('succeeded','failed','unknown')),
  http_status INTEGER CHECK (http_status IS NULL OR (http_status BETWEEN 100 AND 599)),
  response_hash TEXT,
  metadata_json TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS execution_resolutions (
  intent_id TEXT PRIMARY KEY REFERENCES execution_outcomes(intent_id),
  state TEXT NOT NULL CHECK (state IN (
    'refund_pending','reconciliation_required','resolved'
  )),
  reason_code TEXT NOT NULL,
  blocks_wallet INTEGER NOT NULL CHECK (blocks_wallet IN (0,1)),
  opened_at TEXT NOT NULL,
  resolved_at TEXT,
  CHECK (
    (state = 'resolved' AND blocks_wallet = 0 AND resolved_at IS NOT NULL) OR
    (state != 'resolved' AND blocks_wallet = 1 AND resolved_at IS NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS refunds (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES spend_intents(id),
  original_transaction_id TEXT NOT NULL,
  amount_atomic TEXT NOT NULL CHECK (amount_atomic = '0' OR
    (amount_atomic GLOB '[1-9]*' AND amount_atomic NOT GLOB '*[^0-9]*')),
  state TEXT NOT NULL CHECK (
    state IN ('pending','unresolved','abandoned','confirmed','rejected')
  ),
  evidence_json TEXT,
  refund_transaction_id TEXT UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reconciliations (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES spend_intents(id),
  kind TEXT NOT NULL CHECK (kind IN ('payment','execution','refund')),
  outcome TEXT NOT NULL CHECK (outcome IN (
    'settled','rejected','execution_succeeded','execution_failed',
    'execution_unknown','refund_confirmed','refund_rejected','unresolved'
  )),
  evidence_json TEXT NOT NULL,
  operator_id_hash TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS buyer_outcomes (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  status TEXT NOT NULL CHECK (status IN (
    'completed','upstream_failed','payment_denied','payment_failed',
    'payment_unresolved','payment_rejected','execution_failed',
    'execution_unknown','refunded'
  )),
  reason_code TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  recorded_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS signed_receipts (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES spend_intents(id),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  receipt_json TEXT NOT NULL,
  receipt_hash TEXT NOT NULL UNIQUE,
  signature TEXT NOT NULL,
  algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
  key_id TEXT NOT NULL,
  supersedes_receipt_hash TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(intent_id, revision)
) STRICT;

CREATE TABLE IF NOT EXISTS events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  data_json TEXT NOT NULL,
  previous_hash TEXT,
  event_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_intents_session_hash
  ON spend_intents(session_id, intent_hash, state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_open_instance
  ON agent_session_bindings(agent_instance_id) WHERE state = 'open';
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_open_credential
  ON agent_session_bindings(credential_digest) WHERE state = 'open';
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_agent_enrollment
  ON agent_enrollments(state) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_current_isolation_attestation
  ON isolation_attestations(state) WHERE state = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_retry_fingerprint
  ON spend_intents(session_id, ordinary_fingerprint) WHERE retry_matchable = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_session_correlation
  ON spend_intents(session_id, correlation_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_session_binding
  ON spend_sessions(adapter_id, wallet_address, policy_version_id)
  WHERE state = 'open';
CREATE INDEX IF NOT EXISTS idx_budget_session_seller
  ON budget_reservations(session_id, seller_origin, state);
CREATE INDEX IF NOT EXISTS idx_budget_committed_at
  ON budget_reservations(committed_at);
CREATE INDEX IF NOT EXISTS idx_approvals_state_expiry
  ON approvals(decision, expires_at);
CREATE INDEX IF NOT EXISTS idx_payment_state
  ON payment_attempts(state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refunds_one_open_intent
  ON refunds(intent_id) WHERE state IN ('pending','unresolved');
CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_candidate_one_open_intent
  ON payment_reconciliation_candidates(intent_id) WHERE state = 'pending';
`;
