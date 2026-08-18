//! Producing a verdict, and asking the user when the policy says to.
//!
//! Split from the connection loop because they answer different questions. The
//! loop is about a socket; this is about a decision — the taint store, the
//! drift record, the overrides already granted, and the prompt that goes to the
//! interface when none of them settles it.
//!
//! A second `impl Daemon`, in a child module, so these methods still reach the
//! daemon's private state without widening it to the crate.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tokio::sync::oneshot;

use super::{Daemon, Override, parse_source, preview};
use crate::daemon::policy::{Action, Decision, request_from_frame};
use crate::ipc::{DecideRequest, DecideResponse, Outcome, Prompt, ServerMessage, Status, Until};
use crate::protocol::scope::Scope;
use crate::protocol::taint::fingerprint;

impl Daemon {
    pub(super) async fn decide(self: Arc<Self>, req: &DecideRequest) -> DecideResponse {
        let (decision, scope, tool, timeout) = {
            let mut policy = self.policy.lock().await;
            policy.reload_if_changed();

            let source = parse_source(&req.scope_source);
            let scope = Scope::new(source, req.scope_paths.clone());

            let mut tool_buf = String::new();
            let mut request =
                request_from_frame(&req.method, req.frame.as_bytes(), &scope, &mut tool_buf);
            request.scope_key = &req.scope_key;

            // Is anything about to leave that was read from this machine?
            // Checked before evaluation so the rule sees a fact, not a
            // callback. The store is skipped entirely when empty, which is the
            // common case: no read, no cost on the hot path.
            request.tainted = {
                let store = self.taint.lock().await;
                if store.is_empty() {
                    None
                } else {
                    store
                        .overlap(&fingerprint(&request.values.join(" ")), Instant::now())
                        .map(|m| m.origin)
                }
            };

            // Has this tool's advertisement changed since we last saw it?
            //
            // Read here and consumed on the way out, so the same change raises
            // one prompt rather than one per call. The decision the user makes
            // is about the change, and they only get to make it once.
            request.drifted = match request.tool {
                Some(t) => self
                    .drifted
                    .lock()
                    .await
                    .get(
                        req.server
                            .as_deref()
                            .unwrap_or(crate::ipc::client::UNNAMED_SERVER),
                    )
                    .is_some_and(|set| set.contains(t)),
                None => false,
            };

            let decision = policy.evaluate(&request);

            // Consumed whatever the verdict. Leaving it set would raise the
            // same alarm about the same change on every subsequent call, and
            // an alert the user has already answered is the definition of the
            // fatigue §9 warns about.
            if request.drifted
                && let Some(t) = request.tool
                && let Some(set) = self.drifted.lock().await.get_mut(
                    req.server
                        .as_deref()
                        .unwrap_or(crate::ipc::client::UNNAMED_SERVER),
                )
            {
                set.remove(t);
            }

            let tool = request.tool.map(str::to_owned);
            (decision, scope, tool, policy.ask_timeout())
        };

        let forever_allowed = scope.allows_forever();

        // A decision the user has already made is not asked again.
        if let Some(ov) = self
            .matching_override(&req.scope_key, tool.as_deref())
            .await
        {
            return DecideResponse {
                outcome: if ov { Outcome::Allow } else { Outcome::Deny },
                rule: Some("override".to_owned()),
                message: "decision recorded for this project".to_owned(),
                forever_allowed,
            };
        }

        match decision.action {
            Action::Allow => DecideResponse {
                outcome: Outcome::Allow,
                rule: decision.rule,
                message: decision.message,
                forever_allowed,
            },
            Action::Deny => {
                tracing::info!(
                    method = %req.method,
                    tool = tool.as_deref().unwrap_or("-"),
                    rule = decision.rule.as_deref().unwrap_or("-"),
                    "call blocked"
                );
                DecideResponse {
                    outcome: Outcome::Deny,
                    message: decision.agent_message(),
                    rule: decision.rule,
                    forever_allowed,
                }
            }
            Action::Ask => {
                self.ask(req, &decision, tool.as_deref(), forever_allowed, timeout)
                    .await
            }
        }
    }

    /// Asks the user for confirmation.
    async fn ask(
        self: Arc<Self>,
        req: &DecideRequest,
        decision: &Decision,
        tool: Option<&str>,
        forever_allowed: bool,
        timeout: std::time::Duration,
    ) -> DecideResponse {
        let deny = |message: String| DecideResponse {
            outcome: Outcome::Deny,
            rule: decision.rule.clone(),
            message,
            forever_allowed,
        };

        // With no interface, nobody can answer. We refuse rather than allow
        // silently — but we say so to the agent, so it does not conclude the
        // tool is broken.
        if self.state.lock().await.subscribers == 0 {
            return deny(format!(
                "{} (no interface to confirm with — start the mcpwall application)",
                decision.agent_message()
            ));
        }

        let prompt_id = self.next_prompt_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.state.lock().await.pending.insert(prompt_id, tx);

        let prompt = Prompt {
            prompt_id,
            method: req.method.clone(),
            tool: tool.map(str::to_owned),
            server: req.server.clone(),
            preview: preview(&req.frame),
            rule: decision.rule.clone(),
            severity: format!("{:?}", decision.severity).to_lowercase(),
            message: decision.message.clone(),
            findings: decision.findings.iter().map(|f| f.describe()).collect(),
            scope_key: req.scope_key.clone(),
            scope_source: req.scope_source.clone(),
            forever_allowed,
            timeout_seconds: timeout.as_secs(),
        };

        if self
            .prompts
            .send(ServerMessage::Prompt(Box::new(prompt)))
            .is_err()
        {
            self.state.lock().await.pending.remove(&prompt_id);
            return deny(format!(
                "{} (interface unreachable)",
                decision.agent_message()
            ));
        }

        let answer = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(a)) => a,
            _ => {
                // Expiry, or the UI vanished. We withdraw the prompt and tell
                // the interface, so it closes the panel rather than leaving a
                // button that will no longer do anything.
                self.state.lock().await.pending.remove(&prompt_id);
                let _ = self.prompts.send(ServerMessage::Withdraw { prompt_id });
                return deny(format!(
                    "{} (confirmation timed out)",
                    decision.agent_message()
                ));
            }
        };

        // `forever` is refused when the scope's provenance does not warrant
        // it, even if the UI asks for it. The interface is a client, not an
        // authority: a permanent permission granted on an uncertain scope would
        // leak into other projects.
        let until = match answer.until {
            Until::Forever if !forever_allowed => {
                tracing::warn!(
                    scope = %req.scope_key,
                    provenance = %req.scope_source,
                    "`forever` scope requested on an untrusted scope, downgraded to `session`"
                );
                Until::Session
            }
            other => other,
        };

        if let Some(tool) = tool {
            self.record_override(&req.scope_key, tool, answer.allow, until)
                .await;
        }

        if answer.allow {
            DecideResponse {
                outcome: Outcome::Allow,
                rule: decision.rule.clone(),
                message: "allowed by the user".to_owned(),
                forever_allowed,
            }
        } else {
            deny(format!("{} (denied by the user)", decision.agent_message()))
        }
    }

    async fn matching_override(&self, scope_key: &str, tool: Option<&str>) -> Option<bool> {
        let st = self.state.lock().await;
        st.session_overrides
            .iter()
            .find(|o| o.matches(scope_key, tool))
            .map(|o| o.allow)
    }

    async fn record_override(&self, scope_key: &str, tool: &str, allow: bool, until: Until) {
        match until {
            // Nothing to remember: the decision applied to this call only.
            Until::Once => {}
            Until::Session => {
                self.state.lock().await.session_overrides.push(Override {
                    scope_key: scope_key.to_owned(),
                    tool: tool.to_owned(),
                    allow,
                });
            }
            Until::Forever => {
                // In memory first, so the decision applies even if writing the
                // file fails.
                self.state.lock().await.session_overrides.push(Override {
                    scope_key: scope_key.to_owned(),
                    tool: tool.to_owned(),
                    allow,
                });
                if let Some(path) = &self.policy_path
                    && let Err(e) =
                        crate::daemon::policy::append_override(path, scope_key, tool, allow)
                {
                    tracing::error!(error = %e, "permanent override not persisted");
                }
            }
        }
    }

    pub(super) async fn status(&self) -> Status {
        let st = self.state.lock().await;
        let (calls_today, blocked_today, active_sessions) =
            crate::journal::today_counters(&self.journal_db).unwrap_or((0, 0, 0));

        Status {
            calls_today,
            blocked_today,
            active_sessions,
            pending_prompts: st.pending.len() as i64,
            dropped_entries: 0,
            policy_path: self
                .policy_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            ui_connected: st.subscribers > 0,
        }
    }
}
