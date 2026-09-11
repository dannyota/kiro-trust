use kiro_trust_kiro::AttemptProgress;
use kiro_trust_protocol::catalog::{self, ModelKey};
use kiro_trust_protocol::translate::response::UsageSnapshot;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const ERROR_KINDS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageErrorKind {
    LocalConcurrency,
    Authentication,
    ModelCapacity,
    TransientThrottle,
    UpstreamServer,
    Transport,
    Protocol,
    InvalidState,
    InvalidRequest,
    Cancelled,
}

impl UsageErrorKind {
    const ALL: [Self; ERROR_KINDS] = [
        Self::LocalConcurrency,
        Self::Authentication,
        Self::ModelCapacity,
        Self::TransientThrottle,
        Self::UpstreamServer,
        Self::Transport,
        Self::Protocol,
        Self::InvalidState,
        Self::InvalidRequest,
        Self::Cancelled,
    ];

    fn index(self) -> usize {
        match self {
            Self::LocalConcurrency => 0,
            Self::Authentication => 1,
            Self::ModelCapacity => 2,
            Self::TransientThrottle => 3,
            Self::UpstreamServer => 4,
            Self::Transport => 5,
            Self::Protocol => 6,
            Self::InvalidState => 7,
            Self::InvalidRequest => 8,
            Self::Cancelled => 9,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RequestCounts {
    pub started: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub in_flight: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DurationCounts {
    pub total: u64,
    pub max: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorCount {
    pub kind: UsageErrorKind,
    pub count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UsageTotals {
    pub requests: RequestCounts,
    pub tokens: UsageSnapshot,
    pub duration_ms: DurationCounts,
    pub retries: u64,
    pub errors: Vec<ErrorCount>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModelUsageReport {
    pub id: String,
    #[serde(flatten)]
    pub totals: UsageTotals,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageReport {
    pub object: &'static str,
    pub since: String,
    #[serde(flatten)]
    pub totals: UsageTotals,
    pub models: Vec<ModelUsageReport>,
}

#[derive(Default)]
struct Counters {
    requests: RequestCounts,
    tokens: UsageSnapshot,
    duration_ms: DurationCounts,
    retries: u64,
    errors: [u64; ERROR_KINDS],
}

impl Counters {
    fn begin(&mut self) {
        self.requests.started = self.requests.started.saturating_add(1);
        self.requests.in_flight = self.requests.in_flight.saturating_add(1);
    }

    fn terminal(&mut self, outcome: Outcome, usage: UsageSnapshot, duration_ms: u64, retries: u64) {
        self.requests.in_flight = self.requests.in_flight.saturating_sub(1);
        match outcome {
            Outcome::Completed => {
                self.requests.completed = self.requests.completed.saturating_add(1)
            }
            Outcome::Failed(kind) => {
                self.requests.failed = self.requests.failed.saturating_add(1);
                self.errors[kind.index()] = self.errors[kind.index()].saturating_add(1);
            }
            Outcome::Cancelled => {
                self.requests.cancelled = self.requests.cancelled.saturating_add(1);
                self.errors[UsageErrorKind::Cancelled.index()] =
                    self.errors[UsageErrorKind::Cancelled.index()].saturating_add(1);
            }
        }
        add_snapshot(&mut self.tokens, usage);
        self.duration_ms.total = self.duration_ms.total.saturating_add(duration_ms);
        self.duration_ms.max = self.duration_ms.max.max(duration_ms);
        self.retries = self.retries.saturating_add(retries);
    }

    fn report(&self) -> UsageTotals {
        UsageTotals {
            requests: self.requests.clone(),
            tokens: self.tokens,
            duration_ms: self.duration_ms.clone(),
            retries: self.retries,
            errors: UsageErrorKind::ALL
                .into_iter()
                .filter_map(|kind| {
                    let count = self.errors[kind.index()];
                    (count > 0).then_some(ErrorCount { kind, count })
                })
                .collect(),
        }
    }
}

fn add_snapshot(total: &mut UsageSnapshot, value: UsageSnapshot) {
    total.reported.input = total.reported.input.saturating_add(value.reported.input);
    total.reported.output = total.reported.output.saturating_add(value.reported.output);
    total.reported.cache_read = total
        .reported
        .cache_read
        .saturating_add(value.reported.cache_read);
    total.reported.cache_write = total
        .reported
        .cache_write
        .saturating_add(value.reported.cache_write);
    total.estimated.input = total.estimated.input.saturating_add(value.estimated.input);
    total.estimated.output = total
        .estimated
        .output
        .saturating_add(value.estimated.output);
}

enum Outcome {
    Completed,
    Failed(UsageErrorKind),
    Cancelled,
}

struct State {
    total: Counters,
    models: Vec<Counters>,
}

pub struct UsageSummary {
    since: String,
    state: Mutex<State>,
}

impl Default for UsageSummary {
    fn default() -> Self {
        Self::new()
    }
}

impl UsageSummary {
    pub fn new() -> Self {
        let since = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("RFC3339 formatting cannot fail");
        UsageSummary {
            since,
            state: Mutex::new(State {
                total: Counters::default(),
                models: (0..catalog::models().len())
                    .map(|_| Counters::default())
                    .collect(),
            }),
        }
    }

    pub fn begin(self: &Arc<Self>, model: ModelKey) -> RequestUsageGuard {
        let model_index = model.catalog_index();
        let mut state = self.state.lock().expect("usage summary mutex poisoned");
        state.total.begin();
        state.models[model_index].begin();
        drop(state);
        RequestUsageGuard {
            summary: self.clone(),
            model_index,
            started: Instant::now(),
            usage: UsageSnapshot::default(),
            output_bytes: 0,
            progress: AttemptProgress::default(),
            terminal: false,
        }
    }

    pub fn snapshot(&self) -> UsageReport {
        let state = self.state.lock().expect("usage summary mutex poisoned");
        let catalog = catalog::models();
        let models = state
            .models
            .iter()
            .zip(catalog)
            .filter_map(|(counter, model)| {
                (counter.requests.started > 0).then(|| ModelUsageReport {
                    id: model.id,
                    totals: counter.report(),
                })
            })
            .collect();
        UsageReport {
            object: "usage_summary",
            since: self.since.clone(),
            totals: state.total.report(),
            models,
        }
    }
}

pub struct RequestUsageGuard {
    summary: Arc<UsageSummary>,
    model_index: usize,
    started: Instant,
    usage: UsageSnapshot,
    output_bytes: u64,
    progress: AttemptProgress,
    terminal: bool,
}

impl RequestUsageGuard {
    pub fn attempt_progress(&self) -> AttemptProgress {
        self.progress.clone()
    }

    pub fn update(&mut self, usage: UsageSnapshot, output_bytes: u64) {
        self.usage = usage;
        self.output_bytes = output_bytes;
    }

    pub fn complete(&mut self) {
        self.transition(Outcome::Completed);
    }

    pub fn fail(&mut self, kind: UsageErrorKind) {
        self.transition(Outcome::Failed(kind));
    }

    fn transition(&mut self, outcome: Outcome) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        let duration_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let retries = u64::from(self.progress.completed().saturating_sub(1));
        let mut state = self
            .summary
            .state
            .lock()
            .expect("usage summary mutex poisoned");
        state
            .total
            .terminal(outcome_ref(&outcome), self.usage, duration_ms, retries);
        state.models[self.model_index].terminal(outcome, self.usage, duration_ms, retries);
    }
}

fn outcome_ref(outcome: &Outcome) -> Outcome {
    match outcome {
        Outcome::Completed => Outcome::Completed,
        Outcome::Failed(kind) => Outcome::Failed(*kind),
        Outcome::Cancelled => Outcome::Cancelled,
    }
}

impl Drop for RequestUsageGuard {
    fn drop(&mut self) {
        if !self.terminal {
            self.transition(Outcome::Cancelled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiro_trust_protocol::translate::response::ReportedTokens;

    #[test]
    fn counters_saturate_without_wrapping() {
        let mut counters = Counters {
            requests: RequestCounts {
                started: u64::MAX,
                completed: u64::MAX,
                failed: u64::MAX,
                cancelled: u64::MAX,
                in_flight: u64::MAX,
            },
            tokens: UsageSnapshot {
                reported: ReportedTokens {
                    input: u64::MAX,
                    output: u64::MAX,
                    cache_read: u64::MAX,
                    cache_write: u64::MAX,
                },
                estimated: Default::default(),
            },
            duration_ms: DurationCounts {
                total: u64::MAX,
                max: u64::MAX,
            },
            retries: u64::MAX,
            errors: [u64::MAX; ERROR_KINDS],
        };
        counters.begin();
        counters.terminal(
            Outcome::Failed(UsageErrorKind::Transport),
            UsageSnapshot {
                reported: ReportedTokens {
                    input: 1,
                    output: 1,
                    cache_read: 1,
                    cache_write: 1,
                },
                estimated: Default::default(),
            },
            1,
            1,
        );
        assert_eq!(counters.requests.started, u64::MAX);
        assert_eq!(counters.tokens.reported.input, u64::MAX);
        assert_eq!(counters.duration_ms.total, u64::MAX);
        assert_eq!(counters.retries, u64::MAX);
        assert_eq!(counters.errors[UsageErrorKind::Transport.index()], u64::MAX);
    }
}
