use crate::backend::BackendError;
use crate::policy::PolicyError;
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct RunSealError {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) reason: String,
    pub(crate) details: Option<Value>,
    pub(crate) events: Vec<Value>,
}

impl RunSealError {
    pub(crate) fn new(code: impl Into<String>, reason: impl Into<String>) -> Self {
        let code = code.into();
        let reason = reason.into();
        Self {
            message: reason.clone(),
            code,
            reason,
            details: None,
            events: Vec::new(),
        }
    }

    pub(crate) fn with_details(
        code: impl Into<String>,
        reason: impl Into<String>,
        details: Value,
    ) -> Self {
        let code = code.into();
        let reason = reason.into();
        Self {
            message: reason.clone(),
            code,
            reason,
            details: Some(details),
            events: Vec::new(),
        }
    }

    pub(crate) fn with_events(mut self, events: Vec<Value>) -> Self {
        self.events = events;
        self
    }
}

impl From<PolicyError> for RunSealError {
    fn from(err: PolicyError) -> Self {
        Self::new(err.code, err.reason)
    }
}

impl From<BackendError> for RunSealError {
    fn from(err: BackendError) -> Self {
        let details = err.details_json();
        Self::with_details(err.code, err.reason, details)
    }
}
