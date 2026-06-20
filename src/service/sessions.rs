use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct SessionStore {
    sessions: BTreeSet<String>,
}

impl SessionStore {
    pub(super) fn record(&mut self, session_id: String) {
        self.sessions.insert(session_id);
    }

    pub(super) fn dispose(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id)
    }
}
