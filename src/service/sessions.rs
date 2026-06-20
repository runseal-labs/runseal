use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct SessionStore {
    sessions: BTreeSet<String>,
    disposed: BTreeSet<String>,
}

impl SessionStore {
    pub(super) fn record(&mut self, session_id: String) {
        if self.disposed.contains(&session_id) {
            return;
        }
        self.sessions.insert(session_id);
    }

    pub(super) fn dispose(&mut self, session_id: &str) -> bool {
        self.disposed.insert(session_id.to_string());
        self.sessions.remove(session_id)
    }
}
