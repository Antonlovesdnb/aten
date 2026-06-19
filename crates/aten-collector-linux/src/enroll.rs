//! Agent enrollment state machine.
//!
//! ATEN emits a kernel event when, and only when, the involved process
//! is either an enrolled "agent root" (a process whose `comm` matches one of
//! the configured agent CLI names) or a descendant of one. Everything else
//! the kernel observes is dropped. This is the userspace-side filter that
//! keeps the dev-endpoint exec firehose down to a useful trickle.
//!
//! State is keyed by `(pid, start_time_ticks)` so a recycled PID can't be
//! confused for a still-tracked agent descendant. PIDs that exit and reappear
//! against an unrelated start_time are treated as new processes.

use std::collections::HashMap;

/// Key for tracking a specific process incarnation — PID alone is not unique
/// over the lifetime of a long-running daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: i32,
    pub start_time_ticks: u64,
}

/// What we know about an enrolled process: which agent root it descends from.
/// For an agent root itself, `agent_root` equals its own ProcessKey.
#[derive(Debug, Clone, Copy)]
pub struct EnrollmentRecord {
    pub agent_root: ProcessKey,
}

#[derive(Debug, Default)]
pub struct EnrollmentTable {
    inner: HashMap<ProcessKey, EnrollmentRecord>,
}

impl EnrollmentTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a freshly-observed enrolled process. If it has an enrolled
    /// parent, inherit the parent's agent_root; otherwise the process is
    /// itself a new agent root (caller decided this based on comm matching).
    pub fn enroll(&mut self, key: ProcessKey, parent_key: Option<ProcessKey>) -> EnrollmentRecord {
        let record = if let Some(parent_record) = parent_key.and_then(|pk| self.inner.get(&pk)) {
            EnrollmentRecord {
                agent_root: parent_record.agent_root,
            }
        } else {
            EnrollmentRecord { agent_root: key }
        };
        self.inner.insert(key, record);
        record
    }

    pub fn get(&self, key: ProcessKey) -> Option<EnrollmentRecord> {
        self.inner.get(&key).copied()
    }

    pub fn contains(&self, key: ProcessKey) -> bool {
        self.inner.contains_key(&key)
    }

    /// Drop a process incarnation after an OS exit notification.
    pub fn forget(&mut self, key: ProcessKey) -> bool {
        self.inner.remove(&key).is_some()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(pid: i32, t: u64) -> ProcessKey {
        ProcessKey {
            pid,
            start_time_ticks: t,
        }
    }

    #[test]
    fn agent_root_self_references() {
        let mut tbl = EnrollmentTable::new();
        let root = k(100, 1000);
        let rec = tbl.enroll(root, None);
        assert_eq!(rec.agent_root, root);
        assert!(tbl.contains(root));
    }

    #[test]
    fn descendants_inherit_root() {
        let mut tbl = EnrollmentTable::new();
        let root = k(100, 1000);
        tbl.enroll(root, None);
        let child = k(101, 1100);
        let rec = tbl.enroll(child, Some(root));
        assert_eq!(rec.agent_root, root);
        let grand = k(102, 1200);
        let rec2 = tbl.enroll(grand, Some(child));
        assert_eq!(rec2.agent_root, root);
    }

    #[test]
    fn pid_reuse_distinguished_by_start_time() {
        let mut tbl = EnrollmentTable::new();
        let first = k(100, 1000);
        tbl.enroll(first, None);
        // Same pid, different start_time → different incarnation, untracked.
        let recycled = k(100, 2000);
        assert!(!tbl.contains(recycled));
        assert!(tbl.contains(first));
    }
}
