//! Ordered advisory preparation. Only equivalent outstanding requests coalesce.
use std::collections::HashSet;
use std::sync::{Arc, Mutex, mpsc};

pub(super) struct PreparationQueue<T> {
    sender: Option<mpsc::SyncSender<(Vec<u8>, T)>>,
    pending: Arc<Mutex<HashSet<Vec<u8>>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl<T: Send + 'static> PreparationQueue<T> {
    pub(super) fn new(mut prepare: impl FnMut(T) + Send + 'static) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<(Vec<u8>, T)>(32);
        let pending = Arc::new(Mutex::new(HashSet::new()));
        let shared = pending.clone();
        let worker = std::thread::Builder::new()
            .name("setup-read-acls".into())
            .spawn(move || {
                while let Ok((key, payload)) = receiver.recv() {
                    prepare(payload);
                    shared
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&key);
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            pending,
            worker: Some(worker),
        })
    }

    pub(super) fn enqueue(&self, key: Vec<u8>, payload: T) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished()),
            "read preparation worker is not running"
        );
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("read preparation queue poisoned"))?;
        if pending.contains(&key) {
            return Ok(());
        }
        pending.insert(key.clone());
        if let Err(error) = self
            .sender
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("read preparation queue closed"))?
            .try_send((key.clone(), payload))
        {
            pending.remove(&key);
            anyhow::bail!("read preparation queue unavailable: {error}");
        }
        Ok(())
    }

    pub(super) fn close(mut self) -> anyhow::Result<()> {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("read preparation worker failed"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn distinct_parameters_survive_a_blocked_request_and_equivalent_requests_coalesce() {
        let (entered, ready) = mpsc::channel();
        let (release, barrier) = mpsc::channel();
        let (done, observed) = mpsc::channel();
        let queue = PreparationQueue::new(move |value| {
            if value == 1 {
                entered.send(()).unwrap();
                barrier.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            done.send(value).unwrap();
        })
        .unwrap();
        queue.enqueue(vec![1], 1).unwrap();
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        queue.enqueue(vec![2], 2).unwrap();
        queue.enqueue(vec![1], 1).unwrap();
        assert!(observed.try_recv().is_err());
        release.send(()).unwrap();
        assert_eq!(observed.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
        assert_eq!(observed.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
        queue.close().unwrap();
        assert!(observed.try_recv().is_err());
    }
}
