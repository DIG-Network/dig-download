//! [`DownloadQueue`] — a bounded, first-come-first-serve queue over a [`Downloader`] (#1435 req. 1):
//! capsule downloads are QUEUED and scheduled a few at a time, not all fired at once.
//!
//! # Why queue at all
//!
//! The #1423 cache-fill flywheel can enqueue many capsule downloads at once. Launching them all
//! concurrently would saturate this node's own bandwidth and open unbounded peer connections. The
//! queue caps the number of **active** downloads (`max_active`, default 3); the rest wait in arrival
//! order and start as slots free up.
//!
//! # The FCFS guarantee
//!
//! Submissions run through one FIFO channel drained by exactly `max_active` worker tasks. A job is
//! received only when a worker is idle, and the channel yields jobs in submission order — so at most
//! `max_active` downloads run at once and they START in the order they were submitted (no reordering,
//! no starvation).
//!
//! Each [`submit`](DownloadQueue::submit) returns a [`QueuedHandle`] carrying the same live progress
//! event stream and terminal result as a direct [`Downloader::download`], so a caller cannot tell
//! whether its download ran immediately or waited for a slot.

use std::sync::Arc;

use dig_dht::ContentId;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::error::DownloadError;
use crate::orchestrator::{DownloadOptions, Downloader};
use crate::progress::DownloadEvent;
use crate::sink::Sink;

/// The default number of capsule downloads allowed to run at once (the rest queue).
pub const DEFAULT_MAX_ACTIVE_DOWNLOADS: usize = 3;

/// One queued download job handed to a worker: what to download plus the back-channels the worker
/// uses to stream progress and deliver the terminal result to the [`QueuedHandle`].
struct QueuedJob {
    content: ContentId,
    sink: Arc<dyn Sink>,
    opts: DownloadOptions,
    events: mpsc::Sender<DownloadEvent>,
    result: oneshot::Sender<Result<u64, DownloadError>>,
}

/// A bounded FCFS scheduler in front of a [`Downloader`]: [`submit`](Self::submit) as many downloads
/// as you like; at most `max_active` run concurrently and the rest wait their turn in arrival order.
pub struct DownloadQueue {
    submit_tx: mpsc::UnboundedSender<QueuedJob>,
    max_active: usize,
}

impl DownloadQueue {
    /// Build a queue over `downloader` that runs at most `max_active` downloads at once (clamped to at
    /// least 1). Spawns `max_active` worker tasks that drain submissions FCFS for the queue's lifetime.
    pub fn new(downloader: Arc<Downloader>, max_active: usize) -> Arc<Self> {
        let max_active = max_active.max(1);
        let (submit_tx, submit_rx) = mpsc::unbounded_channel::<QueuedJob>();
        // One shared FIFO receiver behind a mutex: a worker locks only long enough to pull the next
        // job, so jobs are handed out in submission order and a job leaves the queue only when a
        // worker is free — the bounded-FCFS invariant.
        let submit_rx = Arc::new(Mutex::new(submit_rx));
        for _ in 0..max_active {
            let downloader = downloader.clone();
            let submit_rx = submit_rx.clone();
            tokio::spawn(async move {
                loop {
                    let job = {
                        let mut rx = submit_rx.lock().await;
                        rx.recv().await
                    };
                    let Some(job) = job else {
                        return; // queue dropped — no more submissions
                    };
                    run_job(&downloader, job).await;
                }
            });
        }
        Arc::new(DownloadQueue {
            submit_tx,
            max_active,
        })
    }

    /// Build a queue with the default active cap ([`DEFAULT_MAX_ACTIVE_DOWNLOADS`]).
    pub fn with_defaults(downloader: Arc<Downloader>) -> Arc<Self> {
        Self::new(downloader, DEFAULT_MAX_ACTIVE_DOWNLOADS)
    }

    /// The configured maximum number of concurrently-active downloads.
    pub fn max_active(&self) -> usize {
        self.max_active
    }

    /// Enqueue a download. Returns immediately with a [`QueuedHandle`]; the transfer starts as soon as
    /// a worker slot is free (immediately if under the active cap), in submission order.
    pub fn submit(
        &self,
        content: ContentId,
        sink: Arc<dyn Sink>,
        opts: DownloadOptions,
    ) -> QueuedHandle {
        let (events_tx, events_rx) = mpsc::channel(256);
        let (result_tx, result_rx) = oneshot::channel();
        let job = QueuedJob {
            content,
            sink,
            opts,
            events: events_tx,
            result: result_tx,
        };
        // Unbounded send never blocks; if all workers are busy the job simply waits in the channel.
        if self.submit_tx.send(job).is_err() {
            // Workers gone (queue dropped): the oneshot is already dropped, so join() yields TaskEnded.
        }
        QueuedHandle {
            events: events_rx,
            result: Some(result_rx),
        }
    }
}

/// Drive one queued download to completion on a worker: start it on the downloader, forward its
/// progress events to the queued handle, then deliver the terminal result.
async fn run_job(downloader: &Downloader, job: QueuedJob) {
    let mut handle = downloader.download(job.content, job.sink, job.opts);
    // Forward progress until the download task closes its event stream (i.e. it reached a terminal
    // state); a receiver that has been dropped just means the caller stopped listening.
    while let Some(event) = handle.next_event().await {
        if job.events.send(event).await.is_err() {
            break;
        }
    }
    let _ = job.result.send(handle.join().await);
}

/// A handle to a queued download: the live progress [`DownloadEvent`] stream plus the terminal result
/// via [`join`](Self::join) — the same surface as a direct download, whether it ran now or waited.
pub struct QueuedHandle {
    events: mpsc::Receiver<DownloadEvent>,
    result: Option<oneshot::Receiver<Result<u64, DownloadError>>>,
}

impl QueuedHandle {
    /// Await the next progress [`DownloadEvent`], or `None` once the stream closes (download ended or
    /// the queue was dropped).
    pub async fn next_event(&mut self) -> Option<DownloadEvent> {
        self.events.recv().await
    }

    /// Await the terminal result: `Ok(total_length)` on success, else the terminal [`DownloadError`]
    /// ([`DownloadError::TaskEnded`] if the queue was dropped before the download ran).
    pub async fn join(mut self) -> Result<u64, DownloadError> {
        match self.result.take() {
            Some(rx) => rx.await.unwrap_or(Err(DownloadError::TaskEnded)),
            None => Err(DownloadError::TaskEnded),
        }
    }
}
