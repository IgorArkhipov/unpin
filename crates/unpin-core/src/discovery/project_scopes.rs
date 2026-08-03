use std::{
    any::Any,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
    thread,
};

use super::{DiscoveryError, ProjectScopeScan, merge_project_scope_scan};

pub(super) fn scan_project_scope_frontier_with(
    frontier: &[PathBuf],
    worker_limit: usize,
    scan_subtree: impl Fn(&Path) -> Result<ProjectScopeScan, DiscoveryError> + Sync,
) -> Result<Vec<ProjectScopeScan>, DiscoveryError> {
    let cancellation = AtomicBool::new(false);
    scan_project_scope_frontier_with_cancellation(
        frontier,
        worker_limit,
        &cancellation,
        scan_subtree,
    )
}

pub(super) fn scan_project_scope_frontier_with_cancellation(
    frontier: &[PathBuf],
    worker_limit: usize,
    cancellation: &AtomicBool,
    scan_subtree: impl Fn(&Path) -> Result<ProjectScopeScan, DiscoveryError> + Sync,
) -> Result<Vec<ProjectScopeScan>, DiscoveryError> {
    if cancellation.load(AtomicOrdering::Acquire) {
        return Err(project_scope_scan_cancelled_error());
    }
    let worker_count = frontier.len().min(worker_limit);
    if worker_count == 0 {
        return Ok(Vec::new());
    }
    if worker_count == 1 {
        return Ok(vec![scan_subtree(&frontier[0])?]);
    }

    let next_directory = AtomicUsize::new(0);
    thread::scope(|scope| -> Result<Vec<ProjectScopeScan>, DiscoveryError> {
        let handles = (0..worker_count)
            .map(|_| {
                scope.spawn(|| -> Result<ProjectScopeScan, DiscoveryError> {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut scan = ProjectScopeScan::default();
                        loop {
                            if cancellation.load(AtomicOrdering::Acquire) {
                                break;
                            }
                            let index = next_directory.fetch_add(1, AtomicOrdering::Relaxed);
                            let Some(directory) = frontier.get(index) else {
                                break;
                            };
                            if cancellation.load(AtomicOrdering::Acquire) {
                                break;
                            }
                            let subtree_scan = match scan_subtree(directory) {
                                Ok(scan) => scan,
                                Err(error) => {
                                    cancellation.store(true, AtomicOrdering::Release);
                                    return Err(error);
                                }
                            };
                            merge_project_scope_scan(&mut scan, subtree_scan);
                        }
                        Ok(scan)
                    }));
                    match result {
                        Ok(result) => result,
                        Err(payload) => {
                            cancellation.store(true, AtomicOrdering::Release);
                            std::panic::resume_unwind(payload);
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        let mut scans = Vec::with_capacity(worker_count);
        let mut first_error = None;
        let mut worker_panic = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(scan)) => scans.push(scan),
                Ok(Err(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(payload) => {
                    worker_panic
                        .get_or_insert_with(|| project_scope_scan_worker_panic_error(payload));
                }
            }
        }
        if worker_panic.is_none()
            && first_error.is_none()
            && cancellation.load(AtomicOrdering::Acquire)
        {
            return Err(project_scope_scan_cancelled_error());
        }
        worker_panic.or(first_error).map_or_else(|| Ok(scans), Err)
    })
}

fn project_scope_scan_cancelled_error() -> DiscoveryError {
    std::io::Error::other("project scope scan cancelled").into()
}

fn project_scope_scan_worker_panic_error(payload: Box<dyn Any + Send>) -> DiscoveryError {
    let details = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string());
    std::io::Error::other(format!("project scope scan worker panicked: {details}")).into()
}
