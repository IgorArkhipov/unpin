use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::{
    providers::ProviderId,
    sessions::{
        CallAdmission, LeaseLifecycle, LeaseSnapshot, LiveExposureStatus, PinnedExposure,
        SessionHandle, SessionManager,
    },
};

use super::GatewayError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySessionStatus {
    pub session_id: String,
    pub provider: ProviderId,
    pub desired_exposure_revision: String,
    pub observed_exposure_revision: String,
    pub live_status: LiveExposureStatus,
    pub lifecycle: LeaseLifecycle,
    pub admission_open: bool,
    pub in_flight_calls: u32,
}

#[derive(Debug)]
pub struct GatewayControlPlane {
    manager: SessionManager,
    handle: SessionHandle,
    snapshot: Mutex<LeaseSnapshot>,
    maximum_concurrent_calls: u32,
}

impl GatewayControlPlane {
    pub fn new(
        manager: SessionManager,
        handle: SessionHandle,
        maximum_concurrent_calls: u32,
    ) -> Result<Self, GatewayError> {
        if maximum_concurrent_calls == 0 {
            return Err(GatewayError::InvalidExposure(
                "concurrent-call limit must be positive",
            ));
        }
        let snapshot = manager.load_for_handle(&handle)?;
        if snapshot.lease.lifecycle != LeaseLifecycle::Active || !snapshot.lease.admission_open {
            return Err(GatewayError::Lease(
                crate::sessions::LeaseError::AdmissionClosed,
            ));
        }
        Ok(Self {
            manager,
            handle,
            snapshot: Mutex::new(snapshot),
            maximum_concurrent_calls,
        })
    }

    pub fn snapshot(&self) -> Result<LeaseSnapshot, GatewayError> {
        self.lock_snapshot().map(|snapshot| snapshot.clone())
    }

    pub fn status(&self) -> Result<GatewaySessionStatus, GatewayError> {
        let snapshot = self.snapshot()?;
        Ok(GatewaySessionStatus {
            session_id: snapshot.lease.session_id,
            provider: snapshot.lease.provider,
            desired_exposure_revision: snapshot.lease.desired_exposure.revision,
            observed_exposure_revision: snapshot.lease.observed_exposure.revision,
            live_status: snapshot.lease.live_status,
            lifecycle: snapshot.lease.lifecycle,
            admission_open: snapshot.lease.admission_open,
            in_flight_calls: snapshot.lease.in_flight_calls,
        })
    }

    pub fn request_exposure(
        &self,
        exposure: PinnedExposure,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, GatewayError> {
        let mut snapshot = self.lock_snapshot()?;
        let updated =
            self.manager
                .request_exposure(&self.handle, &snapshot.revision, exposure, now_unix)?;
        *snapshot = updated.clone();
        Ok(updated)
    }

    pub(crate) fn observe_exposure(
        &self,
        status: LiveExposureStatus,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, GatewayError> {
        self.observe_exposure_inner(None, status, now_unix)
    }

    pub(crate) fn observe_exposure_if_desired(
        &self,
        expected: &PinnedExposure,
        status: LiveExposureStatus,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, GatewayError> {
        self.observe_exposure_inner(Some(expected), status, now_unix)
    }

    fn observe_exposure_inner(
        &self,
        expected: Option<&PinnedExposure>,
        status: LiveExposureStatus,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, GatewayError> {
        let mut snapshot = self.lock_snapshot()?;
        if expected.is_some_and(|expected| snapshot.lease.desired_exposure != *expected) {
            return Err(GatewayError::InvalidExposure(
                "pending exposure is no longer desired",
            ));
        }
        let updated =
            self.manager
                .observe_exposure(&self.handle, &snapshot.revision, status, now_unix)?;
        *snapshot = updated.clone();
        Ok(updated)
    }

    pub(crate) fn admit_call(
        &self,
        exposure_revision: &str,
        now_unix: i64,
    ) -> Result<CallAdmission, GatewayError> {
        let mut snapshot = self.lock_snapshot()?;
        if snapshot.lease.observed_exposure.revision != exposure_revision
            || snapshot.lease.desired_exposure != snapshot.lease.observed_exposure
        {
            return Err(GatewayError::CapabilityUnavailable);
        }
        if snapshot.lease.in_flight_calls >= self.maximum_concurrent_calls {
            return Err(GatewayError::ConcurrencyLimitExceeded);
        }
        let (admission, updated) =
            self.manager
                .admit_call_with_snapshot(&self.handle, &snapshot.revision, now_unix)?;
        *snapshot = updated;
        Ok(admission)
    }

    pub(crate) fn finish_call(
        &self,
        admission: CallAdmission,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, GatewayError> {
        let mut snapshot = self.lock_snapshot()?;
        let updated =
            self.manager
                .finish_call(&self.handle, &snapshot.revision, admission, now_unix)?;
        *snapshot = updated.clone();
        Ok(updated)
    }

    pub fn reconcile_stopped_runtime(&self, now_unix: i64) -> Result<LeaseSnapshot, GatewayError> {
        let mut snapshot = self.lock_snapshot()?;
        let updated =
            self.manager
                .reconcile_stopped_runtime(&self.handle, &snapshot.revision, now_unix)?;
        *snapshot = updated.clone();
        Ok(updated)
    }

    fn lock_snapshot(&self) -> Result<MutexGuard<'_, LeaseSnapshot>, GatewayError> {
        let mut snapshot = match self.snapshot.lock() {
            Ok(snapshot) => snapshot,
            Err(poisoned) => {
                // Durable lease remains authoritative after an in-process panic.
                poisoned.into_inner()
            }
        };
        // Session-end and mode controls may update lease state outside this
        // connection runtime. Refresh under local serialization before every
        // operation so stale cached revisions fail closed instead of reviving
        // fenced admission.
        *snapshot = self.manager.load_for_handle(&self.handle)?;
        Ok(snapshot)
    }
}
