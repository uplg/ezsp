//! Ember duty cycle state and limits.

use le_stream::{FromLeStream, ToLeStream};
use num_derive::FromPrimitive;

/// Ember duty cycle state.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, FromPrimitive)]
#[repr(u8)]
pub enum State {
    /// No Duty cycle tracking or metrics are taking place.
    TrackingOff = 0x00,
    /// Duty Cycle is tracked and has not exceeded any thresholds.
    LbtNormal = 0x01,
    /// We have exceeded the limited threshold of our total duty cycle allotment.
    LbtLimitedThresholdReached = 0x02,
    /// We have exceeded the critical threshold of our total duty cycle allotment.
    LbtCriticalThresholdReached = 0x03,
    /// We have reached the suspend limit and are blocking all outbound transmissions.
    LbtSuspendLimitReached = 0x04,
}

impl From<State> for u8 {
    fn from(state: State) -> Self {
        state as Self
    }
}

/// A structure containing duty cycle limit configurations.
///
/// All limits are absolute, and are required to be as follows:
///
/// `susp_limit` > `crit_thresh` > `limit_thresh`
///
/// For example:
///
/// `susp_limit = 250` (2.5%), `crit_thresh = 180` (1.8%), `limit_thresh = 100` (1.00%).
///
/// See [EmberDutyCycleLimits Struct Reference](https://docs.silabs.com/zigbee/6.6/em35x/structEmberDutyCycleLimits)
/// for more information.
#[derive(Clone, Debug, Eq, PartialEq, FromLeStream, ToLeStream)]
pub struct Limits {
    crit_thresh: u16,
    limit_thresh: u16,
    susp_limit: u16,
}

impl Limits {
    /// Attempt to create a new duty cycle limit configuration, checking the limits.
    #[must_use]
    pub const fn try_new(crit_thresh: u16, limit_thresh: u16, susp_limit: u16) -> Option<Self> {
        if susp_limit > crit_thresh && crit_thresh > limit_thresh {
            Some(Self {
                crit_thresh,
                limit_thresh,
                susp_limit,
            })
        } else {
            None
        }
    }

    /// Create a new duty cycle limit configuration without checking the limits.
    ///
    /// This constructor preserves raw protocol values, including invalid threshold
    /// ordering. Use [`Self::try_new`] to validate limits before configuring the NCP.
    /// Invalid ordering is a protocol constraint, not a Rust memory-safety invariant.
    #[must_use]
    pub const fn new_unchecked(crit_thresh: u16, limit_thresh: u16, susp_limit: u16) -> Self {
        Self {
            crit_thresh,
            limit_thresh,
            susp_limit,
        }
    }

    /// Return the critical threshold in % * 100.
    #[must_use]
    pub const fn crit_thresh(&self) -> u16 {
        self.crit_thresh
    }

    /// Return the limited threshold in % * 100.
    #[must_use]
    pub const fn limit_thresh(&self) -> u16 {
        self.limit_thresh
    }

    /// Return the suspended limit (LBT) in % * 100.
    #[must_use]
    pub const fn susp_limit(&self) -> u16 {
        self.susp_limit
    }
}

#[cfg(test)]
mod tests {
    use super::Limits;

    const LIMITED: u16 = 100;
    const CRITICAL: u16 = 180;
    const SUSPENDED: u16 = 250;

    #[test]
    fn accepts_only_strictly_ordered_limits() {
        assert_eq!(
            Limits::try_new(CRITICAL, LIMITED, SUSPENDED),
            Some(Limits::new_unchecked(CRITICAL, LIMITED, SUSPENDED))
        );
        for (critical, limited, suspended) in [
            (LIMITED, LIMITED, SUSPENDED),
            (CRITICAL, LIMITED, CRITICAL),
            (LIMITED, CRITICAL, SUSPENDED),
            (SUSPENDED, LIMITED, CRITICAL),
        ] {
            assert!(Limits::try_new(critical, limited, suspended).is_none());
            let raw = Limits::new_unchecked(critical, limited, suspended);
            assert_eq!(
                (raw.crit_thresh(), raw.limit_thresh(), raw.susp_limit()),
                (critical, limited, suspended)
            );
        }
    }
}
