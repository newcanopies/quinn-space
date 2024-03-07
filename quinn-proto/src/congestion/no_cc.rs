use crate::congestion::ControllerFactory;
use crate::congestion::Controller;
use std::any::Any;
use std::sync::Arc;
use std::time::{Instant};
use crate::connection::RttEstimator;

#[derive(Debug, Default, Clone)]

/// No congestion control
pub struct NoCC {
    config: Arc<NoCCConfig>,
    /// Maximum number of bytes in flight that may be sent.
    window: u64,
}

impl NoCC {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<NoCCConfig>, _now: Instant, _current_mtu: u16) -> Self {
        Self {
            window: config.initial_window,
            config,
        }
    }

    //fn minimum_window(&self) -> u64 {
    //    u64::MAX
    //}
}

impl Controller for NoCC {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
    ) {}

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {}

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `NoCC` congestion controller
#[derive(Debug, Clone)]
pub struct NoCCConfig {
    initial_window: u64,
}

impl NoCCConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for NoCCConfig {
    fn default() -> Self {
        Self {
            // set to the largest possible value (aka almost infinite)
            initial_window: u64::MAX
        }
    }
}

impl ControllerFactory for NoCCConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NoCC::new(self, now, current_mtu))
    }
}
