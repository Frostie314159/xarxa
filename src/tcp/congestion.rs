use crate::time::Instant;

use super::RttEstimator;

pub(super) mod no_control;

pub(super) mod cubic;

pub(super) mod reno;

#[allow(unused_variables)]
pub(super) trait Controller {
    /// Returns the number of bytes that can be sent.
    fn window(&self) -> usize;

    /// Set the remote window size.
    fn set_remote_window(&mut self, remote_window: usize) {}

    fn on_ack(&mut self, now: Instant, len: usize, in_flight: usize, rtt: &RttEstimator) {}

    /// Fired on each duplicate ack received, after `on_loss` has been called.
    fn on_dup_ack(&mut self, now: Instant, len: usize, in_flight: usize) {}

    /// Fired on a retransmission timeout.
    fn on_rto(&mut self, now: Instant, in_flight: usize) {}

    /// Fired after an inferred loss via three duplicate acks.
    fn on_loss(&mut self, now: Instant, in_flight: usize) {}

    fn pre_transmit(&mut self, now: Instant) {}

    fn post_transmit(&mut self, now: Instant, len: usize) {}

    /// Set the maximum segment size.
    fn set_mss(&mut self, mss: usize) {}
}

#[derive(Debug)]
pub(super) enum AnyController {
    None(no_control::NoControl),

    Reno(reno::Reno),

    Cubic(cubic::Cubic),
}

impl AnyController {
    /// Create a new congestion controller, defaulting to no congestion control.
    ///
    /// Users can select a congestion controller manually with
    /// [`super::TcpSocket::set_congestion_control()`] at run-time.
    #[inline]
    pub fn new() -> Self {
        AnyController::None(no_control::NoControl)
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut dyn Controller {
        match self {
            AnyController::None(n) => n,

            AnyController::Reno(r) => r,

            AnyController::Cubic(c) => c,
        }
    }

    #[inline]
    pub fn inner(&self) -> &dyn Controller {
        match self {
            AnyController::None(n) => n,

            AnyController::Reno(r) => r,

            AnyController::Cubic(c) => c,
        }
    }
}
