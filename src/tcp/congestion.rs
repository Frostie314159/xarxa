use crate::time::Instant;

use super::RttEstimator;

#[cfg(not(any(feature = "socket-tcp-reno", feature = "socket-tcp-cubic")))]
pub(super) mod no_control;

#[cfg(feature = "socket-tcp-cubic")]
pub(super) mod cubic;

#[cfg(feature = "socket-tcp-reno")]
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

/// The congestion controller this build uses, picked by the `socket-tcp-reno` and
/// `socket-tcp-cubic` cargo features.
#[cfg(not(any(feature = "socket-tcp-reno", feature = "socket-tcp-cubic")))]
pub(super) type Congestion = no_control::NoControl;

#[cfg(feature = "socket-tcp-reno")]
pub(super) type Congestion = reno::Reno;

#[cfg(feature = "socket-tcp-cubic")]
pub(super) type Congestion = cubic::Cubic;
