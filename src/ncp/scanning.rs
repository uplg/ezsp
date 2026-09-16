//! Scan requests and their callback-result channels.

use tokio::sync::oneshot::channel;

use crate::Error;
use crate::ncp::{Message, Ncp};
use crate::parameters::networking::handler::{EnergyScanResult, NetworkFound};

impl Ncp {
    /// Starts an active network scan and returns all `networkFound` callback results.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if registering the scan, sending `startScan`, or
    /// receiving the scan result fails, or the completion callback reports failure.
    pub async fn scan_networks(
        &mut self,
        channel_mask: u32,
        duration: u8,
    ) -> Result<Vec<NetworkFound>, Error> {
        let (response, result) = channel();
        self.event_handler_handle
            .send(Message::StartNetworkScan {
                channel_mask,
                duration,
                response,
            })
            .await?;
        result.await?
    }

    /// Starts an energy scan and returns all `energyScanResult` callback results.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if registering the scan, sending `startScan`, or
    /// receiving the scan result fails, or the completion callback reports failure.
    pub async fn scan_channels(
        &mut self,
        channel_mask: u32,
        duration: u8,
    ) -> Result<Vec<EnergyScanResult>, Error> {
        let (response, result) = channel();
        self.event_handler_handle
            .send(Message::StartChannelScan {
                channel_mask,
                duration,
                response,
            })
            .await?;
        result.await?
    }
}
