//! Scan requests and their callback-result channels.

use tokio::sync::oneshot::channel;

use crate::ezsp::network::scan;
use crate::ncp::Ncp;
use crate::parameters::networking::handler::{EnergyScanResult, NetworkFound};
use crate::{Error, Networking};

impl Ncp {
    /// Starts an active network scan and returns all `networkFound` callback results.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if registering the scan, sending `startScan`, or
    /// receiving the scan result fails.
    pub async fn scan_networks(
        &mut self,
        channel_mask: u32,
        duration: u8,
    ) -> Result<Vec<NetworkFound>, Error> {
        let (tx, rx) = channel();
        self.event_handler_handle.send(tx.into()).await?;
        self.connection
            .start_scan(scan::Type::ActiveScan, channel_mask, duration)
            .await?;
        Ok(rx.await?)
    }

    /// Starts an energy scan and returns all `energyScanResult` callback results.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if registering the scan, sending `startScan`, or
    /// receiving the scan result fails.
    pub async fn scan_channels(
        &mut self,
        channel_mask: u32,
        duration: u8,
    ) -> Result<Vec<EnergyScanResult>, Error> {
        let (tx, rx) = channel();
        self.event_handler_handle.send(tx.into()).await?;
        self.connection
            .start_scan(scan::Type::EnergyScan, channel_mask, duration)
            .await?;
        Ok(rx.await?)
    }
}
