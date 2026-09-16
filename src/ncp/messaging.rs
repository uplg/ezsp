//! Outgoing APS messages, payload validation, and unicast fragmentation.

use std::num::NonZero;

use log::debug;
use tokio::sync::oneshot::channel;

use crate::ember::aps::{Frame as ApsFrame, Options};
use crate::ember::message::Destination as EmberDestination;
use crate::ember::{Status as EmberStatus, Status, aps};
use crate::error::Status as ErrorStatus;
use crate::ncp::{Message, MulticastOptions, Ncp};
use crate::types::ByteSizedVec;
use crate::{Error, Messaging};

const STACK_ASSIGNED_APS_SEQUENCE: u8 = 0;
const FIRST_FRAGMENT_INDEX: usize = 0;
const MAX_FRAGMENT_COUNT: usize = u8::MAX as usize;

impl Ncp {
    /// Builds an outgoing EZSP APS frame with an explicit local source endpoint.
    ///
    /// EZSP assigns the APS sequence when a send command is accepted, so the
    /// sequence field in the command payload is initialized with a placeholder.
    #[must_use]
    pub(crate) const fn aps_frame_from(
        source_endpoint: u8,
        profile_id: u16,
        cluster_id: u16,
        destination_endpoint: u8,
        group_id: u16,
        options: Options,
    ) -> aps::Frame {
        aps::Frame::new(
            profile_id,
            cluster_id,
            source_endpoint,
            destination_endpoint,
            options,
            group_id,
            STACK_ASSIGNED_APS_SEQUENCE,
        )
    }

    /// Starts a unicast APS send from an explicit local endpoint.
    ///
    /// Payloads larger than the EZSP maximum APS payload length are fragmented
    /// for unicast delivery when `fragmentation_permitted` is true. The
    /// stack-assigned APS sequence from the first fragment is reused for
    /// follow-up fragments, matching EZSP host fragmentation behavior. Every
    /// non-final fragment waits for its `messageSent` callback before the next
    /// fragment is sent. The final fragment's callback is emitted through the
    /// application event channel. The `aps_options` apply only to this message
    /// and are combined with the NCP's baseline APS options; fragmentation
    /// additionally enables [`Options::RETRY`]. The application-provided
    /// `sequence` is sent as the EZSP message tag and is returned by the
    /// corresponding application acknowledgement event. EZSP independently
    /// assigns the APS sequence in the transmitted frame.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if an oversized payload may not be fragmented,
    /// fragmentation would exceed 255 fragments, registering a fragment
    /// response channel or sending an EZSP command fails, or a non-final
    /// fragment's `messageSent` callback reports failure.
    #[expect(clippy::too_many_arguments)]
    pub async fn unicast(
        &mut self,
        source_endpoint: u8,
        short_id: u16,
        profile_id: u16,
        cluster_id: u16,
        destination_endpoint: u8,
        payload: impl AsRef<[u8]>,
        aps_options: Options,
        sequence: u8,
        fragmentation_permitted: bool,
    ) -> Result<(), Error> {
        let payload = payload.as_ref();
        let aps_frame = Self::aps_frame_from(
            source_endpoint,
            profile_id,
            cluster_id,
            destination_endpoint,
            0,
            self.options.union(aps_options),
        );
        let destination = EmberDestination::Direct(short_id);
        let maximum_payload_length = usize::from(self.connection.maximum_payload_length().await?);

        if payload.len() <= maximum_payload_length {
            self.send_unicast_fragment(destination, aps_frame, payload, sequence)
                .await?;
            return Ok(());
        }
        if !fragmentation_permitted {
            return Err(message_too_long());
        }

        self.send_fragmented_unicast(
            destination,
            aps_frame,
            payload,
            maximum_payload_length,
            sequence,
        )
        .await
    }

    /// Starts a multicast APS send from an explicit local endpoint.
    ///
    /// The matching `messageSent` callback is emitted through the application
    /// event channel. The `aps_options` apply only to this message and are
    /// combined with the NCP's baseline APS options. The
    /// application-provided `sequence` is translated into the EZSP message tag;
    /// EZSP independently manages the APS sequence in the transmitted frame.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the payload is larger than the EZSP maximum APS
    /// payload length or sending the EZSP command fails.
    #[expect(clippy::too_many_arguments)]
    pub async fn multicast(
        &mut self,
        source_endpoint: u8,
        group_id: u16,
        profile_id: u16,
        cluster_id: u16,
        destination_endpoint: u8,
        payload: impl AsRef<[u8]>,
        options: MulticastOptions,
        aps_options: Options,
        sequence: u8,
    ) -> Result<(), Error> {
        let payload = payload.as_ref();
        let aps_frame = Self::aps_frame_from(
            source_endpoint,
            profile_id,
            cluster_id,
            destination_endpoint,
            group_id,
            self.options.union(aps_options),
        );
        let message = self.reject_oversized_payload(payload).await?;

        debug!(
            "Sending multicast: Hops: {}, Radius: {:#04X}, APS Frame: {aps_frame}, Tag: {sequence:#04X}, Message: {:#04X?}",
            options.hops(),
            options.nonmember_radius(),
            message.as_slice()
        );

        self.connection
            .send_multicast(
                aps_frame,
                options.hops(),
                options.nonmember_radius(),
                sequence,
                message,
            )
            .await?;

        Ok(())
    }

    /// Starts a broadcast APS send from an explicit local endpoint.
    ///
    /// The matching `messageSent` callback is emitted through the application
    /// event channel. The `aps_options` apply only to this message and are
    /// combined with the NCP's baseline APS options. The
    /// application-provided `sequence` is translated into the EZSP message tag;
    /// EZSP independently manages the APS sequence in the transmitted frame.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the payload is larger than the EZSP maximum APS
    /// payload length or sending the EZSP command fails.
    #[expect(clippy::too_many_arguments)]
    pub async fn broadcast(
        &mut self,
        source_endpoint: u8,
        short_id: u16,
        profile_id: u16,
        cluster_id: u16,
        destination_endpoint: u8,
        payload: impl AsRef<[u8]>,
        radius: u8,
        aps_options: Options,
        sequence: u8,
    ) -> Result<(), Error> {
        let payload = payload.as_ref();
        let aps_frame = Self::aps_frame_from(
            source_endpoint,
            profile_id,
            cluster_id,
            destination_endpoint,
            0,
            self.options.union(aps_options),
        );
        let message = self.reject_oversized_payload(payload).await?;

        debug!(
            "Sending broadcast to: {short_id:#06X}, Radius: {radius:#04X}, APS Frame: {aps_frame}, Tag: {sequence:#04X}, Message: {:#04X?}",
            message.as_slice()
        );

        self.connection
            .send_broadcast(short_id, aps_frame, radius, sequence, message)
            .await?;

        Ok(())
    }

    async fn send_fragmented_unicast(
        &mut self,
        destination: EmberDestination,
        aps_frame: ApsFrame,
        payload: &[u8],
        maximum_payload_length: usize,
        tag: u8,
    ) -> Result<(), Error> {
        let fragment_count = fragment_count(payload.len(), maximum_payload_length)?;
        let mut sequence = None;

        let mut fragments = payload
            .chunks(maximum_payload_length)
            .enumerate()
            .peekable();

        while let Some((index, chunk)) = fragments.next() {
            let mut fragment = aps_frame.clone();
            fragment.enable_retry();

            if index == FIRST_FRAGMENT_INDEX {
                fragment.set_first_fragment(fragment_count);
            } else {
                let sequence = sequence.expect("first fragment sets the APS sequence");
                let index = u8::try_from(index).expect("fragment count is limited to u8::MAX");
                fragment.set_sequence(sequence);
                fragment.set_followup_fragment(
                    NonZero::new(index).expect("follow-up fragment index is non-zero"),
                );
            }

            let response = if fragments.peek().is_some() {
                let (tx, rx) = channel();
                self.event_handler_handle
                    .send(Message::Sent { tag, sender: tx })
                    .await?;
                Some(rx)
            } else {
                None
            };

            let seq = self
                .send_unicast_fragment(destination, fragment, chunk, tag)
                .await?;

            if index == FIRST_FRAGMENT_INDEX {
                sequence.replace(seq);
            }

            if let Some(response) = response {
                match response.await? {
                    Ok(Status::Success) => (),
                    other => return Err(other.into()),
                }
            }
        }

        Ok(())
    }

    async fn send_unicast_fragment(
        &mut self,
        destination: EmberDestination,
        aps_frame: ApsFrame,
        payload: &[u8],
        tag: u8,
    ) -> Result<u8, Error> {
        let message = byte_sized_payload(payload)?;

        debug!(
            "Sending unicast to: {destination:?}, APS Frame: {aps_frame}, Tag: {tag:#04X}, Message: {:#04X?}",
            message.as_slice()
        );

        self.connection
            .send_unicast(destination, aps_frame, tag, message)
            .await
    }

    async fn reject_oversized_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<ByteSizedVec<u8>, Error> {
        let maximum_payload_length = usize::from(self.connection.maximum_payload_length().await?);

        if payload.len() > maximum_payload_length {
            Err(message_too_long())
        } else {
            byte_sized_payload(payload)
        }
    }
}

fn byte_sized_payload(payload: &[u8]) -> Result<ByteSizedVec<u8>, Error> {
    ByteSizedVec::from_slice(payload).map_err(|_| message_too_long())
}

fn fragment_count(payload_length: usize, maximum_payload_length: usize) -> Result<u8, Error> {
    if maximum_payload_length == 0 {
        return Err(message_too_long());
    }

    let fragments = payload_length.div_ceil(maximum_payload_length);

    if fragments > MAX_FRAGMENT_COUNT {
        return Err(message_too_long());
    }

    u8::try_from(fragments).map_err(|_| message_too_long())
}

const fn message_too_long() -> Error {
    Error::Status(ErrorStatus::Ember(Ok(EmberStatus::MessageTooLong)))
}
