use std::future::Future;

use log::{error, trace, warn};
use tokio::sync::mpsc;

use crate::api::Message;
use crate::frame::Frame;
use crate::parameters::configuration;
use crate::{Callback, Error, Parameters, Response};

/// Receives decoded frames from a transport-specific inbound stream.
///
/// The transport performs link-layer I/O and EZSP byte decoding before yielding
/// a complete [`Frame<Parameters>`](Frame). The generic receiver actor then
/// routes responses, synchronous callback-shaped responses, and asynchronous
/// callbacks to their respective consumers.
///
/// The receiver actor passes the currently negotiated protocol version to each
/// call so transports can switch between legacy and extended EZSP header
/// decoding. An `ASHv2` implementation decodes one complete `ASHv2` DATA
/// payload into one [`Frame<Parameters>`](Frame), using legacy headers while
/// the supplied version is `None`.
pub trait Receive {
    /// Receives the next decoded frame using `negotiated_version`, or returns
    /// `None` when the input closes.
    ///
    /// The receiver actor passes `None` until it observes the initial `version`
    /// response. Subsequent calls receive `Some(version)` so the transport can
    /// select version-sensitive decoding without storing negotiation state.
    ///
    /// This method has no error result. The transport implementation therefore
    /// owns its malformed-frame policy, for example logging and skipping an
    /// invalid frame or closing the input.
    fn receive(
        &mut self,
        negotiated_version: Option<u8>,
    ) -> impl Future<Output = Option<Frame<Parameters>>> + Send;
}

/// Routes received EZSP frames to the transmitter actor or callback stream.
#[derive(Debug)]
pub struct Receiver<T> {
    receive: T,
    callbacks: mpsc::Sender<Callback>,
    transmitter: mpsc::Sender<Message>,
    negotiated_version: Option<u8>,
}

impl<T> Receiver<T>
where
    T: Receive,
{
    /// Creates a receiver task around a transport-specific inbound half.
    #[must_use]
    pub const fn new(
        receive: T,
        callbacks: mpsc::Sender<Callback>,
        transmitter: mpsc::Sender<Message>,
    ) -> Self {
        Self {
            receive,
            callbacks,
            transmitter,
            negotiated_version: None,
        }
    }

    async fn handle_frame(&mut self, frame: Frame<Parameters>) -> Result<(), Error> {
        let (header, payload) = frame.into();

        if let Parameters::Response(Response::Configuration(configuration::Response::Version(
            version,
        ))) = &payload
            && let Some(previous_version) =
                self.negotiated_version.replace(version.protocol_version())
        {
            error!(
                "Replaced previous version {previous_version} with version {}.",
                version.protocol_version()
            );
        }

        match payload {
            Parameters::Callback(callback) if header.is_async_callback() => {
                trace!("Forwarding async callback: {callback:?}");
                // Never await the callback channel: this task also routes
                // command responses. Consumers commonly await command
                // responses while handling callbacks, so blocking here on a
                // full channel stalls response routing, times out in-flight
                // commands, and can deadlock the pipeline. Under a callback
                // storm, dropping the excess is the lesser evil.
                self.callbacks.try_send(callback).unwrap_or_else(|error| {
                    warn!("Dropping callback (channel full or closed): {error}");
                });
            }
            payload => {
                match &payload {
                    Parameters::Response(response) => trace!("Forwarding response: {response:?}"),
                    Parameters::Callback(callback) => {
                        trace!("Forwarding non-async callback as response: {callback:?}");
                    }
                }
                self.transmitter
                    .send(Message::Response(Frame::new(header, payload)))
                    .await?;
            }
        }

        Ok(())
    }
}

impl<T> Receiver<T>
where
    T: Receive + Send,
{
    /// Runs until the inbound stream or the transmitter actor channel closes.
    pub async fn run(mut self) {
        while let Some(frame) = self.receive.receive(self.negotiated_version).await {
            if let Err(error) = self.handle_frame(frame).await {
                warn!("{error}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use le_stream::FromLeStream;

    use super::*;
    use crate::frame::Parsable;
    use crate::{Header, Legacy, LowByte};

    const STACK_STATUS_ID: u8 = 0x19;
    const NETWORK_UP: u8 = 0x90;
    const NOP_ID: u8 = 0x05;

    struct Frames(VecDeque<Frame<Parameters>>);

    impl Receive for Frames {
        fn receive(
            &mut self,
            _negotiated_version: Option<u8>,
        ) -> impl Future<Output = Option<Frame<Parameters>>> + Send {
            std::future::ready(self.0.pop_front())
        }
    }

    /// Frame control: response bit, plus callback type "async" when requested.
    fn response_header(sequence: u8, id: u8, is_async_callback: bool) -> Header {
        let control = if is_async_callback { 0x90 } else { 0x80 };
        let low_byte = LowByte::from_le_stream([control].into_iter()).expect("one byte");
        Header::Legacy(Legacy::new(sequence, low_byte, id))
    }

    #[test]
    fn full_callback_channel_does_not_block_response_routing() {
        let (callbacks, mut callbacks_rx) = mpsc::channel(1);
        let (transmitter, mut transmitter_rx) = mpsc::channel(4);
        let stack_status = || {
            Callback::parse_from_le_stream(STACK_STATUS_ID.into(), [NETWORK_UP].into_iter())
                .expect("valid stackStatusHandler")
        };
        // Fill the callback channel so a blocking send would never complete.
        callbacks
            .try_send(stack_status())
            .expect("channel has room");

        let frames = Frames(VecDeque::from([
            Frame::new(
                response_header(0xFF, STACK_STATUS_ID, true),
                Parameters::Callback(stack_status()),
            ),
            Frame::new(
                response_header(0, NOP_ID, false),
                Parameters::Response(
                    Response::parse_from_le_stream(NOP_ID.into(), std::iter::empty())
                        .expect("valid nop response"),
                ),
            ),
        ]));

        let mut run = pin!(Receiver::new(frames, callbacks, transmitter).run());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            matches!(run.as_mut().poll(&mut cx), Poll::Ready(())),
            "receiver must not wait for callback channel capacity"
        );

        let Ok(Message::Response(frame)) = transmitter_rx.try_recv() else {
            panic!("response was not routed to the transmitter");
        };
        let (header, _): (Header, Parameters) = frame.into();
        assert_eq!(header.sequence(), 0);
        assert!(callbacks_rx.try_recv().is_ok());
        assert!(
            callbacks_rx.try_recv().is_err(),
            "excess callback is dropped"
        );
    }
}
