use std::fmt::Debug;
use std::sync::Arc;

use log::{trace, warn};
use tokio::sync::mpsc::{UnboundedSender};

use super::decoder::Decoder;
use super::np_rw_lock::NpRwLock;
use super::state::State;
use crate::error::Error;
use crate::frame::{Callback, Frame, Parameters};

/// Split incoming `EZSP` frames into responses and asynchronous callbacks.
pub struct Splitter {
    incoming: Decoder,
    responses: UnboundedSender<Result<Parameters, Error>>,
    callbacks: UnboundedSender<Callback>,
    state: Arc<NpRwLock<State>>,
}

impl Splitter {
    /// Create a new `Splitter`.
    ///
    /// Sets the incoming frames decoder as a source for frames
    /// and the responses and callbacks sinks as destinations.
    #[must_use]
    pub const fn new(
        incoming: Decoder,
        responses: UnboundedSender<Result<Parameters, Error>>,
        callbacks: UnboundedSender<Callback>,
        state: Arc<NpRwLock<State>>,
    ) -> Self {
        Self {
            incoming,
            responses,
            callbacks,
            state,
        }
    }

    /// Run the splitter.
    ///
    /// Continuously decodes incoming frames and forwards them as responses or callbacks.
    pub async fn run(mut self) {
        while let Some(frame) = self.incoming.decode().await {
            match frame {
                Ok(frame) => {
                    trace!("Received frame: {frame:?}");
                    self.handle_frame(frame);
                }
                Err(error) => {
                    warn!("Failed to decode frame: {error}");

                    if self.state.read().is_response_pending() {
                        self.responses
                            .send(Err(error))
                            .expect("Response channel should be open. This is a bug.");
                    }
                }
            }
        }
    }

    fn handle_frame(&self, frame: Frame) {
        let (header, parameters) = frame.into();

        match parameters {
            Parameters::Response(response) => {
                trace!("Forwarding response: {response:?}");
                self.handle_response(Parameters::Response(response));
            }
            Parameters::Callback(callback) => {
                if header.is_async_callback() {
                    trace!("Forwarding async callback: {callback:?}");
                    self.handle_callback(callback);
                } else {
                    trace!("Forwarding non-async callback as response: {callback:?}");
                    self.handle_response(Parameters::Callback(callback));
                }
            }
        }
    }

    fn handle_response(&self, parameters: Parameters) {
        self.responses
            .send(Ok(parameters))
            .expect("Response channel should be open. This is a bug.");
    }

    fn handle_callback(&self, handler: Callback) {
        self.callbacks
            .send(handler)
            .expect("Callback channel should be open. This is a bug");
    }
}

impl Debug for Splitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Splitter")
            .field("incoming", &self.incoming)
            .field("responses", &self.responses)
            .field("callbacks", &"...")
            .field("state", &self.state)
            .finish()
    }
}
