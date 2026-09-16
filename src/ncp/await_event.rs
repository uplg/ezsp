use tokio::sync::mpsc::Receiver;

use crate::ember::Status;
use crate::frame::parameters::networking::handler::Handler as Networking;
use crate::{Callback, Error};

/// Waits for network lifecycle callbacks, reporting a closed callback stream.
pub trait AwaitEvent {
    /// Waits until the requested network status is observed.
    fn await_network_status(
        &mut self,
        status: Status,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Waits until the network is up.
    fn await_network_up(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        self.await_network_status(Status::NetworkUp)
    }

    /// Waits until the network is down.
    fn await_network_down(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        self.await_network_status(Status::NetworkDown)
    }
}

impl AwaitEvent for Receiver<Callback> {
    async fn await_network_status(&mut self, status: Status) -> Result<(), Error> {
        while let Some(callback) = self.recv().await {
            if let Callback::Networking(Networking::StackStatus(stack_status)) = callback
                && stack_status.result() == Ok(status)
            {
                return Ok(());
            }
        }
        Err(Error::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use le_stream::FromLeStream;
    use tokio::sync::mpsc;

    use super::AwaitEvent;
    use crate::ember::Status;
    use crate::parameters::networking::handler::{Handler, StackStatus};
    use crate::{Callback, Error};

    const CHANNEL_CAPACITY: usize = 2;

    fn callback(status: Status) -> Callback {
        let status = StackStatus::from_le_stream([u8::from(status)].into_iter()).unwrap();
        Callback::Networking(Handler::StackStatus(Box::new(status)))
    }

    #[test]
    fn closed_stream_is_not_a_successful_network_transition() {
        let (sender, mut receiver) = mpsc::channel(CHANNEL_CAPACITY);
        sender.try_send(callback(Status::NetworkDown)).unwrap();
        drop(sender);
        let mut future = pin!(receiver.await_network_up());
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::ChannelClosed))
        ));
    }

    #[test]
    fn waits_for_the_requested_status() {
        for (requested, unrelated) in [
            (Status::NetworkUp, Status::NetworkDown),
            (Status::NetworkDown, Status::NetworkUp),
        ] {
            let (sender, mut receiver) = mpsc::channel(CHANNEL_CAPACITY);
            sender.try_send(callback(unrelated)).unwrap();
            let mut future = pin!(receiver.await_network_status(requested));
            let mut context = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut context).is_pending());
            sender.try_send(callback(requested)).unwrap();
            assert!(matches!(
                future.as_mut().poll(&mut context),
                Poll::Ready(Ok(()))
            ));
        }
    }
}
