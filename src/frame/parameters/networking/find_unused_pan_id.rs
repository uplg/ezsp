//! Parameters for the [`Networking::find_unused_pan_id`](crate::Networking::find_unused_pan_id) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x00D3,
    { channel_mask: u32, duration: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(channel_mask: u32, duration: u8) -> Self {
                Self {
                    channel_mask,
                    duration,
                }
            }
        }
    },
    { status: u8 } => Networking(networking)::FindUnusedPanId,
    impl {
        /// Converts the response into `()` or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for () {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(())
            }
        }
    }
);
