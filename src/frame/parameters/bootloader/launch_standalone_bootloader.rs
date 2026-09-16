//! Parameters for the [`Bootloader::launch_standalone_bootloader()`](crate::Bootloader::launch_standalone_bootloader) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x008F,
    { mode: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(mode: u8) -> Self {
                Self { mode }
            }
        }
    },
    { status: u8 } => Bootloader(bootloader)::LaunchStandaloneBootloader,
    impl {
        /// Convert the response into a [`Result<()>`](crate::Result) by evaluating its status field.
        impl TryFrom<Response> for () {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(())
            }
        }
    }
);
