//! Parameters for the [`Binding::delete_binding`](crate::Binding::delete) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x002D,
    { index: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(index: u8) -> Self {
                Self { index }
            }
        }
    },
    { status: u8 } => Binding(binding)::Delete,
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
