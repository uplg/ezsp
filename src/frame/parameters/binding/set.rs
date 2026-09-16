//! Parameters for the [`Binding::set_binding`](crate::Binding::set) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::binding::TableEntry;

crate::frame::parameters::frame!(
    0x002B,
    { index: u8, value: TableEntry },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(index: u8, value: TableEntry) -> Self {
                Self { index, value }
            }
        }
    },
    { status: u8 } => Binding(binding)::Set,
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
