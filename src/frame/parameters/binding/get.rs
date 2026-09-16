//! Parameters for the [`Binding::get_binding`](crate::Binding::get) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::binding::TableEntry;

crate::frame::parameters::frame!(
    0x002C,
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
    { status: u8, value: TableEntry } => Binding(binding)::Get,
    impl {
        /// Convert the response into its [`TableEntry`] or an appropriate [`Error`]
        /// by evaluating its status field.
        impl TryFrom<Response> for TableEntry {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.value)
            }
        }
    }
);
