//! Parameters for the [`Configuration::add_endpoint`](crate::Configuration::add_endpoint) command.

use std::iter::{Chain, FlatMap};

use le_stream::{FromLeStream, ToLeStream};

use crate::Error;
use crate::ezsp::Status;
use crate::types::ByteSizedVec;

crate::frame::parameters::frame!(
    0x0002,
    { endpoint: u8, profile_id: u16, device_id: u16, app_flags: u8, clusters: Clusters },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(
                endpoint: u8,
                profile_id: u16,
                device_id: u16,
                app_flags: u8,
                input_cluster_list: ByteSizedVec<u16>,
                output_cluster_list: ByteSizedVec<u16>,
            ) -> Self {
                Self {
                    endpoint,
                    profile_id,
                    device_id,
                    app_flags,
                    clusters: Clusters::new(input_cluster_list, output_cluster_list),
                }
            }
        }
    },
    { status: u8 } => Configuration(configuration)::AddEndpoint,
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

/// Helper struct to deal with special serialization of the cluster lists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Clusters {
    input_clusters: ByteSizedVec<u16>,
    output_clusters: ByteSizedVec<u16>,
}

impl Clusters {
    /// Creates command parameters.
    #[must_use]
    pub const fn new(
        input_clusters: ByteSizedVec<u16>,
        output_clusters: ByteSizedVec<u16>,
    ) -> Self {
        Self {
            input_clusters,
            output_clusters,
        }
    }

    /// Return the input clusters.
    #[must_use]
    pub fn input_clusters(&self) -> &[u16] {
        &self.input_clusters
    }

    /// Return the output clusters.
    #[must_use]
    pub fn output_clusters(&self) -> &[u16] {
        &self.output_clusters
    }
}

impl FromLeStream for Clusters {
    fn from_le_stream<T>(mut bytes: T) -> Option<Self>
    where
        T: Iterator<Item = u8>,
    {
        let input_cluster_counts = u8::from_le_stream(bytes.by_ref())?;
        let output_cluster_counts = u8::from_le_stream(bytes.by_ref())?;
        let mut input_clusters = ByteSizedVec::new();
        let mut output_clusters = ByteSizedVec::new();

        for _ in 0..input_cluster_counts {
            input_clusters
                .push(u16::from_le_stream(bytes.by_ref())?)
                .ok()?;
        }

        for _ in 0..output_cluster_counts {
            output_clusters
                .push(u16::from_le_stream(bytes.by_ref())?)
                .ok()?;
        }

        Some(Self {
            input_clusters,
            output_clusters,
        })
    }
}

impl ToLeStream for Clusters {
    type Iter = Chain<
        Chain<
            Chain<<u8 as ToLeStream>::Iter, <u8 as ToLeStream>::Iter>,
            FlatMap<
                <ByteSizedVec<u16> as IntoIterator>::IntoIter,
                <u16 as ToLeStream>::Iter,
                fn(u16) -> <u16 as ToLeStream>::Iter,
            >,
        >,
        FlatMap<
            <ByteSizedVec<u16> as IntoIterator>::IntoIter,
            <u16 as ToLeStream>::Iter,
            fn(u16) -> <u16 as ToLeStream>::Iter,
        >,
    >;

    fn to_le_stream(self) -> Self::Iter {
        let input_count = u8::try_from(self.input_clusters.len())
            .expect("ByteSizedVec contains at most u8::MAX clusters");
        let output_count = u8::try_from(self.output_clusters.len())
            .expect("ByteSizedVec contains at most u8::MAX clusters");

        #[expect(trivial_casts)]
        input_count
            .to_le_stream()
            .chain(output_count.to_le_stream())
            .chain(
                self.input_clusters
                    .into_iter()
                    .flat_map(ToLeStream::to_le_stream as _),
            )
            .chain(
                self.output_clusters
                    .into_iter()
                    .flat_map(ToLeStream::to_le_stream as _),
            )
    }
}

#[cfg(test)]
mod tests {
    use le_stream::{FromLeStream, ToLeStream};

    use super::Clusters;
    use crate::types::ByteSizedVec;

    const INPUT: u16 = 0x1234;
    const OUTPUT: u16 = 0x5678;
    const MAX_COUNT: usize = u8::MAX as usize;
    const COUNTS_LENGTH: usize = 2;
    const CLUSTER_LENGTH: usize = size_of::<u16>();

    #[test]
    fn preserves_counts_before_cluster_payloads() {
        for count in [0, 1, MAX_COUNT] {
            let input = ByteSizedVec::from_slice(&[INPUT; MAX_COUNT][..count]).unwrap();
            let output = ByteSizedVec::from_slice(&[OUTPUT; MAX_COUNT][..count]).unwrap();
            let clusters = Clusters::new(input, output);
            let bytes: Vec<_> = clusters.clone().to_le_stream().collect();
            let expected_count = u8::try_from(count).unwrap();
            let expected: Vec<_> = [expected_count, expected_count]
                .into_iter()
                .chain(std::iter::repeat_n(INPUT, count).flat_map(u16::to_le_bytes))
                .chain(std::iter::repeat_n(OUTPUT, count).flat_map(u16::to_le_bytes))
                .collect();
            assert_eq!(bytes, expected);
            assert_eq!(
                bytes.len(),
                COUNTS_LENGTH + COUNTS_LENGTH * count * CLUSTER_LENGTH
            );
            assert_eq!(Clusters::from_le_stream(bytes.into_iter()), Some(clusters));
        }
    }

    #[test]
    fn rejects_truncated_counts_and_payloads() {
        let complete = [1, 1, 0x34, 0x12, 0x78, 0x56];
        for length in 0..complete.len() {
            assert!(Clusters::from_le_stream(complete[..length].iter().copied()).is_none());
        }
    }
}
