use le_stream::{FromLeStream, ToLeStream};

/// An unsigned integer encoded as one to four little-endian bytes.
///
/// Encoding omits zero high bytes, but always writes the low byte, including
/// for zero. Decoding accepts the available trailing bytes, up to four bytes;
/// the surrounding frame must delimit this value from any following fields.
#[expect(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromLeStream, ToLeStream)]
pub struct VariableLengthU32 {
    byte_1: u8,
    byte_2: Option<u8>,
    byte_3: Option<u8>,
    byte_4: Option<u8>,
}

impl From<VariableLengthU32> for u32 {
    fn from(value: VariableLengthU32) -> Self {
        Self::from_le_bytes([
            value.byte_1,
            value.byte_2.unwrap_or_default(),
            value.byte_3.unwrap_or_default(),
            value.byte_4.unwrap_or_default(),
        ])
    }
}

impl From<u32> for VariableLengthU32 {
    fn from(value: u32) -> Self {
        let [byte_1, byte_2, byte_3, byte_4] = value.to_le_bytes();
        Self {
            byte_1,
            byte_2: (byte_2 != 0 || byte_3 != 0 || byte_4 != 0).then_some(byte_2),
            byte_3: (byte_3 != 0 || byte_4 != 0).then_some(byte_3),
            byte_4: (byte_4 != 0).then_some(byte_4),
        }
    }
}

#[cfg(test)]
mod tests {
    use le_stream::{FromLeStream, ToLeStream};

    use super::VariableLengthU32;

    const CASES: &[(u32, &[u8])] = &[
        (0, &[0]),
        (0xFF, &[0xFF]),
        (0x100, &[0, 1]),
        (0xFFFF, &[0xFF, 0xFF]),
        (0x1_0000, &[0, 0, 1]),
        (0xFF_FFFF, &[0xFF, 0xFF, 0xFF]),
        (0x100_0000, &[0, 0, 0, 1]),
        (u32::MAX, &[0xFF, 0xFF, 0xFF, 0xFF]),
    ];

    #[test]
    fn preserves_encoding_at_each_length_boundary() {
        for &(value, expected) in CASES {
            let encoded: Vec<_> = VariableLengthU32::from(value).to_le_stream().collect();
            assert_eq!(encoded, expected);
            let decoded = VariableLengthU32::from_le_stream(expected.iter().copied()).unwrap();
            assert_eq!(u32::from(decoded), value);
        }
        assert!(VariableLengthU32::from_le_stream(std::iter::empty()).is_none());
    }
}
