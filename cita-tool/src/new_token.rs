use ethabi::{Address, Bytes, FixedBytes, Token, Uint};
use rustc_hex::ToHex;

/// Ethereum ABI params.
#[derive(Debug, PartialEq, Clone)]
pub enum NewToken {
    /// Address.
    ///
    /// solidity name: address
    /// Encoded to left padded [0u8; 32].
    Address(Address),
    /// Vector of bytes with known size.
    ///
    /// solidity name eg.: bytes8, bytes32, bytes64, bytes1024
    /// Encoded to right padded [0u8; ((N + 31) / 32) * 32].
    FixedBytes(FixedBytes),
    /// Vector of bytes of unknown size.
    ///
    /// solidity name: bytes
    /// Encoded in two parts.
    /// Init part: offset of 'closing part`.
    /// Closing part: encoded length followed by encoded right padded bytes.
    Bytes(Bytes),
    /// Signed integer.
    ///
    /// solidity name: int
    Int(Uint),
    /// Unisnged integer.
    ///
    /// solidity name: uint
    Uint(Uint),
    /// Boolean value.
    ///
    /// solidity name: bool
    /// Encoded as left padded [0u8; 32], where last bit represents boolean value.
    Bool(bool),
    /// String.
    ///
    /// solidity name: string
    /// Encoded in the same way as bytes. Must be utf8 compliant.
    String(String),
    /// Array with known size.
    ///
    /// solidity name eg.: int[3], bool[3], address[][8]
    /// Encoding of array is equal to encoding of consecutive elements of array.
    FixedArray(Vec<NewToken>),
    /// Array of params with unknown size.
    ///
    /// solidity name eg. int[], bool[], address[5][]
    Array(Vec<NewToken>),
    /// Tuple of params of variable types.
    ///
    /// solidity name: tuple
    Tuple(Vec<NewToken>),
}

impl From<Token> for NewToken {
    fn from(token: Token) -> Self {
        match token {
            Token::Bool(b) => NewToken::Bool(b),
            Token::String(s) => NewToken::String(s),
            Token::Address(a) => NewToken::Address(a),
            Token::Bytes(bytes) => NewToken::Bytes(bytes),
            Token::FixedBytes(bytes) => NewToken::FixedBytes(bytes),
            Token::Uint(i) => NewToken::Uint(i),
            Token::Int(i) => NewToken::Int(i),
            Token::Array(arr) => NewToken::Array(
                arr.iter()
                    .map(|t| NewToken::from(t.clone()))
                    .collect::<Vec<NewToken>>(),
            ),
            Token::FixedArray(arr) => NewToken::FixedArray(
                arr.iter()
                    .map(|t| NewToken::from(t.clone()))
                    .collect::<Vec<NewToken>>(),
            ),
            _ => NewToken::Tuple(vec![NewToken::Bool(false)]), // todo tuple
        }
    }
}

impl std::fmt::Display for NewToken {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            NewToken::Bool(b) => write!(f, "{b}"),
            NewToken::String(ref s) => write!(f, "{s}"),
            NewToken::Address(ref a) => write!(f, "{a:x}"),
            NewToken::Bytes(ref bytes) | NewToken::FixedBytes(ref bytes) => {
                write!(f, "{}", bytes.to_hex::<String>())
            }
            NewToken::Uint(ref i) => write!(f, "{i}"),
            NewToken::Int(mut i) => {
                if i.0[3] & 0x8000_0000_0000_0000 != 0 {
                    i.0[0] = 0xffff_ffff_ffff_ffff - i.0[0] + 1;
                    i.0[1] = 0xffff_ffff_ffff_ffff - i.0[1];
                    i.0[2] = 0xffff_ffff_ffff_ffff - i.0[2];
                    i.0[3] = 0xffff_ffff_ffff_ffff - i.0[3];
                    write!(f, "-{i}")
                } else {
                    write!(f, "{i}")
                }
            }
            NewToken::Array(ref arr) | NewToken::FixedArray(ref arr) => {
                let s = arr
                    .iter()
                    .map(|ref t| format!("{t}"))
                    .collect::<Vec<String>>()
                    .join(",");

                write!(f, "[{s}]")
            }
            NewToken::Tuple(ref _t) => write!(f, "tuple not support"), // todo tuple
        }
    }
}
