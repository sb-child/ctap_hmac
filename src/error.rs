// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use cbor_codec::{DecodeError, EncodeError};
use failure::_core::fmt::{Error, Formatter};
use failure::_core::option::Option;
use failure::{Backtrace, Context, Fail};
use std::fmt;
use std::fmt::Display;

pub type FidoResult<T> = Result<T, FidoError>;

#[derive(Debug)]
pub struct FidoError(Context<FidoErrorKind>);

#[derive(Debug, Copy, Clone, Fail, Eq, PartialEq)]
pub struct CborErrorCode(u8);

// generated using build.rs
include!(concat!(env!("OUT_DIR"), "/ctap_error_codes.rs"));

impl CborErrorCode {
    fn detail(&self) -> Option<(u8, &'static str, &'static str)> {
        for (code, name, desc) in CTAP_ERROR_CODES {
            if *code == self.0 as usize {
                return Some((self.0, name, desc));
            }
        }
        None
    }

    pub fn name(&self) -> Option<&'static str> {
        self.detail().map(|(_, name, _)| name)
    }

    pub fn description(&self) -> Option<&'static str> {
        self.detail().map(|(_, _, desc)| desc)
    }

    pub fn code(&self) -> u8 {
        self.0
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum FidoErrorKind {
    #[fail(display = "Read/write error with device.")]
    Io,
    #[fail(display = "Operation timed out")]
    Timeout,
    #[fail(display = "Error while reading packet from device.")]
    ReadPacket,
    #[fail(display = "Error while writing packet to device.")]
    WritePacket,
    #[fail(display = "Error while parsing CTAP from device.")]
    ParseCtap,
    #[fail(display = "Error while encoding CBOR for device.")]
    CborEncode,
    #[fail(display = "Error while decoding CBOR from device.")]
    CborDecode,
    #[fail(display = "Packets received from device in the wrong order.")]
    InvalidSequence,
    #[fail(display = "Failed to generate private keypair.")]
    GenerateKey,
    #[fail(display = "Failed to generate shared secret.")]
    GenerateSecret,
    #[fail(display = "Failed to parse public key.")]
    ParsePublic,
    #[fail(display = "Failed to encrypt PIN.")]
    EncryptPin,
    #[fail(display = "Failed to decrypt PIN.")]
    DecryptPin,
    #[fail(display = "Failed to verify response signature.")]
    VerifySignature,
    #[fail(display = "Failed to verify response signature.")]
    KeyType,
    #[fail(display = "Device returned error: {}", _0)]
    CborError(CborErrorCode),
    #[fail(display = "Device does not support FIDO2")]
    DeviceUnsupported,
    #[fail(display = "This operating requires a PIN but none was provided.")]
    PinRequired,
}

impl Fail for FidoError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.0.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.0.backtrace()
    }
}

// impl From<ring::error::Unspecified> for FidoError {
//     fn from(_: ring::error::Unspecified) -> Self { FidoError:: }
// }

// impl Fail for ring::error::Unspecified {
//     fn cause(&self) -> Option<&dyn Fail> {
//         None
//     }

//     fn backtrace(&self) -> Option<&failure::Backtrace> {
//         None
//     }
// }

impl Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl FidoError {
    pub fn kind(&self) -> FidoErrorKind {
        *self.0.get_context()
    }
}

impl From<FidoErrorKind> for FidoError {
    #[inline(always)]
    fn from(kind: FidoErrorKind) -> FidoError {
        FidoError(Context::new(kind))
    }
}

impl From<Context<FidoErrorKind>> for FidoError {
    fn from(inner: Context<FidoErrorKind>) -> FidoError {
        FidoError(inner)
    }
}

impl From<EncodeError> for FidoError {
    #[inline(always)]
    fn from(err: EncodeError) -> FidoError {
        FidoError(err.context(FidoErrorKind::CborEncode))
    }
}

impl From<DecodeError> for FidoError {
    #[inline(always)]
    fn from(err: DecodeError) -> FidoError {
        FidoError(err.context(FidoErrorKind::CborDecode))
    }
}

impl From<u8> for CborErrorCode {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

impl Display for CborErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        if let Some((code, _name, desc)) = self.detail() {
            write!(f, "CborError: 0x{:x?}: {}", code, desc)?;
        } else {
            write!(f, "CborError: 0x{:x?}: unknown", self.code())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cbor_error_code() {
        assert_eq!(
            CborErrorCode(0x33).to_string(),
            "CborError: 0x33: PIN authentication, pinAuth, verification failed."
        )
    }
}
