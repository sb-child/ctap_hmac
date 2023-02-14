// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//! An implementation of the CTAP2 protocol over USB.
//!
//! # Example
//!
//! ```
//! # use ctap_hmac::*;
//! # fn do_fido() -> FidoResult<()> {
//!
//!use ctap_hmac::*;
//!let device_info = get_devices()?.next().expect("no device connected");
//!let mut device = FidoDevice::new(&device_info)?;
//!
//!// This can be omitted if the FIDO device is not configured with a PIN.
//!let pin = "test";
//!device.unlock(pin)?;
//!
//!// In a real application these values would come from the requesting app.
//!let cred_request = FidoCredentialRequestBuilder::default()
//!     .rp_id("rp_id")
//!     .user_name("user_name")
//!     .build().unwrap();
//!let cred = device.make_credential(&cred_request)?;
//!let cred = &&cred;
//!let assertion_request = FidoAssertionRequestBuilder::default()
//!     .rp_id("rp_id")
//!     .credential(cred)
//!     .build().unwrap();
//!// In a real application the credential would be stored and used later.
//!let result = device.get_assertion(&assertion_request);
//!
//! # Ok(())
//! # }

#![allow(dead_code)]

extern crate failure;
extern crate rand;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate derive_builder;
extern crate byteorder;
extern crate cbor as cbor_codec;
extern crate crypto as rust_crypto;
extern crate num_traits;
extern crate ring;
extern crate untrusted;

mod cbor;
mod crypto;
mod error;
pub mod extensions;
mod hid_common;
mod hid_linux;
mod packet;
mod util;

use std::cmp;
use std::fs;
use std::io::{Cursor, Write};
use std::u16;
use std::u8;

use self::cbor::{AuthenticatorOptions, PublicKeyCredentialDescriptor};
pub use self::error::*;
use self::hid_linux as hid;
use self::packet::CtapCommand;
pub use self::util::*;
use crate::cbor::{AuthenticatorData, GetAssertionRequest};
use failure::{Fail, ResultExt};
use num_traits::FromPrimitive;
use rand::prelude::*;
use std::collections::BTreeMap;

static BROADCAST_CID: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

/// Looks for any connected HID devices and returns those that support FIDO.
pub fn get_devices() -> FidoResult<impl Iterator<Item = hid::DeviceInfo>> {
    hid::enumerate()
        .context(FidoErrorKind::Io)
        .map(|devices| devices.filter(|dev| dev.usage_page == 0xf1d0 && dev.usage == 0x01))
        .map_err(From::from)
}

/// A credential created by a FIDO2 authenticator.
#[derive(Debug, Clone)]
pub struct FidoCredential {
    /// The ID provided by the authenticator.
    pub id: Vec<u8>,
    /// The public key provided by the authenticator, in uncompressed form.
    pub public_key: Option<Vec<u8>>,
}
/// An opened FIDO authenticator.
pub struct FidoDevice {
    device: fs::File,
    packet_size: u16,
    channel_id: [u8; 4],
    needs_pin: bool,
    shared_secret: Option<crypto::SharedSecret>,
    pin_token: Option<crypto::PinToken>,
    aaguid: [u8; 16],
}

pub struct FidoCancelHandle {
    device: fs::File,
    packet_size: u16,
    channel_id: [u8; 4],
}

impl FidoCancelHandle {
    pub fn cancel(&mut self) -> FidoResult<()> {
        let payload = &[1u8];
        let to_send = payload.len() as u16;
        let max_payload = (self.packet_size - 7) as usize;
        let (frame, payload) = payload.split_at(cmp::min(payload.len(), max_payload));
        packet::write_init_packet(
            &mut self.device,
            64,
            &self.channel_id,
            &CtapCommand::Cancel,
            to_send,
            frame,
        )?;
        if payload.is_empty() {
            return Ok(());
        }
        let max_payload = (self.packet_size - 5) as usize;
        for (seq, frame) in (0..u8::MAX).zip(payload.chunks(max_payload)) {
            packet::write_cont_packet(&mut self.device, 64, &self.channel_id, seq, frame)?;
        }
        self.device.flush().context(FidoErrorKind::WritePacket)?;
        Ok(())
    }

    pub fn cancel_after<T>(&mut self, body: impl Fn(()) -> T) -> FidoResult<T> {
        let res = body(());
        match self.cancel() {
            Ok(_) => Ok(res),
            Err(e) => Err(e),
        }
    }
}

/// Request a new credential from the authenticator. The `rp_id` should be
/// a stable string used to identify the party for whom the credential is
/// created, for convenience it will be returned with the credential.
/// `user_id` and `user_name` are not required when requesting attestations
/// but they MAY be displayed to the user and MAY be stored on the device
/// to be returned with an attestation if the device supports this.
/// `client_data_hash` SHOULD be a SHA256 hash of provided `client_data`,
/// this is only used to verify the attestation provided by the
/// authenticator. When not implementing WebAuthN this can be any random
/// 32-byte array.
///
/// This method will fail if a PIN is required but the device is not
/// unlocked or if the device returns malformed data.
#[derive(Clone, Debug, Builder)]
#[builder(setter(into))]
#[builder(pattern = "owned")]
pub struct FidoCredentialRequest<'a> {
    /// create resident key
    #[builder(default)]
    rk: bool,
    /// user verification
    #[builder(default)]
    uv: bool,
    /// relying party id
    rp_id: &'a str,
    /// relying party id
    #[builder(default)]
    rp_name: Option<&'a str>,
    /// relying party icon url
    #[builder(default)]
    rp_icon_url: Option<&'a str>,
    /// user id
    #[builder(default = "&[0u8]")]
    user_id: &'a [u8],
    /// user name
    #[builder(default)]
    user_name: Option<&'a str>,
    /// user icon url
    #[builder(default)]
    user_icon_url: Option<&'a str>,
    /// user display name
    #[builder(default)]
    user_display_name: Option<&'a str>,
    #[builder(default = "&[]")]
    exclude_list: &'a [&'a FidoCredential],
    #[builder(default = "&[0u8; 32]")]
    client_data_hash: &'a [u8],
    #[builder(default)]
    extension_data: BTreeMap<&'a str, &'a cbor_codec::value::Value>,
}

impl<'a> FidoCredentialRequest<'a> {
    pub fn make_credential(&self, device: &mut FidoDevice) -> FidoResult<FidoCredential> {
        device.make_credential(&self)
    }
}

/// Request an assertion from the authenticator for a given credential.
/// `client_data_hash` SHOULD be a SHA256 hash of provided `client_data`,
/// this is signed and verified as part of the attestation. When not
/// implementing WebAuthN this can be any random 32-byte array.
///
/// This method will return whether the assertion matches the credential
/// provided, and will fail if a PIN is required but not provided or if the
/// device returns malformed data.
#[derive(Clone, Debug, Builder)]
#[builder(setter(into))]
#[builder(pattern = "owned")]
pub struct FidoAssertionRequest<'a, 'b> {
    #[builder(default)]
    up: bool,
    #[builder(default)]
    rk: bool,
    #[builder(default)]
    uv: bool,
    /// The Relying Party ID provided by the platform when this key was generated.
    rp_id: &'a str,
    credentials: &'a [&'a FidoCredential],
    #[builder(default = "&[]")]
    exclude_list: &'a [&'a FidoCredential],
    #[builder(default = "&[0u8; 32]")]
    client_data_hash: &'a [u8],
    #[builder(default)]
    extension_data: BTreeMap<&'b str, &'b cbor_codec::value::Value>,
}

impl<'a, 'b> FidoAssertionRequest<'a, 'b> {
    pub fn get_assertion(&self, device: &mut FidoDevice) -> FidoResult<&'a FidoCredential> {
        device.get_assertion(self).map(|res| res.0)
    }
}

impl<'a, 'b> FidoAssertionRequestBuilder<'a, 'b> {
    pub fn credential(mut self, credential: &'a &'a FidoCredential) -> Self {
        self.credentials = Some(std::slice::from_ref(credential));
        self
    }
}

impl FidoDevice {
    /// Open and initialize a given device. DeviceInfo is provided by the `get_devices`
    /// function. This method will allocate a channel for this application, verify that
    /// it supports FIDO2, and checks if a PIN is set.
    ///
    /// This method will fail if the device can't be opened, if the device returns
    /// malformed data or if the device is not supported.
    pub fn new(device: &hid::DeviceInfo) -> error::FidoResult<Self> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true);
        let mut dev = FidoDevice {
            device: options.open(&device.path).context(FidoErrorKind::Io)?,
            packet_size: 64,
            channel_id: BROADCAST_CID,
            needs_pin: false,
            shared_secret: None,
            pin_token: None,
            aaguid: [0; 16],
        };
        dev.init()?;
        Ok(dev)
    }

    fn init(&mut self) -> FidoResult<()> {
        let mut nonce = [0u8; 8];
        thread_rng().fill_bytes(&mut nonce);
        let response = self.exchange(CtapCommand::Init, &nonce)?;
        if response.len() < 17 || response[0..8] != nonce {
            Err(FidoErrorKind::ParseCtap)?
        }
        let flags = response[16];
        if flags & 0x04 == 0 {
            Err(FidoErrorKind::DeviceUnsupported)?
        }
        self.channel_id.copy_from_slice(&response[8..12]);
        let response = match self.cbor(cbor::Request::GetInfo)? {
            cbor::Response::GetInfo(resp) => resp,
            _ => Err(FidoErrorKind::CborDecode)?,
        };
        if !response.versions.iter().any(|ver| ["FIDO_2_0", "FIDO_2_1_PRE"].contains(&ver.as_str())) {
            Err(FidoErrorKind::DeviceUnsupported)?
        }
        // Require pin protocol version 1, only if pin-protocol is supported at all
        if !response
            .pin_protocols
            .iter()
            .any(|ver| *ver == 1) && response.pin_protocols.len() > 0
        {
            Err(FidoErrorKind::DeviceUnsupported)?
        }
        self.needs_pin = response.options.client_pin == Some(true);
        self.aaguid = response.aaguid;
        Ok(())
    }

    /// Get the authenticator's AAGUID. This is not unique to an authenticator,
    /// but it is unique to the specific brand and model.
    pub fn aaguid(&self) -> &[u8] {
        &self.aaguid
    }

    fn init_shared_secret(&mut self) -> FidoResult<()> {
        let mut request = cbor::ClientPinRequest::default();
        request.pin_protocol = 1;
        request.sub_command = 0x02; // getKeyAgreement
        let response = match self.cbor(cbor::Request::ClientPin(request))? {
            cbor::Response::ClientPin(resp) => resp,
            _ => Err(FidoErrorKind::CborDecode)?,
        };
        if let Some(key_agreement) = response.key_agreement {
            self.shared_secret = Some(crypto::SharedSecret::new(&key_agreement)?);
            Ok(())
        } else {
            Err(FidoErrorKind::CborDecode)?
        }
    }

    /// True if this authenticator requires a PIN
    pub fn needs_pin(&self) -> bool {
        self.needs_pin
    }

    /// Unlock the device with the provided PIN. Internally this will generate
    /// an ECDH keypair, send the encrypted PIN to the device and store the PIN
    /// token that the device generates on every power cycle. The PIN itself is
    /// not stored.
    ///
    /// This method will fail if the device returns malformed data or the PIN is
    /// incorrect.
    pub fn unlock(&mut self, pin: &str) -> FidoResult<()> {
        while self.shared_secret.is_none() {
            self.init_shared_secret()?;
        }
        // If the PIN is invalid the device should create a new agreementKey,
        // so we only replace shared_secret on success.
        let shared_secret = self.shared_secret.take().unwrap();
        let mut request = cbor::ClientPinRequest::default();
        request.pin_protocol = 1;
        request.sub_command = 0x05; // getPINToken
        request.key_agreement = Some(&shared_secret.public_key);
        request.pin_hash_enc = Some(shared_secret.encrypt_pin(pin)?);
        let response = match self.cbor(cbor::Request::ClientPin(request))? {
            cbor::Response::ClientPin(resp) => resp,
            _ => Err(FidoErrorKind::CborDecode)?,
        };
        if let Some(mut pin_token) = response.pin_token {
            self.pin_token = Some(shared_secret.decrypt_token(&mut pin_token)?);
            self.shared_secret = Some(shared_secret);
            Ok(())
        } else {
            Err(FidoErrorKind::CborDecode)?
        }
    }

    pub fn cancel_handle(&mut self) -> FidoResult<FidoCancelHandle> {
        Ok(self
            .device
            .try_clone()
            .map(|device| FidoCancelHandle {
                device,
                packet_size: self.packet_size,
                channel_id: self.channel_id,
            })
            .context(FidoErrorKind::Io)?)
    }

    pub fn make_credential(
        &mut self,
        request: &FidoCredentialRequest<'_>,
    ) -> FidoResult<FidoCredential> {
        let rp = cbor::PublicKeyCredentialRpEntity {
            id: request.rp_id,
            name: request.rp_name,
            icon: request.rp_icon_url,
        };
        let user = cbor::PublicKeyCredentialUserEntity {
            id: request.user_id,
            name: request.user_name.unwrap_or(""),
            icon: request.user_icon_url,
            display_name: request.user_display_name,
        };

        let options = Some(AuthenticatorOptions {
            up: false,
            uv: request.uv,
            rk: request.rk,
        });
        if self.needs_pin && self.pin_token.is_none() {
            Err(FidoErrorKind::PinRequired)?
        }
        if request.client_data_hash.len() != 32 {
            Err(FidoErrorKind::CborEncode)?
        }
        while self.shared_secret.is_none() {
            self.init_shared_secret()?;
        }
        let pub_key_cred_params = [("public-key", -7)];
        let pin_auth = self
            .pin_token
            .as_ref()
            .map(|token| token.auth(&request.client_data_hash));
        let request = cbor::MakeCredentialRequest {
            client_data_hash: request.client_data_hash,
            rp,
            user,
            pub_key_cred_params: &pub_key_cred_params,
            exclude_list: &request
                .exclude_list
                .iter()
                .map(|cred| PublicKeyCredentialDescriptor {
                    cred_type: "public-key".into(),
                    id: cred.id.clone(),
                })
                .collect::<Vec<_>>()[..],
            extensions: &request
                .extension_data
                .iter()
                .map(|(name, data)| (*name, *data))
                .collect::<Vec<_>>()[..],
            options,
            pin_auth,
            pin_protocol: pin_auth.and(Some(0x01)),
        };

        let response = match self.cbor(cbor::Request::MakeCredential(request))? {
            cbor::Response::MakeCredential(resp) => resp,
            _ => Err(FidoErrorKind::CborDecode)?,
        };
        let public_key = cbor::P256Key::from_cose(
            &response
                .auth_data
                .attested_credential_data
                .credential_public_key,
        )?
        .bytes();
        Ok(FidoCredential {
            id: response.auth_data.attested_credential_data.credential_id,
            public_key: Some(Vec::from(&public_key[..])),
        })
    }

    /// Request a new credential from the authenticator. The `rp_id` should be
    /// a stable string used to identify the party for whom the credential is
    /// created, for convenience it will be returned with the credential.
    /// `user_id` and `user_name` are not required when requesting attestations
    /// but they MAY be displayed to the user and MAY be stored on the device
    /// to be returned with an attestation if the device supports this.
    /// `client_data_hash` SHOULD be a SHA256 hash of provided `client_data`,
    /// this is only used to verify the attestation provided by the
    /// authenticator. When not implementing WebAuthN this can be any random
    /// 32-byte array.
    ///
    /// This method will fail if a PIN is required but the device is not
    /// unlocked or if the device returns malformed data.
    pub fn get_assertion<'a, 'b>(
        &mut self,
        assertion: &FidoAssertionRequest<'a, 'b>,
    ) -> FidoResult<(&'a FidoCredential, AuthenticatorData)> {
        while self.shared_secret.is_none() {
            self.init_shared_secret()?;
        }
        if self.needs_pin && self.pin_token.is_none() {
            Err(FidoErrorKind::PinRequired)?
        }
        if assertion.client_data_hash.len() != 32 {
            Err(FidoErrorKind::CborEncode)?
        }
        let pin_auth = self
            .pin_token
            .as_ref()
            .map(|token| token.auth(&assertion.client_data_hash));
        let request = GetAssertionRequest {
            rp_id: assertion.rp_id,
            client_data_hash: assertion.client_data_hash,
            allow_list: &assertion
                .credentials
                .iter()
                .map(|cred| PublicKeyCredentialDescriptor {
                    cred_type: "public-key".into(),
                    id: cred.id.clone(),
                })
                .collect::<Vec<_>>()[..],
            extensions: &assertion
                .extension_data
                .iter()
                .map(|(name, data)| (*name, *data))
                .collect::<Vec<_>>()[..],
            options: Some(AuthenticatorOptions {
                rk: assertion.rk,
                uv: assertion.uv,
                up: assertion.up,
            }),
            pin_auth: pin_auth,
            pin_protocol: pin_auth.and(Some(0x01)),
        };
        let response = match self.cbor(cbor::Request::GetAssertion(request))? {
            cbor::Response::GetAssertion(resp) => resp,
            _ => Err(FidoErrorKind::CborDecode)?,
        };
        let credential = assertion
            .credentials
            .iter()
            .flat_map(|cred| {
                response
                    .credential
                    .as_ref()
                    .filter(|rcred| rcred.id == cred.id)
                    .map(|_| *cred)
            })
            .next();

        credential
            .and_then(|cred| {
                if cred
                    .public_key
                    .as_ref()
                    .map(|public_key| {
                        crypto::verify_signature(
                            &public_key,
                            &assertion.client_data_hash,
                            &response.auth_data_bytes,
                            &response.signature,
                        )
                    })
                    .unwrap_or(true)
                {
                    Some(cred)
                } else {
                    None
                }
            })
            .ok_or(FidoError::from(FidoErrorKind::VerifySignature))
            .map(|cred| (cred, response.auth_data))
    }

    fn cbor(&mut self, request: cbor::Request) -> FidoResult<cbor::Response> {
        let mut buf = Cursor::new(Vec::new());
        request
            .encode(&mut buf)
            .context(FidoErrorKind::CborEncode)?;
        let response = self.exchange(CtapCommand::Cbor, &buf.into_inner())?;
        request
            .decode(Cursor::new(response))
            .context(FidoErrorKind::CborDecode)
            .map_err(From::from)
    }

    fn exchange(&mut self, cmd: CtapCommand, payload: &[u8]) -> FidoResult<Vec<u8>> {
        self.send(&cmd, payload)?;
        self.receive(&cmd)
    }

    fn send(&mut self, cmd: &CtapCommand, payload: &[u8]) -> FidoResult<()> {
        if payload.is_empty() || payload.len() > u16::MAX as usize {
            Err(FidoErrorKind::WritePacket)?
        }
        let to_send = payload.len() as u16;
        let max_payload = (self.packet_size - 7) as usize;
        let (frame, payload) = payload.split_at(cmp::min(payload.len(), max_payload));
        packet::write_init_packet(&mut self.device, 64, &self.channel_id, cmd, to_send, frame)?;
        if payload.is_empty() {
            return Ok(());
        }
        let max_payload = (self.packet_size - 5) as usize;
        for (seq, frame) in (0..u8::MAX).zip(payload.chunks(max_payload)) {
            packet::write_cont_packet(&mut self.device, 64, &self.channel_id, seq, frame)?;
        }
        self.device.flush().context(FidoErrorKind::WritePacket)?;
        Ok(())
    }

    fn receive(&mut self, cmd: &CtapCommand) -> FidoResult<Vec<u8>> {
        let mut first_packet: Option<packet::InitPacket> = None;
        while first_packet.is_none() {
            let packet = packet::InitPacket::from_reader(&mut self.device, 64)?;
            if packet.cmd == CtapCommand::Error {
                Err(packet::CtapError::from_u8(packet.payload[0])
                    .unwrap_or(packet::CtapError::Other)
                    .context(FidoErrorKind::ParseCtap))?
            }
            if packet.cid == self.channel_id && &packet.cmd == cmd {
                first_packet = Some(packet);
            }
        }
        let first_packet = first_packet.unwrap();
        let mut data = first_packet.payload;
        let mut to_read = (first_packet.size as isize) - data.len() as isize;
        let mut seq = 0;
        while to_read > 0 {
            let packet = packet::ContPacket::from_reader(&mut self.device, 64, to_read as usize)?;
            if packet.cid != self.channel_id {
                continue;
            }
            if packet.seq != seq {
                Err(FidoErrorKind::InvalidSequence)?
            }
            to_read -= packet.payload.len() as isize;
            data.extend(&packet.payload);
            seq += 1;
        }
        Ok(data)
    }
}
