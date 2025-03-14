use crate::TrussedRequirements;
use cosey::EcdhEsHkdf256PublicKey;
use ctap_types::{ctap2::client_pin::Permissions, Error, Result};
use trussed::{
    cbor_deserialize, cbor_serialize_bytes,
    client::{CryptoClient, HmacSha256, P256},
    syscall, try_syscall,
    types::{
        Bytes, KeyId, KeySerialization, Location, Mechanism, Message, ShortData, StorageAttributes,
        String,
    },
};
use trussed_hkdf::{KeyOrData, OkmId};
use core::{default, ops::Deref};

// PIN protocol 1 supports 16 or 32 bytes, PIN protocol 2 requires 32 bytes.
const PIN_TOKEN_LENGTH: usize = 32;
const CTAP2_HMAC_KEY: &[u8; 14] = b"CTAP2 HMAC key";
const CTAP2_AES_KEY: &[u8; 13] = b"CTAP2 AES key";
const CTAP2_CLIENT_KEY: &[u8; 19] = b"CTAP2.1+ Client key";
const CTAP2_TOKEN_KEY: &[u8; 18] = b"CTAP2.1+ Token key";

#[derive(Clone, Copy, Debug)]
pub enum PinProtocolVersion {
    V1,
    V2,
}

impl From<PinProtocolVersion> for u8 {
    fn from(version: PinProtocolVersion) -> Self {
        match version {
            PinProtocolVersion::V1 => 1,
            PinProtocolVersion::V2 => 2,
        }
    }
}

#[derive(Debug)]
pub enum RpScope<'a> {
    All,
    RpId(&'a str),
    RpIdHash(&'a [u8; 32]),
}

#[derive(Debug)]
pub struct ExpandedPinToken {
    // CTAP2.1+ expanded pin token to authenticate messages Client -> Token
    client_key: KeyId,
    // CTAP2.1+ expanded pin token to authenticate messages Token -> Client
    token_key: KeyId,
}

#[derive(Debug)]
pub struct PinToken {
    key_id: KeyId,
    // CTAP2.1+ expansion
    expanded_pin_token: Option<ExpandedPinToken>,
    state: PinTokenState,
}

impl PinToken {
    fn generate<T: HmacSha256>(trussed: &mut T) -> PinToken {
        let key_id =
            syscall!(trussed.generate_secret_key(PIN_TOKEN_LENGTH, Location::Volatile)).key;
        Self::new(key_id)
    }

    fn new(key_id: KeyId) -> Self {
        Self {
            key_id,
            expanded_pin_token: Default::default(),
            state: Default::default(),
        }
    }

    fn delete<T: CryptoClient>(mut self, trussed: &mut T) {
        syscall!(trussed.delete(self.key_id));
        if self.expanded_pin_token.is_some() {
            syscall!(trussed.delete(self.expanded_pin_token.as_ref().unwrap().client_key));
            syscall!(trussed.delete(self.expanded_pin_token.as_ref().unwrap().token_key));
            self.expanded_pin_token = None;
        }
    }

    pub fn require_permissions(&self, permissions: Permissions) -> Result<()> {
        if self.state.permissions.contains(permissions) {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    fn is_valid_for_rp(&self, scope: RpScope<'_>) -> bool {
        if let Some(rp) = self.state.rp.as_ref() {
            // if an RP id is set, the token is only valid for that scope
            match scope {
                RpScope::All => false,
                RpScope::RpId(rp_id) => rp.id == rp_id,
                RpScope::RpIdHash(hash) => &rp.hash == hash,
            }
        } else {
            // if no RP ID is set, the token is valid for all scopes
            true
        }
    }

    pub fn require_valid_for_rp(&self, scope: RpScope<'_>) -> Result<()> {
        if self.is_valid_for_rp(scope) {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }
}

#[derive(Debug)]
pub struct PinTokenMut<'a, T: CryptoClient> {
    pin_token: &'a mut PinToken,
    trussed: &'a mut T,
}

impl<T: CryptoClient> PinTokenMut<'_, T> {
    pub fn restrict(&mut self, permissions: Permissions, rp_id: Option<String<256>>) {
        self.pin_token.state.permissions = permissions;
        self.pin_token.state.rp = rp_id.map(|id| Rp::new(self.trussed, id));
    }

    // in spec: encrypt(..., pinUvAuthToken)
    pub fn encrypt(&mut self, shared_secret: &SharedSecret) -> Result<Bytes<48>> {
        let token = shared_secret.wrap(self.trussed, self.pin_token.key_id);
        Bytes::from_slice(&token).map_err(|_| Error::Other)
    }
}

#[derive(Debug)]
struct Rp {
    id: String<256>,
    hash: [u8; 32],
}

impl Rp {
    fn new<T: CryptoClient>(trussed: &mut T, id: String<256>) -> Self {
        let hash =
            syscall!(trussed.hash(Mechanism::Sha256, Message::from_slice(id.as_ref()).unwrap()))
                .hash
                .as_slice()
                .try_into()
                .unwrap();
        Self { id, hash }
    }
}

#[derive(Debug, Default)]
struct PinTokenState {
    permissions: Permissions,
    rp: Option<Rp>,
    is_user_present: bool,
    is_user_verified: bool,
    is_in_use: bool,
}

#[derive(Debug)]
pub struct PinProtocolState {
    key_agreement_key: KeyId,
    // only used to delete the old shared secret from VFS when generating a new one.  ideally, the
    // SharedSecret struct would clean up after itself.
    shared_secret: Option<SharedSecret>,

    // for protocol version 1
    pin_token_v1: Option<PinToken>,
    // for protocol version 2
    pin_token_v2: Option<PinToken>,
}

impl PinProtocolState {
    // in spec: initialize(...)
    pub fn new<T: TrussedRequirements>(trussed: &mut T) -> Self {
        Self {
            key_agreement_key: generate_key_agreement_key(trussed),
            shared_secret: None,
            pin_token_v1: None,
            pin_token_v2: None,
        }
    }

    pub fn reset<T: TrussedRequirements>(self, trussed: &mut T) {
        if let Some(token) = self.pin_token_v1 {
            token.delete(trussed);
        }
        if let Some(token) = self.pin_token_v2 {
            token.delete(trussed);
        }
        syscall!(trussed.delete(self.key_agreement_key));
        if let Some(shared_secret) = self.shared_secret {
            shared_secret.delete(trussed);
        }
    }
}

#[derive(Debug)]
pub struct PinProtocol<'a, T: TrussedRequirements> {
    trussed: &'a mut T,
    state: &'a mut PinProtocolState,
    version: PinProtocolVersion,
}

impl<'a, T: TrussedRequirements> PinProtocol<'a, T> {
    pub fn new(
        trussed: &'a mut T,
        state: &'a mut PinProtocolState,
        version: PinProtocolVersion,
    ) -> Self {
        Self {
            trussed,
            state,
            version,
        }
    }

    fn pin_token(&self) -> Option<&PinToken> {
        match self.version {
            PinProtocolVersion::V1 => self.state.pin_token_v1.as_ref(),
            PinProtocolVersion::V2 => self.state.pin_token_v2.as_ref(),
        }
    }

    pub fn regenerate(&mut self) {
        syscall!(self.trussed.delete(self.state.key_agreement_key));
        if let Some(shared_secret) = self.state.shared_secret.take() {
            shared_secret.delete(self.trussed);
        }
        self.state.key_agreement_key = generate_key_agreement_key(self.trussed);
    }

    // in spec: resetPinUvAuthToken()
    pub fn reset_pin_tokens(&mut self) {
        if let Some(token) = self.state.pin_token_v1.take() {
            token.delete(self.trussed);
        }
        if let Some(token) = self.state.pin_token_v2.take() {
            token.delete(self.trussed);
        }
    }

    // in spec: beginUsingPinUvAuthToken(userIsPresent)
    fn begin_using_pin_token(&mut self, is_user_present: bool) -> PinTokenMut<'_, T> {
        // we assume that the previous PIN token has already been reset so we don’t need to delete it
        let mut pin_token = PinToken::generate(self.trussed);
        pin_token.state.is_user_present = is_user_present;
        pin_token.state.is_user_verified = true;
        // TODO: set initial usage time limit
        // TODO: start and observe usage timer
        pin_token.state.is_in_use = true;
        let pin_token_field = match self.version {
            PinProtocolVersion::V1 => &mut self.state.pin_token_v1,
            PinProtocolVersion::V2 => &mut self.state.pin_token_v2,
        };
        let pin_token = pin_token_field.insert(pin_token);
        PinTokenMut {
            pin_token,
            trussed: self.trussed,
        }
    }

    pub fn reset_and_begin_using_pin_token(&mut self, is_user_present: bool) -> PinTokenMut<'_, T> {
        self.reset_pin_tokens();
        self.begin_using_pin_token(is_user_present)
    }

    // in spec: getPublicKey
    #[must_use]
    pub fn key_agreement_key(&mut self) -> EcdhEsHkdf256PublicKey {
        // CTAP2.1++
        self.regenerate();
        let public_key = syscall!(self
            .trussed
            .derive_p256_public_key(self.state.key_agreement_key, Location::Volatile))
        .key;
        let serialized_cose_key = syscall!(self.trussed.serialize_key(
            Mechanism::P256,
            public_key,
            KeySerialization::EcdhEsHkdf256
        ))
        .serialized_key;
        let cose_key = cbor_deserialize(&serialized_cose_key).unwrap();
        syscall!(self.trussed.delete(public_key));
        cose_key
    }

    #[must_use]
    fn verify(&mut self, key: KeyId, data: &[u8], signature: &[u8]) -> bool {
        let actual_signature = syscall!(self.trussed.sign_hmacsha256(key, data)).signature;
        let expected_signature = match self.version {
            PinProtocolVersion::V1 => &actual_signature[..16],
            PinProtocolVersion::V2 => &actual_signature,
        };
        expected_signature == signature
    }

    // in spec: verify(pinUvAuthToken, ...)
    // CTAP2.1+ -> verifies pin auth using either the pintoken in CTAP2 or the expanded pin token from CTAP2.1+
    // TODO: Restructure function to avoid two "if mutual"
    pub fn verify_pin_token(&mut self, data: &[u8], signature: &[u8], mutual: bool) -> Result<&PinToken> {
        if mutual {   
            self.expand_pin_token()?;
        };
        let pin_token = self.pin_token().ok_or(Error::PinAuthInvalid)?;
        let key_id = if mutual { pin_token.expanded_pin_token.as_ref().unwrap().client_key } else { pin_token.key_id };
        if pin_token.state.is_in_use && self.verify(key_id, data, signature) {
            // We previously checked that `pin_token()` is not None in the first line of this
            // function so this cannot panic, but we cannot return the `pin_token` variable here
            // because of the `verify` call after it.
            Ok(self.pin_token().unwrap())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    // in spec: verify(shared secret, ...)
    pub fn verify_pin_auth(
        &mut self,
        shared_secret: &SharedSecret,
        data: &[u8],
        pin_auth: &[u8],
    ) -> Result<()> {
        let key_id = shared_secret.hmac_key_id();
        if self.verify(key_id, data, pin_auth) {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    // in spec: decapsulate(...) = ecdh(...)
    // The returned key ID is valid until the next call of shared_secret or regenerate.  The caller
    // has to delete the key from the VFS after end of use.  Ideally, this should be enforced by
    // the compiler, for example by using a callback.
    pub fn shared_secret(&mut self, peer_key: &EcdhEsHkdf256PublicKey) -> Result<SharedSecret> {
        self.shared_secret_impl(peer_key)
            .ok_or(Error::InvalidParameter)
    }

    fn shared_secret_impl(&mut self, peer_key: &EcdhEsHkdf256PublicKey) -> Option<SharedSecret> {
        let serialized_peer_key: Message = cbor_serialize_bytes(peer_key).ok()?;
        let peer_key = try_syscall!(self.trussed.deserialize_p256_key(
            &serialized_peer_key,
            KeySerialization::EcdhEsHkdf256,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .ok()?
        .key;

        let result = try_syscall!(self.trussed.agree(
            Mechanism::P256,
            self.state.key_agreement_key,
            peer_key,
            StorageAttributes::new().set_persistence(Location::Volatile),
        ));
        syscall!(self.trussed.delete(peer_key));
        let pre_shared_secret = result.ok()?.shared_secret;

        if let Some(shared_secret) = self.state.shared_secret.take() {
            shared_secret.delete(self.trussed);
        }

        let shared_secret = self.kdf(pre_shared_secret);
        syscall!(self.trussed.delete(pre_shared_secret));

        let shared_secret = shared_secret?;
        self.state.shared_secret = Some(shared_secret.clone());
        Some(shared_secret)
    }

    fn kdf(&mut self, input: KeyId) -> Option<SharedSecret> {
        match self.version {
            PinProtocolVersion::V1 => self.kdf_v1(input),
            PinProtocolVersion::V2 => self.kdf_v2(input),
        }
    }

    // PIN protocol 1: derive a single key using SHA-256
    fn kdf_v1(&mut self, input: KeyId) -> Option<SharedSecret> {
        let key_id = syscall!(self.trussed.derive_key(
            Mechanism::Sha256,
            input,
            None,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .key;
        Some(SharedSecret::V1 { key_id })
    }

    // PIN protocol 2: derive two keys using HKDF-SHA-256
    // In the spec, the keys are concatenated and the relevant part is selected during the key
    // operations.  For simplicity, we store two separate keys instead.
    fn kdf_v2(&mut self, input: KeyId) -> Option<SharedSecret> {
        fn hkdf<T: TrussedRequirements>(trussed: &mut T, okm: OkmId, info: &[u8]) -> Option<KeyId> {
            let info = Message::from_slice(info).ok()?;
            try_syscall!(trussed.hkdf_expand(okm, info, 32, Location::Volatile))
                .ok()
                .map(|reply| reply.key)
        }

        // salt: 0x00 * 32 => None
        let okm = try_syscall!(self.trussed.hkdf_extract(
            KeyOrData::Key(input),
            None,
            Location::Volatile
        ))
        .ok()?
        .okm;
        let hmac_key_id = hkdf(self.trussed, okm, CTAP2_HMAC_KEY);
        let aes_key_id = hkdf(self.trussed, okm, CTAP2_AES_KEY);

        syscall!(self.trussed.delete(okm.0));

        Some(SharedSecret::V2 {
            hmac_key_id: hmac_key_id?,
            aes_key_id: aes_key_id?,
        })
    }

    // CTAP2.1+: derive two keys from pintoken using HKDF-SHA-256
    fn kdf_mpaca(&mut self, input: KeyId) -> Option<ExpandedPinToken> {
        fn hkdf<T: TrussedRequirements>(trussed: &mut T, okm: OkmId, info: &[u8]) -> Option<KeyId> {
            let info = Message::from_slice(info).ok()?;
            try_syscall!(trussed.hkdf_expand(okm, info, 32, Location::Volatile))
                .ok()
                .map(|reply| reply.key)
        }

        // salt: 0x00 * 32 => None
        let okm = try_syscall!(self.trussed.hkdf_extract(
            KeyOrData::Key(input),
            None,
            Location::Volatile
        ))
        .ok()?
        .okm;
        let client_key = hkdf(self.trussed, okm, CTAP2_CLIENT_KEY);
        let token_key = hkdf(self.trussed, okm, CTAP2_TOKEN_KEY);

        syscall!(self.trussed.delete(okm.0));

        Some(ExpandedPinToken {
            client_key: client_key?,
            token_key: token_key?,
        })
    }
    
    // CTAP2.1+ function to expand the pin_token for mutual authentication
    fn expand_pin_token(&mut self) -> Result<()> {
        if (self.is_pin_token_expanded()) {
            return Ok(())
        }
        let pin_token = {
            let pin_token = self.pin_token().unwrap();
            pin_token
        };
        //CTAP2.1+ TODO: deal with potential errors here with unwrap
        let expanded_pin_token = self.kdf_mpaca(pin_token.key_id).unwrap();
        let pin_token = self.state.pin_token_v2.as_mut().unwrap();
        pin_token.expanded_pin_token = Some(expanded_pin_token);
        Ok(())
    }

    pub fn authenticate_response(&mut self, data: &[u8]) -> Result<[u8;32]>{
        if !self.is_pin_token_expanded() {
            return Err(Error::CannotAuthenticateResponse);
        }
        let pin_token = self.pin_token().ok_or(Error::PinAuthInvalid)?;
        if pin_token.state.is_in_use {
            let mut signature = [0u8;32];
            let key = pin_token.expanded_pin_token.as_ref().ok_or(Error::CannotAuthenticateResponse)?;
            signature.copy_from_slice(&syscall!(self.trussed.sign_hmacsha256(key.token_key, data)).signature[..]);
            Ok(signature)
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    fn is_pin_token_expanded(&self) -> bool {
        if let Some(x) = self.pin_token() {
            return x.expanded_pin_token.is_some()
        }
        false
    }
}

#[derive(Clone, Debug)]
pub enum SharedSecret {
    V1 {
        key_id: KeyId,
    },
    V2 {
        hmac_key_id: KeyId,
        aes_key_id: KeyId,
    },
}

impl SharedSecret {
    fn aes_key_id(&self) -> KeyId {
        match self {
            Self::V1 { key_id } => *key_id,
            Self::V2 { aes_key_id, .. } => *aes_key_id,
        }
    }

    fn hmac_key_id(&self) -> KeyId {
        match self {
            Self::V1 { key_id } => *key_id,
            Self::V2 { hmac_key_id, .. } => *hmac_key_id,
        }
    }

    fn generate_iv<T: CryptoClient>(&self, trussed: &mut T) -> ShortData {
        match self {
            Self::V1 { .. } => ShortData::from_slice(&[0; 16]).unwrap(),
            Self::V2 { .. } => syscall!(trussed.random_bytes(16))
                .bytes
                .try_convert_into()
                .unwrap(),
        }
    }

    #[must_use]
    pub fn encrypt<T: CryptoClient>(&self, trussed: &mut T, data: &[u8]) -> Bytes<1024> {
        let key_id = self.aes_key_id();
        let iv = self.generate_iv(trussed);
        let mut ciphertext =
            syscall!(trussed.encrypt(Mechanism::Aes256Cbc, key_id, data, &[], Some(iv.clone())))
                .ciphertext;
        if matches!(self, Self::V2 { .. }) {
            ciphertext.insert_slice_at(&iv, 0).unwrap();
        }
        ciphertext
    }

    #[must_use]
    fn wrap<T: CryptoClient>(&self, trussed: &mut T, key: KeyId) -> Bytes<1024> {
        let wrapping_key = self.aes_key_id();
        let iv = self.generate_iv(trussed);
        let mut wrapped_key = syscall!(trussed.wrap_key(
            Mechanism::Aes256Cbc,
            wrapping_key,
            key,
            &[],
            Some(iv.clone())
        ))
        .wrapped_key;
        if matches!(self, Self::V2 { .. }) {
            wrapped_key.insert_slice_at(&iv, 0).unwrap();
        }
        wrapped_key
    }

    #[must_use]
    pub fn decrypt<T: CryptoClient>(&self, trussed: &mut T, data: &[u8]) -> Option<Bytes<1024>> {
        let key_id = self.aes_key_id();
        let (iv, data) = match self {
            Self::V1 { .. } => (Default::default(), data),
            Self::V2 { .. } => {
                if data.len() < 16 {
                    return None;
                }
                data.split_at(16)
            }
        };
        try_syscall!(trussed.decrypt(Mechanism::Aes256Cbc, key_id, data, b"", iv, b""))
            .ok()
            .and_then(|response| response.plaintext)
    }

    pub fn delete<T: CryptoClient>(self, trussed: &mut T) {
        match self {
            Self::V1 { key_id } => {
                syscall!(trussed.delete(key_id));
            }
            Self::V2 {
                hmac_key_id,
                aes_key_id,
            } => {
                for key_id in [hmac_key_id, aes_key_id] {
                    syscall!(trussed.delete(key_id));
                }
            }
        }
    }
}

fn generate_key_agreement_key<T: P256>(trussed: &mut T) -> KeyId {
    syscall!(trussed.generate_p256_private_key(Location::Volatile)).key
}
