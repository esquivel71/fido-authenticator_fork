#![cfg(feature = "dispatch")]

pub mod virt;
pub mod webauthn;

use std::collections::BTreeMap;

use ciborium::Value;
use hex_literal::hex;

use virt::{Ctap2, Ctap2Error};
use webauthn::{
    AttStmtFormat, ClientPin, CredentialManagement, CredentialManagementParams, ExtensionsInput,
    GetAssertion, GetInfo, KeyAgreementKey, MakeCredential, MakeCredentialOptions, PinToken,
    PubKeyCredDescriptor, PubKeyCredParam, PublicKey, Rp, SharedSecret, User,
};

#[test]
fn test_ping() {
    virt::run_ctaphid(|device| {
        device.ping(&[0xf1, 0xd0]).unwrap();
    });
}

#[test]
fn test_get_info() {
    virt::run_ctap2(|device| {
        let reply = device.exec(GetInfo).unwrap();
        assert!(reply.versions.contains(&"FIDO_2_0".to_owned()));
        assert!(reply.versions.contains(&"FIDO_2_1".to_owned()));
        assert_eq!(
            reply.aaguid.as_bytes().unwrap(),
            &hex!("8BC5496807B14D5FB249607F5D527DA2")
        );
        assert_eq!(reply.pin_protocols, Some(vec![2, 1]));
        assert_eq!(
            reply.attestation_formats,
            Some(vec!["packed".to_owned(), "none".to_owned()])
        );
    });
}

fn get_shared_secret(device: &Ctap2, platform_key_agreement: &KeyAgreementKey) -> SharedSecret {
    let reply = device.exec(ClientPin::new(2, 2)).unwrap();
    let authenticator_key_agreement: PublicKey = reply.key_agreement.unwrap().into();
    platform_key_agreement.shared_secret(&authenticator_key_agreement)
}

fn set_pin(
    device: &Ctap2,
    key_agreement_key: &KeyAgreementKey,
    shared_secret: &SharedSecret,
    pin: &[u8],
) {
    let mut padded_pin = [0; 64];
    padded_pin[..pin.len()].copy_from_slice(pin);
    let pin_enc = shared_secret.encrypt(&padded_pin);
    let pin_auth = shared_secret.authenticate(&pin_enc);
    let mut request = ClientPin::new(2, 3);
    request.key_agreement = Some(key_agreement_key.public_key());
    request.new_pin_enc = Some(pin_enc);
    request.pin_auth = Some(pin_auth);
    device.exec(request).unwrap();
}

#[test]
fn test_set_pin() {
    let key_agreement_key = KeyAgreementKey::generate();
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, b"123456");
    })
}

fn get_pin_token(
    device: &Ctap2,
    key_agreement_key: &KeyAgreementKey,
    shared_secret: &SharedSecret,
    pin: &[u8],
    permissions: u8,
    rp_id: Option<String>,
) -> PinToken {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(pin);
    let pin_hash = hasher.finalize();
    let pin_hash_enc = shared_secret.encrypt(&pin_hash[..16]);
    let mut request = ClientPin::new(2, 9);
    request.key_agreement = Some(key_agreement_key.public_key());
    request.pin_hash_enc = Some(pin_hash_enc);
    request.permissions = Some(permissions);
    request.rp_id = rp_id;
    let reply = device.exec(request).unwrap();
    let encrypted_pin_token = reply.pin_token.as_ref().unwrap().as_bytes().unwrap();
    shared_secret.decrypt_pin_token(encrypted_pin_token)
}

#[test]
fn test_get_pin_token() {
    let key_agreement_key = KeyAgreementKey::generate();
    let pin = b"123456";
    virt::run_ctap2(|device| {
        let shared_secret = get_shared_secret(&device, &key_agreement_key);
        set_pin(&device, &key_agreement_key, &shared_secret, pin);
        get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None);
    })
}

#[derive(Clone, Debug)]
struct RequestPinToken {
    permissions: u8,
    rp_id: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum AttestationFormatsPreference {
    Empty,
    None,
    Packed,
    NonePacked,
    PackedNone,
    OtherNonePacked,
    MultiOtherNonePacked,
}

impl AttestationFormatsPreference {
    const ALL: &'static [Self] = &[
        Self::Empty,
        Self::None,
        Self::Packed,
        Self::NonePacked,
        Self::PackedNone,
        Self::OtherNonePacked,
        Self::MultiOtherNonePacked,
    ];

    fn format(&self) -> Option<AttStmtFormat> {
        match self {
            Self::Empty | Self::Packed | Self::PackedNone => Some(AttStmtFormat::Packed),
            Self::NonePacked | Self::OtherNonePacked | Self::MultiOtherNonePacked => {
                Some(AttStmtFormat::None)
            }
            Self::None => None,
        }
    }
}

impl From<AttestationFormatsPreference> for Vec<&'static str> {
    fn from(preference: AttestationFormatsPreference) -> Self {
        let mut vec = Vec::new();
        match preference {
            AttestationFormatsPreference::Empty => {}
            AttestationFormatsPreference::None => {
                vec.push("none");
            }
            AttestationFormatsPreference::Packed => {
                vec.push("packed");
            }
            AttestationFormatsPreference::NonePacked => {
                vec.push("none");
                vec.push("packed");
            }
            AttestationFormatsPreference::PackedNone => {
                vec.push("packed");
                vec.push("none");
            }
            AttestationFormatsPreference::OtherNonePacked => {
                vec.push("tpm");
                vec.push("none");
                vec.push("packed");
            }
            AttestationFormatsPreference::MultiOtherNonePacked => {
                vec.resize(100, "tpm");
                vec.push("none");
                vec.push("packed");
            }
        }
        vec
    }
}

#[derive(Debug)]
struct TestMakeCredential {
    pin_token: Option<RequestPinToken>,
    pub_key_alg: i32,
    attestation_formats_preference: Option<AttestationFormatsPreference>,
}

impl TestMakeCredential {
    fn run(&self) {
        println!("{}", "=".repeat(80));
        println!("Running test:");
        println!("{self:#?}");
        println!();

        let key_agreement_key = KeyAgreementKey::generate();
        let pin = b"123456";
        let rp_id = "example.com";
        // TODO: client data
        let client_data_hash = b"";

        virt::run_ctap2(|device| {
            let pin_auth = self.pin_token.as_ref().map(|pin_token| {
                let shared_secret = get_shared_secret(&device, &key_agreement_key);
                set_pin(&device, &key_agreement_key, &shared_secret, pin);
                let pin_token = get_pin_token(
                    &device,
                    &key_agreement_key,
                    &shared_secret,
                    pin,
                    pin_token.permissions,
                    pin_token.rp_id.clone(),
                );
                pin_token.authenticate(client_data_hash)
            });

            let rp = Rp::new(rp_id);
            let user = User::new(b"id123")
                .name("john.doe")
                .display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", self.pub_key_alg)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            if let Some(pin_auth) = pin_auth {
                request.pin_auth = Some(pin_auth);
                request.pin_protocol = Some(2);
            }
            request.attestation_formats_preference =
                self.attestation_formats_preference.map(From::from);

            let result = device.exec(request);
            if let Some(error) = self.expected_error() {
                assert_eq!(result, Err(Ctap2Error(error)));
            } else {
                let reply = result.unwrap();
                assert!(reply.auth_data.credential.is_some());
                let format = self
                    .attestation_formats_preference
                    .unwrap_or(AttestationFormatsPreference::Packed)
                    .format();
                if let Some(format) = format {
                    assert_eq!(reply.fmt, format.as_str());
                    reply.att_stmt.unwrap().validate(format, &reply.auth_data);
                } else {
                    assert_eq!(reply.fmt, AttStmtFormat::None.as_str());
                    assert!(reply.att_stmt.is_none());
                }
            }
        });
    }

    fn expected_error(&self) -> Option<u8> {
        if let Some(pin_token) = &self.pin_token {
            if pin_token.permissions != 0x01 {
                return Some(0x33);
            }
            if let Some(rp_id) = &pin_token.rp_id {
                if rp_id != "example.com" {
                    return Some(0x33);
                }
            }
        }
        if self.pub_key_alg != -7 {
            return Some(0x26);
        }
        None
    }
}

#[test]
fn test_make_credential() {
    let pin_tokens = [
        None,
        Some(RequestPinToken {
            permissions: 0x01,
            rp_id: None,
        }),
        Some(RequestPinToken {
            permissions: 0x01,
            rp_id: Some("example.com".to_owned()),
        }),
        Some(RequestPinToken {
            permissions: 0x01,
            rp_id: Some("test.com".to_owned()),
        }),
        Some(RequestPinToken {
            permissions: 0x04,
            rp_id: None,
        }),
    ];
    for pin_token in pin_tokens {
        for pub_key_alg in [-7, -11] {
            TestMakeCredential {
                pin_token: pin_token.clone(),
                pub_key_alg,
                attestation_formats_preference: None,
            }
            .run();
            for attestation_formats_preference in AttestationFormatsPreference::ALL {
                TestMakeCredential {
                    pin_token: pin_token.clone(),
                    pub_key_alg,
                    attestation_formats_preference: Some(*attestation_formats_preference),
                }
                .run();
            }
        }
    }
}

#[derive(Debug)]
struct TestGetAssertion {
    mc_third_party_payment: Option<bool>,
    ga_third_party_payment: Option<bool>,
}

impl TestGetAssertion {
    fn run(&self) {
        println!("{}", "=".repeat(80));
        println!("Running test:");
        println!("{self:#?}");
        println!();

        let rp_id = "example.com";
        // TODO: client data
        let client_data_hash = &[0; 32];

        virt::run_ctap2(|device| {
            let rp = Rp::new(rp_id);
            let user = User::new(b"id123")
                .name("john.doe")
                .display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            if let Some(third_party_payment) = self.mc_third_party_payment {
                request.extensions = Some(ExtensionsInput {
                    third_party_payment: Some(third_party_payment),
                });
            }
            let response = device.exec(request).unwrap();
            let credential = response.auth_data.credential.unwrap();

            let mut request = GetAssertion::new(rp_id, client_data_hash);
            request.allow_list = Some(vec![PubKeyCredDescriptor::new(
                "public-key",
                credential.id.clone(),
            )]);
            if let Some(third_party_payment) = self.ga_third_party_payment {
                request.extensions = Some(ExtensionsInput {
                    third_party_payment: Some(third_party_payment),
                });
            }
            let response = device.exec(request).unwrap();
            assert_eq!(response.credential.ty, "public-key");
            assert_eq!(response.credential.id, credential.id);
            assert_eq!(response.auth_data.credential, None);
            credential.verify_assertion(&response.auth_data, client_data_hash, &response.signature);
            if self.ga_third_party_payment.unwrap_or_default() {
                let extensions = response.auth_data.extensions.unwrap();
                assert_eq!(
                    extensions.get("thirdPartyPayment"),
                    Some(&Value::from(
                        self.mc_third_party_payment.unwrap_or_default()
                    ))
                );
            } else {
                assert!(response.auth_data.extensions.is_none());
            }
        });
    }
}

#[test]
fn test_get_assertion() {
    for mc_third_party_payment in [Some(false), Some(true), None] {
        for ga_third_party_payment in [Some(false), Some(true), None] {
            TestGetAssertion {
                mc_third_party_payment,
                ga_third_party_payment,
            }
            .run()
        }
    }
}

#[derive(Debug)]
struct TestListCredentials {
    pin_token_rp_id: bool,
    third_party_payment: Option<bool>,
}

impl TestListCredentials {
    fn run(&self) {
        let key_agreement_key = KeyAgreementKey::generate();
        let pin = b"123456";
        let rp_id = "example.com";
        let user_id = b"id123";
        virt::run_ctap2(|device| {
            let shared_secret = get_shared_secret(&device, &key_agreement_key);
            set_pin(&device, &key_agreement_key, &shared_secret, pin);

            let pin_token =
                get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x01, None);
            // TODO: client data
            let client_data_hash = b"";
            let pin_auth = pin_token.authenticate(client_data_hash);

            let rp = Rp::new(rp_id);
            let user = User::new(user_id).name("john.doe").display_name("John Doe");
            let pub_key_cred_params = vec![PubKeyCredParam::new("public-key", -7)];
            let mut request = MakeCredential::new(client_data_hash, rp, user, pub_key_cred_params);
            request.options = Some(MakeCredentialOptions::default().rk(true));
            request.pin_auth = Some(pin_auth);
            request.pin_protocol = Some(2);
            if let Some(third_party_payment) = self.third_party_payment {
                request.extensions = Some(ExtensionsInput {
                    third_party_payment: Some(third_party_payment),
                });
            }
            let reply = device.exec(request).unwrap();
            assert_eq!(
                reply.auth_data.flags & 0b1,
                0b1,
                "up flag not set in auth_data: 0b{:b}",
                reply.auth_data.flags
            );
            assert_eq!(
                reply.auth_data.flags & 0b100,
                0b100,
                "uv flag not set in auth_data: 0b{:b}",
                reply.auth_data.flags
            );

            let pin_token =
                get_pin_token(&device, &key_agreement_key, &shared_secret, pin, 0x04, None);
            let pin_auth = pin_token.authenticate(&[0x02]);
            let request = CredentialManagement {
                subcommand: 0x02,
                subcommand_params: None,
                pin_protocol: Some(2),
                pin_auth: Some(pin_auth),
            };
            let reply = device.exec(request).unwrap();
            let rp: BTreeMap<String, Value> = reply.rp.unwrap().deserialized().unwrap();
            // TODO: check rp ID hash
            assert!(reply.rp_id_hash.is_some());
            assert_eq!(reply.total_rps, Some(1));
            assert_eq!(rp.get("id").unwrap(), &Value::from(rp_id));

            let pin_token_rp_id = self.pin_token_rp_id.then(|| rp_id.to_owned());
            let pin_token = get_pin_token(
                &device,
                &key_agreement_key,
                &shared_secret,
                pin,
                0x04,
                pin_token_rp_id,
            );
            let params = CredentialManagementParams {
                rp_id_hash: Some(reply.rp_id_hash.unwrap().as_bytes().unwrap().to_owned()),
                ..Default::default()
            };
            let mut pin_auth_param = vec![0x04];
            pin_auth_param.extend_from_slice(&params.serialized());
            let pin_auth = pin_token.authenticate(&pin_auth_param);
            let request = CredentialManagement {
                subcommand: 0x04,
                subcommand_params: Some(params),
                pin_protocol: Some(2),
                pin_auth: Some(pin_auth),
            };
            let reply = device.exec(request).unwrap();
            let user: BTreeMap<String, Value> = reply.user.unwrap().deserialized().unwrap();
            assert_eq!(reply.total_credentials, Some(1));
            assert_eq!(user.get("id").unwrap(), &Value::from(user_id.as_slice()));
            assert_eq!(
                reply.third_party_payment,
                Some(self.third_party_payment.unwrap_or_default())
            );
        });
    }
}

#[test]
fn test_list_credentials() {
    for pin_token_rp_id in [false, true] {
        for third_party_payment in [Some(false), Some(true), None] {
            let test = TestListCredentials {
                pin_token_rp_id,
                third_party_payment,
            };
            println!("{}", "=".repeat(80));
            println!("Running test:");
            println!("{test:#?}");
            println!();
            test.run();
        }
    }
}
