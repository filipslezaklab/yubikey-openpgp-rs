// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Borrow;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use card_backend::{CardBackend, SmartcardError};
use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
use openpgp_card::ocard::data::ApplicationIdentifier;
use openpgp_card::ocard::StatusBytes;
use openpgp_card::state::{Admin, Open, Sign, Transaction, User};
use openpgp_card::Card;
use openpgp_card::Error;
use secrecy::SecretString;
use yubikey_management::Application;

// check if given card is a yubikey and it does support OpenPGP
fn check_yk_support(card: Box<dyn CardBackend + Send + Sync>) -> Result<bool, SmartcardError> {
    let mut yk_m = yubikey_management::YkManagement::select(card)?;
    let config = yk_m.read_config()?;
    // support only Yubikey's 4+ (support for RSA 4096)
    match config.version() {
        Some(v) => {
            if v.major() < 4 {
                return Ok(false);
            }
        }
        None => return Ok(false),
    }
    match config.usb_supported().get(&Application::Openpgp) {
        None => return Ok(false),
        _ => {}
    }
    match config.usb_enabled().get(&Application::Openpgp) {
        None => return Ok(false),
        _ => {}
    }
    Ok(true)
}

pub(crate) fn list_available_yubikeys_openpgp_ident() -> Result<Vec<ApplicationIdentifier>, Error> {
    let cards = PcscBackend::cards(None)?;
    let mut res: Vec<ApplicationIdentifier> = Vec::new();
    for backend in cards {
        let mut card = Card::<Open>::new(backend?)?;
        let mut ident: ApplicationIdentifier;
        // read ident
        {
            let mut transaction = card.transaction()?;
            ident = transaction.application_identifier()?;
        }
        let card_backed = card.into_backend();
        if check_yk_support(card_backed)? {
            res.push(ident);
        }
    }
    Ok(res)
}

pub(crate) fn cards() -> Result<Vec<Card<Open>>, Error> {
    let mut cards = vec![];

    for backend in PcscBackend::cards(None)? {
        let mut card = Card::<Open>::new(backend?)?;
    }

    Ok(cards)
}

pub(crate) fn open_card(ident: &str) -> Result<Card<Open>, Error> {
    let cards = PcscBackend::card_backends(None)?;
    let card = Card::<Open>::open_by_ident(cards, ident)?;

    Ok(card)
}

/// Get pin from file. Or via user input, if no file and no pinpad is available.
///
/// If a pinpad is available, return Null (the pinpad will be used to get access to the card).
///
/// `msg` is the message to show when asking the user to enter a PIN.
pub(crate) fn get_pin(
    card: &mut Card<Transaction<'_>>,
    pin_file: Option<PathBuf>,
    msg: &str,
) -> Result<Option<SecretString>> {
    if let Some(path) = pin_file {
        // we have a pin file
        Ok(Some(load_pin(&path).context(format!(
            "Failed to read PIN file {}",
            path.display()
        ))?))
    } else if !card.feature_pinpad_verify() {
        // we have no pin file and no pinpad
        let pin = rpassword::prompt_password(msg).context("Failed to read PIN")?;
        Ok(Some(pin.into()))
    } else {
        // we have a pinpad
        Ok(None)
    }
}

/// Let the user input a PIN twice, return PIN if both entries match, error otherwise
pub(crate) fn input_pin_twice(msg1: &str, msg2: &str) -> Result<SecretString> {
    // get new user pin
    let newpin1 = rpassword::prompt_password(msg1)?;
    let newpin2 = rpassword::prompt_password(msg2)?;

    // FIXME: zeroize?

    if newpin1 != newpin2 {
        Err(anyhow::anyhow!("PINs do not match."))
    } else {
        Ok(newpin1.into())
    }
}

pub(crate) fn verify_to_user<'app, 'open>(
    card: &'open mut Card<Transaction<'app>>,
    pin: Option<SecretString>,
) -> Result<Card<User<'app, 'open>>, Box<dyn std::error::Error>> {
    if let Some(pin) = pin {
        card.verify_user_pin(pin)?;
    } else {
        if !card.feature_pinpad_verify() {
            return Err(anyhow!("No user PIN file provided, and no pinpad found").into());
        };

        card.verify_user_pinpad(&|| eprintln!("Enter user PIN on card reader pinpad."))?;
    }

    Ok(card.to_user_card(None)?)
}

pub(crate) fn verify_to_sign<'app, 'open>(
    card: &'open mut Card<Transaction<'app>>,
    pin: &str,
) -> Result<Card<Sign<'app, 'open>>, Box<dyn std::error::Error>> {
    let s = SecretString::from_str(pin)?;
    card.verify_user_signing_pin(s)?;
    Ok(card.to_signing_card(None)?)
}

pub(crate) fn verify_to_admin<'app, 'open>(
    card: &'open mut Card<Transaction<'app>>,
    pin: &str,
) -> Result<Card<Admin<'app, 'open>>, Box<dyn std::error::Error>> {
    let s = SecretString::from_str(pin)?;
    card.verify_admin_pin(s)?;
    Ok(card.to_admin_card(None)?)
}

pub(crate) fn load_pin(pin_file: &Path) -> Result<SecretString> {
    let pin = std::fs::read_to_string(pin_file)?;
    Ok(pin.trim().to_string().into())
}

pub(crate) fn open_or_stdin(f: Option<&Path>) -> Result<Box<dyn std::io::Read + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::open(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdin())),
    }
}

pub(crate) fn open_or_stdout(f: Option<&Path>) -> Result<Box<dyn std::io::Write + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::create(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdout())),
    }
}

fn get_ssh_pubkey(pkm: &PublicKeyMaterial, ident: String) -> Result<sshkeys::PublicKey> {
    let cardname = format!("opgpcard:{ident}");

    let (key_type, kind) = match pkm {
        PublicKeyMaterial::R(rsa) => {
            let key_type = sshkeys::KeyType::from_name("ssh-rsa")?;

            let kind = sshkeys::PublicKeyKind::Rsa(sshkeys::RsaPublicKey {
                e: rsa.v().to_vec(),
                n: rsa.n().to_vec(),
            });

            Ok((key_type, kind))
        }
        PublicKeyMaterial::E(ecc) => {
            if let AlgorithmAttributes::Ecc(ecc_attrs) = ecc.algo() {
                match ecc_attrs.ecc_type() {
                    EccType::EdDSA => {
                        let key_type = sshkeys::KeyType::from_name("ssh-ed25519")?;

                        let kind = sshkeys::PublicKeyKind::Ed25519(sshkeys::Ed25519PublicKey {
                            key: ecc.data().to_vec(),
                            sk_application: None,
                        });

                        Ok((key_type, kind))
                    }
                    EccType::ECDSA => {
                        let (curve, name) = match ecc_attrs.curve() {
                            Curve::NistP256r1 => Ok((
                                sshkeys::Curve::from_identifier("nistp256")?,
                                "ecdsa-sha2-nistp256",
                            )),
                            Curve::NistP384r1 => Ok((
                                sshkeys::Curve::from_identifier("nistp384")?,
                                "ecdsa-sha2-nistp384",
                            )),
                            Curve::NistP521r1 => Ok((
                                sshkeys::Curve::from_identifier("nistp521")?,
                                "ecdsa-sha2-nistp521",
                            )),
                            _ => Err(anyhow!("Unexpected ECDSA curve {:?}", ecc_attrs.curve())),
                        }?;

                        let key_type = sshkeys::KeyType::from_name(name)?;

                        let kind = sshkeys::PublicKeyKind::Ecdsa(sshkeys::EcdsaPublicKey {
                            curve,
                            key: ecc.data().to_vec(),
                            sk_application: None,
                        });

                        Ok((key_type, kind))
                    }
                    _ => Err(anyhow!("Unexpected EccType {:?}", ecc_attrs.ecc_type())),
                }
            } else {
                Err(anyhow!("Unexpected Algo in EccPub {:?}", ecc))
            }
        }
    }?;

    let pk = sshkeys::PublicKey {
        key_type,
        comment: Some(cardname),
        kind,
    };

    Ok(pk)
}

/// Return a String representation of an ssh public key, in a form like:
/// "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAuTuxILMTvzTIRvaRqqUM3aRDoEBgz/JAoWKsD1ECxy opgpcard:FFFE:43194240"
pub(crate) fn get_ssh_pubkey_string(pkm: &PublicKeyMaterial, ident: String) -> Result<String> {
    let pk = get_ssh_pubkey(pkm, ident)?;

    let mut v = vec![];
    pk.write(&mut v)?;

    let s = String::from_utf8_lossy(&v).to_string();

    Ok(s.trim().into())
}

/// Gnuk doesn't allow the User password (pw1) to be changed while no
/// private key material exists on the card.
///
/// This fn checks for Gnuk's Status code and the case that no keys exist
/// on the card, and prints a note to the user, pointing out that the
/// absence of keys on the card might be the reason for the error they get.
pub(crate) fn print_gnuk_note(err: Error, card: &mut Card<Transaction>) -> Result<()> {
    if matches!(
        err,
        Error::CardStatus(StatusBytes::ConditionOfUseNotSatisfied)
    ) {
        // check if no keys exist on the card
        let fps = card.fingerprints()?;
        if fps.signature().is_none() && fps.decryption().is_none() && fps.authentication().is_none()
        {
            eprintln!(
                "\nNOTE: Some cards (e.g. Gnuk) don't allow \
                        User PIN change while no keys exist on the card."
            );
        }
    }
    Ok(())
}

pub(crate) fn pem_encode(data: Vec<u8>) -> String {
    const PEM_TAG: &str = "CERTIFICATE";

    let pem = pem::Pem::new(String::from(PEM_TAG), data);

    pem::encode(&pem)
}
