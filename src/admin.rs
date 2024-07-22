use anyhow::Error;
use openpgp_card::{
    ocard::{algorithm::AlgoSimple, KeyType},
    state::{Admin, Transaction},
    Card,
};
use openpgp_card_rpgp::public_key_material_to_key;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKey;
use secrecy::SecretString;

pub(crate) fn generate_command(
    mut card: Card<Transaction>,
    admin: &str,
    user_sign: &str,
) -> anyhow::Result<()> {
    match crate::util::verify_to_admin(&mut card, admin) {
        Err(_) => panic!("BAD ADMIN PIN"),
        _ => {}
    }
    match crate::util::verify_to_sign(&mut card, user_sign) {
        Err(_) => panic!("BAD USER PIN"),
        _ => {}
    }
    let algo = AlgoSimple::RSA4k;

    let (key_sig, key_dec, key_auth) = {
        let mut admin = card.to_admin_card(None)?;
        gen_subkeys(&mut admin, true, true, algo)?
    };
    println!("{:?}\n{:?}\n{:?}", key_sig, key_dec, key_auth);
    Ok(())
}

pub(crate) fn gen_subkeys(
    admin: &mut Card<Admin>,
    decrypt: bool,
    auth: bool,
    algo: AlgoSimple,
) -> anyhow::Result<(PublicKey, PublicKey, PublicKey)> {
    admin.set_algorithm(KeyType::Signing, algo);
    let (pkm, ts) =
        admin.generate_key(openpgp_card_rpgp::public_to_fingerprint, KeyType::Signing)?;
    let key_sig =
        openpgp_card_rpgp::public_key_material_to_key(&pkm, KeyType::Signing, &ts, None, None)?;
    admin.set_algorithm(KeyType::Decryption, algo);
    let (pkm, ts) = admin.generate_key(
        openpgp_card_rpgp::public_to_fingerprint,
        KeyType::Decryption,
    )?;
    let key_dec = public_key_material_to_key(&pkm, KeyType::Decryption, &ts, None, None)?;
    admin.set_algorithm(KeyType::Attestation, algo);
    let (pkm, ts) = admin.generate_key(
        openpgp_card_rpgp::public_to_fingerprint,
        KeyType::Authentication,
    )?;
    let key_auth = public_key_material_to_key(&pkm, KeyType::Authentication, &ts, None, None)?;

    Ok((key_sig, key_dec, key_auth))
}
