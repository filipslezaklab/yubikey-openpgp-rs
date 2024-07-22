use crate::util::open_card;
use chrono::{DateTime, Utc};
use openpgp_card::ocard::KeyType;
use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub(crate) struct KeySlotInfo {
    pub(crate) fingerprint: Option<String>,
    pub(crate) creation_time: Option<String>,
    pub(crate) algorithm: Option<String>,
    pub(crate) algorithm_details: Option<String>,
    pub(crate) touch_policy: Option<String>,
    pub(crate) touch_features: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) public_key_material: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct Status {
    pub(crate) ident: String,
    pub(crate) cardholder_name: Option<String>,
    pub(crate) language_preferences: Vec<String>,
    pub(crate) certificate_url: Option<String>,
    pub(crate) login_data: Option<String>,
    pub(crate) signature_key: KeySlotInfo,
    pub(crate) signature_count: u32,
    pub(crate) user_pin_valid_for_only_one_signature: bool,
    pub(crate) decryption_key: KeySlotInfo,
    pub(crate) authentication_key: KeySlotInfo,
    pub(crate) attestation_key: Option<KeySlotInfo>,
    pub(crate) user_pin_remaining_attempts: u8,
    pub(crate) admin_pin_remaining_attempts: u8,
    pub(crate) reset_code_remaining_attempts: u8,
    pub(crate) kdf_mode: bool,
    pub(crate) additional_key_statuses: Vec<(u8, String)>,
    pub(crate) ca_fingerprints: Vec<String>,
}

pub(crate) fn print_status(ident: String) -> anyhow::Result<()> {
    let mut open = open_card(&ident)?;
    let mut card = open.transaction()?;
    let mut status = Status::default();

    // Cardholder Name
    let name = card.cardholder_name()?;
    if !name.is_empty() {
        status.cardholder_name = Some(name);
    }

    // Certificate URL
    let url = card.url()?;
    if !url.is_empty() {
        status.certificate_url = Some(url);
    }

    let login_data = card.login_data()?;
    if !login_data.is_empty() {
        status.login_data = Some(String::from_utf8_lossy(&login_data).into());
    }

    // Language Preference
    if let Some(lang) = card.cardholder_related_data()?.lang() {
        for lang in lang {
            status.language_preferences.push(format!("{lang}"));
        }
    }

    // key information (imported vs. generated on card)
    let ki = card.key_information().ok().flatten();

    let pws = card.pw_status_bytes()?;

    // information about subkeys

    let fps = card.fingerprints()?;
    let kgt = card.key_generation_times()?;

    let mut signature_key = KeySlotInfo::default();

    if let Some(fp) = fps.signature() {
        signature_key.fingerprint = Some(fp.to_hex());
    }

    signature_key.algorithm = Some(format!("{}", card.algorithm_attributes(KeyType::Signing)?));

    if let Some(kgt) = kgt.signature() {
        signature_key.creation_time = Some(format!("{}", DateTime::<Utc>::from(kgt)));
    }

    if let Some(uif) = card.user_interaction_flag(KeyType::Signing)? {
        signature_key.touch_policy = Some(format!("{}", uif.touch_policy()));
        signature_key.touch_features = Some(format!("{}", uif.features()));
    }

    if let Some(ks) = ki.as_ref().map(|ki| ki.sig_status()) {
        signature_key.status = Some(format!("{ks}"));
    }

    if let Ok(pkm) = card.public_key_material(KeyType::Signing) {
        signature_key.public_key_material = Some(pkm.to_string());
    }

    let dsc = card.digital_signature_count()?;

    let mut decryption_key = KeySlotInfo::default();

    if let Some(fp) = fps.decryption() {
        decryption_key.fingerprint = Some(fp.to_hex());
    }

    decryption_key.algorithm = Some(format!(
        "{}",
        card.algorithm_attributes(KeyType::Decryption)?
    ));

    if let Some(kgt) = kgt.decryption() {
        decryption_key.creation_time = Some(format!("{}", DateTime::<Utc>::from(kgt)));
    }

    if let Some(uif) = card.user_interaction_flag(KeyType::Decryption)? {
        decryption_key.touch_policy = Some(format!("{}", uif.touch_policy()));
        decryption_key.touch_features = Some(format!("{}", uif.features()));
    }

    if let Some(ks) = ki.as_ref().map(|ki| ki.dec_status()) {
        decryption_key.status = Some(format!("{ks}"));
    }

    if let Ok(pkm) = card.public_key_material(KeyType::Decryption) {
        decryption_key.public_key_material = Some(pkm.to_string());
    }

    let mut auth_key = KeySlotInfo::default();

    auth_key.algorithm = Some(format!(
        "{}",
        card.algorithm_attributes(KeyType::Authentication)?
    ));

    if let Some(fp) = fps.authentication() {
        auth_key.fingerprint = Some(fp.to_hex());
    }

    if let Some(kgt) = kgt.authentication() {
        auth_key.creation_time = Some(format!("{}", DateTime::<Utc>::from(kgt)));
    }

    if let Some(uif) = card.user_interaction_flag(KeyType::Authentication)? {
        auth_key.touch_policy = Some(format!("{}", uif.touch_policy()));
        auth_key.touch_features = Some(format!("{}", uif.features()));
    }

    if let Some(ks) = ki.as_ref().map(|ki| ki.aut_status()) {
        auth_key.status = Some(format!("{ks}"));
    }

    if let Ok(pkm) = card.public_key_material(KeyType::Attestation) {
        auth_key.public_key_material = Some(pkm.to_string());
    }

    let mut attestation_key = KeySlotInfo::default();

    if let Ok(Some(fp)) = card.fingerprint(KeyType::Attestation) {
        attestation_key.fingerprint = Some(fp.to_hex());
    }

    if let Ok(algo) = card.algorithm_attributes(KeyType::Attestation) {
        attestation_key.algorithm = Some(format!("{algo}"));
    }

    if let Ok(Some(kgt)) = card.key_generation_time(KeyType::Attestation) {
        attestation_key.creation_time = Some(format!("{}", DateTime::<Utc>::from(&kgt)));
    }

    if let Some(uif) = card.user_interaction_flag(KeyType::Attestation)? {
        attestation_key.touch_policy = Some(format!("{}", uif.touch_policy()));
        attestation_key.touch_features = Some(format!("{}", uif.features()));
    }

    // "Key-Ref = 0x81 is reserved for the Attestation key of Yubico"
    // (see OpenPGP card spec 3.4.1 pg.43)
    if let Some(ki) = ki.as_ref() {
        if let Some(n) = (0..ki.num_additional()).find(|&n| ki.additional_ref(n) == 0x81) {
            let ks = ki.additional_status(n);
            attestation_key.status = Some(format!("{ks}"));
        }
    };

    status.signature_key = signature_key;
    status.authentication_key = auth_key;
    status.decryption_key = decryption_key;
    status.attestation_key = Some(attestation_key);

    status.user_pin_valid_for_only_one_signature = pws.pw1_cds_valid_once();

    status.user_pin_remaining_attempts = pws.err_count_pw1();
    status.admin_pin_remaining_attempts = pws.err_count_pw3();
    status.reset_code_remaining_attempts = pws.err_count_rc();

    if let Ok(kdf) = card.kdf_do() {
        if kdf.kdf_algo() != 0 {
            status.kdf_mode = true;
        }
    }

    if let Ok(fps) = card.ca_fingerprints() {
        for fp in fps.iter().flatten() {
            status.ca_fingerprints.push(fp.to_string());
        }
    }

    println!("{:?}", status);

    Ok(())
}
