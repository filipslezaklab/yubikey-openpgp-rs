use std::str::FromStr;

use crate::util;
use anyhow::anyhow;
use anyhow::Result;
use secrecy::SecretString;

static BAD_PIN: &str = "00000000";

pub fn factory_reset(ident: &str) -> Result<()> {
    eprintln!("Resetting Card {}", ident);
    let mut card = util::open_card(ident)?;
    let admin_status = {
        let mut transaction = card.transaction()?;
        let pws = transaction.pw_status_bytes()?;
        pws.err_count_pw3()
    };

    // to reset admin retries needs to be blocked
    if admin_status != 0 {
        let mut result = false;
        let bad_secret = SecretString::from_str(BAD_PIN)?;
        while !result {
            let admin_status = {
                let mut transaction = card.transaction()?;
                transaction.verify_admin_pin(bad_secret.clone()).ok();
                transaction.pw_status_bytes()?.err_count_pw3()
            };
            result = admin_status == 0;
        }
    }

    let mut transaction = card.transaction()?;
    transaction.factory_reset().map_err(|e| anyhow!(e));

    Ok(())
}
