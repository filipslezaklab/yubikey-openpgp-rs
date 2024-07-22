#![allow(unused)]

use admin::{gen_subkeys, generate_command};
use dotenvy::dotenv;
use status::print_status;
use system::factory_reset;
use util::{list_available_yubikeys_openpgp_ident, open_card};
mod admin;
mod status;
mod system;
mod util;

const POC_PIN_USER: &str = "123456";
const POC_PIN_ADMIN: &str = "12345678";

fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let cards = list_available_yubikeys_openpgp_ident()?;
    if cards.len() != 1 {
        panic!(
            "Only one card allowed to be present!\nFound: {}",
            &cards.len()
        );
    }
    println!("{:?}", &cards);
    let selected_ident = cards[0].ident().clone();
    print_status(selected_ident.clone())?;
    println!("Wiping the key...");
    factory_reset(&selected_ident)?;
    println!("card clean...");
    println!("Generating keys...");
    let mut card = open_card(&selected_ident)?;
    {
        let mut transaction = card.transaction()?;
        generate_command(transaction, POC_PIN_ADMIN, POC_PIN_USER)?;
    }
    println!("Keys generated in OpenPGP applet !");
    Ok(())
}
