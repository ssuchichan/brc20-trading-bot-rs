use anyhow::Ok;
use anyhow::Result;
use globutils::wallet::{self, public_key_to_base64, public_key_to_bech32};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct FraAccount {
    pub index: i32,
    pub menmonic: String,
    pub address: String,
    pub public_key: String,
}

pub fn gen_accounts(amount: i32) -> Result<Vec<FraAccount>> {
    let mut accounts = vec![];
    for index in 0..amount {
        let menmonic = wallet::generate_mnemonic_default();
        let key_pair = wallet::restore_keypair_from_mnemonic_default(&menmonic).unwrap();
        let xfr_public_key = key_pair.get_pk();
        let public_key = public_key_to_base64(&xfr_public_key);
        let address = public_key_to_bech32(&xfr_public_key);

        accounts.push(FraAccount {
            index,
            menmonic,
            address,
            public_key,
        });
    }

    Ok(accounts)
}
