use anyhow::Result;
use anyhow::{anyhow, Ok};
use base64::{engine, Engine};
use globutils::wallet::{
    generate_mnemonic_default, public_key_to_base64, public_key_to_bech32,
    restore_keypair_from_mnemonic_default,
};
use ledger::data_model::{TxoSID, Utxo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zei::serialization::ZeiFromToBytes;
use zei::xfr::sig::XfrSecretKey;
use zei::xfr::structs::OwnerMemo;

#[derive(Serialize, Deserialize, Debug)]
pub struct FraAccount {
    pub index: Option<i32>,
    pub mnemonic: Option<String>,
    pub address: String,
    pub public_key: Option<String>,
    pub private_key: String,
}

#[allow(dead_code)]
fn private_key_to_base64(key: &XfrSecretKey) -> String {
    engine::general_purpose::URL_SAFE.encode(ZeiFromToBytes::zei_to_bytes(key))
}

pub fn gen_accounts(amount: i32) -> Result<Vec<FraAccount>> {
    let mut accounts = vec![];
    for index in 0..amount {
        let mnemonic = generate_mnemonic_default();
        let key_pair = restore_keypair_from_mnemonic_default(&mnemonic).unwrap();
        let xfr_public_key = key_pair.get_pk_ref();
        let xfr_private_key = key_pair.get_sk_ref();

        let private_key = hex::encode(ZeiFromToBytes::zei_to_bytes(xfr_private_key));
        let public_key = public_key_to_base64(xfr_public_key);
        let address = public_key_to_bech32(&xfr_public_key);

        accounts.push(FraAccount {
            index: Some(index),
            mnemonic: Some(mnemonic),
            address,
            public_key: Some(public_key),
            private_key,
        });
    }

    Ok(accounts)
}

pub fn get_owned_utxos_x(
    url: &str,
    pubkey: &str,
) -> Result<HashMap<TxoSID, (Utxo, Option<OwnerMemo>)>> {
    let url = format!("{}/owned_utxos/{}", url, pubkey);

    attohttpc::get(url)
        .send()
        .and_then(|resp| resp.bytes())
        .map_err(|e| anyhow! {"{:?}", e})
        .and_then(|b| {
            serde_json::from_slice::<HashMap<TxoSID, (Utxo, Option<OwnerMemo>)>>(&b)
                .map_err(|e| anyhow!("{:?}", e))
        })
}
