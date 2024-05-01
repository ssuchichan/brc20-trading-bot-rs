use crate::types::FraAccount;
use anyhow::Error;
use anyhow::{anyhow, Result};
use base64::{engine, Engine};
use globutils::wallet::{
    generate_mnemonic_default, public_key_to_base64, public_key_to_bech32,
    restore_keypair_from_mnemonic_default, restore_keypair_from_seckey_base64,
};
use ledger::data_model::{TxoSID, Utxo, ASSET_TYPE_FRA};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zei::serialization::ZeiFromToBytes;
use zei::xfr::asset_record::open_blind_asset_record;
use zei::xfr::sig::XfrSecretKey;
use zei::xfr::structs::OwnerMemo;

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
