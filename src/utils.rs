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

#[derive(Serialize, Deserialize)]
struct AccountUtxos(Vec<(TxoSID, Vec<(Utxo, Option<OwnerMemo>)>)>);

pub async fn get_owned_utxos(url: &str, private_key: &str) -> Result<u64> {
    let key_pair = restore_keypair_from_seckey_base64(private_key).unwrap();
    let url = format!(
        "{}/owned_utxos/{}",
        url,
        public_key_to_base64(key_pair.get_pk_ref()).as_str()
    );
    let resp = reqwest::Client::new().get(url).send().await?;
    if !resp.status().is_success() {
        return Err(Error::msg("node rpc error"));
    };
    let body = resp.bytes().await?;

    let mut balance = 0;
    let utxos = serde_json::from_slice::<HashMap<TxoSID, (Utxo, Option<OwnerMemo>)>>(&body)?;

    for (_, (utxo, owner_memo)) in utxos.into_iter() {
        let oar = open_blind_asset_record(&utxo.0.record, &owner_memo, &key_pair).unwrap();
        if oar.asset_type != ASSET_TYPE_FRA {
            continue;
        }
        balance += oar.amount;
    }

    Ok(balance)
}

#[cfg(test)]
mod tests {
    use crate::utils::get_owned_utxos;
    use anyhow::Result;

    #[tokio::test]
    pub async fn test_get_owned_utxos() -> Result<()> {
        let private_key = "SehGPW8zpCE--3GJjY9r8WJYz-5QckO7WPWFnhOsGSU=";
        let balance =
            get_owned_utxos("https://prod-testnet.prod.findora.org:8668", &private_key).await?;

        Ok(())
    }
}
