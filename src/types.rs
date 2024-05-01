use anyhow::{Error, Result};
use finutils::txn_builder::{TransactionBuilder, TransferOperationBuilder};
use globutils::wallet::{
    public_key_to_base64, restore_keypair_from_mnemonic_default, restore_keypair_from_seckey_base64,
};
use ledger::data_model::{
    Transaction, TransferType, TxoSID, Utxo, ASSET_TYPE_FRA, BLACK_HOLE_PUBKEY, TX_FEE_MIN_V1,
};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use zei::xfr::asset_record::{open_blind_asset_record, AssetRecordType};
use zei::xfr::sig::XfrPublicKey;
use zei::xfr::structs::{AssetRecordTemplate, OwnerMemo};

#[derive(Debug, Serialize, Deserialize)]
pub struct ListItem {
    pub id: i32,
    pub ticker: i32,
    pub from: String,
    pub amount: String,
    pub price: String,
    pub state: i32,
    pub to: String,
    pub create_time: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub total: i32,
    #[serde(rename = "currentPage")]
    pub current_page: i32,
    #[serde(rename = "pageSize")]
    pub page_size: i32,
    #[serde(rename = "totalPages")]
    pub total_pages: i32,
    pub data: Option<Vec<ListItem>>,
}

#[derive(Serialize, Deserialize)]
struct AccountUtxos(Vec<(TxoSID, Vec<(Utxo, Option<OwnerMemo>)>)>);

#[derive(Serialize, Deserialize, Debug)]
pub struct FraAccount {
    pub index: Option<i32>,
    pub mnemonic: String,
    pub address: String,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
}

impl FraAccount {
    pub async fn mint(&self) {
        todo!()
    }

    pub async fn build_transfer_tx(
        &self,
        to: XfrPublicKey,
        to_amount: u64,
        utxo_inputs: u64,
        builder: &mut TransactionBuilder,
    ) -> Result<Transaction> {
        let from_key_pair = restore_keypair_from_mnemonic_default(&self.mnemonic).unwrap();

        let asset_record_type = AssetRecordType::from_flags(false, false);
        let mut transfer_op_builder = TransferOperationBuilder::new();

        let template_from = AssetRecordTemplate::with_no_asset_tracing(
            utxo_inputs - to_amount - TX_FEE_MIN_V1,
            ASSET_TYPE_FRA,
            asset_record_type,
            from_key_pair.get_pk().clone(),
        );

        let template_fee = AssetRecordTemplate::with_no_asset_tracing(
            TX_FEE_MIN_V1,
            ASSET_TYPE_FRA,
            asset_record_type,
            *BLACK_HOLE_PUBKEY,
        );

        let receive_fra = AssetRecordTemplate::with_no_asset_tracing(
            to_amount,
            ASSET_TYPE_FRA,
            asset_record_type,
            to,
        );

        let op = transfer_op_builder
            .add_output(&template_fee, None, None, None, None)
            .and_then(|b| b.add_output(&template_from, None, None, None, None))
            .and_then(|b| b.add_output(&receive_fra, None, None, None, None))
            .and_then(|b| b.create(TransferType::Standard))
            .and_then(|b| b.sign(&from_key_pair))
            .and_then(|b| b.transaction())
            .unwrap();

        let tx: Transaction = builder
            .add_operation(op)
            .sign_to_map(&from_key_pair)
            .clone()
            .take_transaction();

        Ok(tx)
    }
}

#[derive(Debug)]
pub struct Rpc {
    ex_url: Url,
    node_url: Url,
}

impl Rpc {
    pub fn new(ex_url: &str, node_url: &str) -> Result<Self> {
        let ex_url = Url::parse(ex_url)?;
        let node_url = Url::parse(node_url)?;
        Ok(Self { ex_url, node_url })
    }

    pub async fn get_token_list(
        &self,
        token: &str,
        page: i32,
        page_size: i32,
    ) -> Result<ListResponse> {
        let mut url = self.ex_url.join("list").unwrap();
        url.set_query(Some(
            format!(
                "pageNo={}&pageCount={}&ticker={}&state=0",
                page, page_size, token
            )
            .as_str(),
        ));

        let resp = Client::new().get(url).send().await?;
        if !resp.status().is_success() {
            return Err(Error::msg("RPC error"));
        }

        let body = resp.text().await?;
        if let Ok(list_resp) = serde_json::from_str(&body) {
            Ok(list_resp)
        } else {
            Err(Error::msg("deserialize error"))
        }
    }

    pub async fn get_owned_utxos(&self, private_key: &str) -> Result<u64> {
        let key_pair = restore_keypair_from_seckey_base64(private_key).unwrap();
        let url = format!(
            "{}owned_utxos/{}",
            &self.node_url,
            public_key_to_base64(key_pair.get_pk_ref()).as_str()
        );
        let resp = Client::new().get(url).send().await?;
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

    async fn get_transaction_builder(&self) -> Result<TransactionBuilder> {
        let url = format!("{}global_state", &self.node_url);
        let resp = Client::new().get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(Error::msg("node rpc error"));
        };
        let body = resp.bytes().await?;
        let res = serde_json::from_slice::<(Value, u64, Value)>(&body)?;
        Ok(TransactionBuilder::from_seq_id(res.1))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Rpc;
    use anyhow::Result;

    #[tokio::test]
    async fn test_get_token_list() -> Result<()> {
        let rpc = Rpc::new(
            "https://api-testnet.brc20.findora.org",
            "https://prod-testnet.prod.findora.org:8668",
        )?;
        let token_list = rpc.get_token_list("bonk", 1, 10).await?;
        println!("{:?}", token_list);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_utxos() -> Result<()> {
        let rpc = Rpc::new(
            "https://api-testnet.brc20.findora.org",
            "https://prod-testnet.prod.findora.org:8668",
        )?;
        let private_key = "SehGPW8zpCE--3GJjY9r8WJYz-5QckO7WPWFnhOsGSU=";
        let balance = rpc.get_owned_utxos(private_key).await?;
        println!("{}", balance);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_transaction_builder() -> Result<()> {
        let rpc = Rpc::new(
            "https://api-testnet.brc20.findora.org",
            "https://prod-testnet.prod.findora.org:8668",
        )?;
        let tx_builder = rpc.get_transaction_builder().await?;

        Ok(())
    }
}
