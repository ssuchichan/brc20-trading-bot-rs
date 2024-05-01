use anyhow::{Error, Result};
use globutils::wallet::{public_key_to_base64, restore_keypair_from_seckey_base64};
use ledger::data_model::{TxoSID, Utxo, ASSET_TYPE_FRA};
use reqwest::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zei::xfr::asset_record::open_blind_asset_record;
use zei::xfr::structs::OwnerMemo;

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
    pub mnemonic: Option<String>,
    pub address: String,
    pub public_key: Option<String>,
    pub private_key: String,
}

impl FraAccount {
    pub async fn mint(&self) {
        todo!()
    }

    pub async fn transfer(&self, to: &str) {}
}

#[derive(Debug)]
pub struct Rpc {
    client: Client,
    ex_url: Url,
    node_url: Url,
}

impl Rpc {
    pub fn new(ex_url: &str, node_url: &str) -> Result<Self> {
        let client = reqwest::Client::new();
        let ex_url = Url::parse(ex_url)?;
        let node_url = Url::parse(node_url)?;
        Ok(Self {
            client,
            ex_url,
            node_url,
        })
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

        let resp = self.client.get(url).send().await?;
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
            self.node_url,
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
}
