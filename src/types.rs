use anyhow::Error;
use anyhow::Result;
use reqwest::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug)]
pub struct Rpc {
    client: Client,
    url: Url,
}

impl Rpc {
    pub fn new(url: &str) -> Result<Self> {
        let client = reqwest::Client::new();
        let url = Url::parse(url)?;
        Ok(Self { client, url })
    }

    pub async fn get_token_list(
        &self,
        token: &str,
        page: i32,
        page_size: i32,
    ) -> Result<ListResponse> {
        let mut url = self.url.join("list").unwrap();
        url.set_query(Some(
            format!(
                "pageNo={}&pageCount={}&ticker={}&state=0",
                page, page_size, token
            )
            .as_str(),
        ));
        println!("{}", url.as_str());

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
}

pub async fn get_balance() {}

#[cfg(test)]
mod tests {
    use crate::types::Rpc;
    use anyhow::Result;

    #[tokio::test]
    async fn test_get_token_list() -> Result<()> {
        let rpc = Rpc::new("https://api-mainnet.brc20.findora.org")?;
        let token_list = rpc.get_token_list("bonk", 1, 10).await?;
        println!("{:?}", token_list);
        Ok(())
    }
}
