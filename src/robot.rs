extern crate dotenv;
use serde::{Deserialize, Serialize};
use sqlx::Error;
use sqlx::PgPool;

#[derive(Serialize, Deserialize)]
pub struct Robot {
    pub mnemonic: String,
    pub account: String,
    pub create_time: i64,
    pub update_time: i64,
}

impl Robot {
    pub async fn all_accounts(pool: &PgPool) -> Result<Vec<String>, Error> {
        let result: Vec<(String,)> = sqlx::query_as("SELECT account FROM robot")
            .fetch_all(pool)
            .await?;
        Ok(result.into_iter().map(|(account,)| account).collect())
    }
}
