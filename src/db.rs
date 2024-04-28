use crate::utils::FraAccount;
use anyhow::Result;
use sqlx::PgPool;

#[derive(Debug)]
pub struct Storage {
    pool: PgPool,
}

impl Storage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_accounts(&self, ty: i32, accounts: &Vec<FraAccount>) -> Result<()> {
        if !accounts.is_empty() {
            for account in accounts {
                sqlx::query("INSERT INTO brc20_accounts VALUES($1,$2) ON CONFLICT(address) DO UPDATE SET ty=$2")
                    .bind(&account.address)
                    .bind(ty)
                    .execute(&self.pool)
                    .await?;
            }
        }

        Ok(())
    }
}
