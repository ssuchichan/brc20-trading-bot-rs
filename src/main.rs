mod db;
mod platform;
mod robot;
mod types;
mod utils;

use crate::db::Storage;
use crate::types::FraAccount;
use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use env_logger::Target;
use log::info;
use sqlx::pool::PoolOptions;
use sqlx::{PgPool, Pool, Postgres};
use std::io::Read;
use std::sync::Arc;
use std::{env, io};
use std::{fs::File, io::Write};
use utils::gen_accounts;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = 10)]
    accounts: i32,
}

const ACCOUNT_MINT: &'static str = "accounts-mint.txt";
const ACCOUNT_BUY: &'static str = "accounts-buy.txt";
#[allow(dead_code)]
const MINT_LIMIT: usize = 7;
const ACCOUNT_TYPE_MINT: i32 = 1;
const ACCOUNT_TYPE_BUY: i32 = 2;

#[derive(Debug)]
struct BotServer {
    storage: Arc<Storage>,
    accounts_mint: Vec<FraAccount>,
    accounts_buy: Vec<FraAccount>,
}

impl BotServer {
    pub fn new(
        pool: PgPool,
        accounts_mint: Vec<FraAccount>,
        accounts_buy: Vec<FraAccount>,
    ) -> Self {
        Self {
            storage: Arc::new(Storage::new(pool)),
            accounts_mint,
            accounts_buy,
        }
    }

    pub async fn prepare_accounts(&self) -> Result<()> {
        self.storage
            .insert_accounts(ACCOUNT_TYPE_MINT, &self.accounts_mint)
            .await?;

        self.storage
            .insert_accounts(ACCOUNT_TYPE_BUY, &self.accounts_buy)
            .await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::builder().target(Target::Stdout).init();

    let db_url = env::var("DATABASE_URL")?;
    let pool: Pool<Postgres> = PoolOptions::new()
        .connect(&db_url)
        .await
        .expect("connect DB");
    info!("Connecting DB...ok");

    let args = Args::parse();
    let accounts_mint: Vec<FraAccount> = match File::open(ACCOUNT_MINT) {
        Ok(mut f) => {
            info!("Reading accounts for mint...");
            let mut contents = String::new();
            f.read_to_string(&mut contents)?;
            let accounts = serde_json::from_str(&contents)?;
            info!("Reading accounts for mint... ok");
            accounts
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                info!("Generating accounts for mint...");
                let accounts = gen_accounts(args.accounts)?;
                let mut f = File::create(ACCOUNT_MINT)?;
                let s = serde_json::to_string_pretty(&accounts)?;
                let _ = f.write_all(s.as_bytes())?;
                info!("Generating accounts for mint... ok");
                accounts
            } else {
                panic!("{}", e);
            }
        }
    };

    let accounts_buy: Vec<FraAccount> = match File::open(ACCOUNT_BUY) {
        Ok(mut f) => {
            info!("Reading accounts for buying...");
            let mut contents = String::new();
            f.read_to_string(&mut contents)?;
            let accounts = serde_json::from_str(&contents)?;
            info!("Reading accounts for buying... ok");
            accounts
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                info!("Generating accounts for buying...");
                let accounts = gen_accounts(args.accounts)?;
                let mut f = File::create(ACCOUNT_BUY)?;
                let s = serde_json::to_string_pretty(&accounts)?;
                let _ = f.write_all(s.as_bytes())?;
                info!("Generating accounts for buying... ok");
                accounts
            } else {
                panic!("{}", e);
            }
        }
    };

    let server = BotServer::new(pool, accounts_mint, accounts_buy);
    server.prepare_accounts().await?;

    info!("Starting server...");

    Ok(())
}
