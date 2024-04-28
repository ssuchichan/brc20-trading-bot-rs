mod db;
mod platform;
mod robot;
mod utils;

use crate::db::Storage;
use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use log::info;
use sqlx::pool::PoolOptions;
use sqlx::{PgPool, Pool, Postgres};
use std::io::Read;
use std::sync::Arc;
use std::{env, io};
use std::{fs::File, io::Write};
use std::time::Duration;
use env_logger::{Builder, Target};
use tokio::time;
use tokio::time::Sleep;
use utils::gen_accounts;
use utils::FraAccount;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = 20)]
    accounts: i32,
}

const ACCOUNT_MINT: &'static str = "accounts-mint.txt";
const ACCOUNT_BUY: &'static str = "accounts-buy.txt";
const MINT_LIMIT: usize = 7;
const ACCOUNT_TYPE_MINT: i32 = 1;
const ACCOUNT_TYPE_BUY: i32 = 2;

#[derive(Debug)]
struct BotServer {
    storage: Arc<Storage>,
}

impl BotServer {
    pub fn new(pool: PgPool) -> Self {
        Self {
            storage: Arc::new(Storage::new(pool)),
        }
    }

    pub async fn prepare_accounts(&self, accounts: &Vec<FraAccount>, ty: i32) -> Result<()> {
        Ok(self.storage.insert_accounts(ty, accounts).await?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::builder()
        .target(Target::Stdout)
        .init();


    let db_url = env::var("DATABASE_URL")?;
    let pool: Pool<Postgres> = PoolOptions::new()
        .connect(&db_url)
        .await
        .expect("connect DB");
    info!("Connecting DB...ok");

    let server = BotServer::new(pool);

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
                server
                    .prepare_accounts(&accounts, ACCOUNT_TYPE_MINT)
                    .await?;

                info!("Generating accounts for mint... ok");
                accounts
            } else {
                panic!("{}", e);
            }
        }
    };

    server
        .prepare_accounts(&accounts_mint, ACCOUNT_TYPE_MINT)
        .await?;

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

    server
        .prepare_accounts(&accounts_buy, ACCOUNT_TYPE_BUY)
        .await?;



    Ok(())
}
