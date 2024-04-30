mod db;
mod platform;
mod robot;
mod types;
mod utils;

use crate::db::Storage;
use crate::types::{FraAccount, ListResponse, Rpc};
use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use env_logger::Target;
use log::info;
use sqlx::pool::PoolOptions;
use sqlx::{PgPool, Pool, Postgres};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use std::{env, io};
use std::{fs::File, io::Write};
use tokio::time::interval;
use tokio::{runtime, time};
use utils::gen_accounts;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = 10)]
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
    accounts_mint: Vec<FraAccount>,
    accounts_buy: Vec<FraAccount>,
    rpc_ex: Arc<Rpc>,
}

impl BotServer {
    pub fn new(
        pool: PgPool,
        rpc_url: &str,
        accounts_mint: Vec<FraAccount>,
        accounts_buy: Vec<FraAccount>,
    ) -> Result<Self> {
        Ok(Self {
            storage: Arc::new(Storage::new(pool)),
            accounts_mint,
            accounts_buy,
            rpc_ex: Arc::new(Rpc::new(rpc_url)?),
        })
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

    pub async fn get_token_list(
        &self,
        token: &str,
        page: i32,
        page_size: i32,
    ) -> Result<ListResponse> {
        let res = self.rpc_ex.get_token_list(token, page, page_size).await?;
        Ok(res)
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
    println!("Connecting DB...ok");

    let args = Args::parse();
    let accounts_mint: Vec<FraAccount> = match File::open(ACCOUNT_MINT) {
        Ok(mut f) => {
            let mut contents = String::new();
            f.read_to_string(&mut contents)?;
            let accounts = serde_json::from_str(&contents)?;
            println!("Reading accounts-mint... ok");
            accounts
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                let accounts = gen_accounts(args.accounts)?;
                let mut f = File::create(ACCOUNT_MINT)?;
                let s = serde_json::to_string_pretty(&accounts)?;
                let _ = f.write_all(s.as_bytes())?;
                println!("Generating accounts-mint... ok");
                accounts
            } else {
                panic!("{}", e);
            }
        }
    };

    let accounts_buy: Vec<FraAccount> = match File::open(ACCOUNT_BUY) {
        Ok(mut f) => {
            let mut contents = String::new();
            f.read_to_string(&mut contents)?;
            let accounts = serde_json::from_str(&contents)?;
            println!("Reading accounts-buy... ok");
            accounts
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                let accounts = gen_accounts(args.accounts)?;
                let mut f = File::create(ACCOUNT_BUY)?;
                let s = serde_json::to_string_pretty(&accounts)?;
                let _ = f.write_all(s.as_bytes())?;
                println!("Generating accounts-buy... ok");
                accounts
            } else {
                panic!("{}", e);
            }
        }
    };
    let token = env::var("TOKEN")?;
    let rpc_ex_url = env::var("EX_RPC")?;
    let server = BotServer::new(pool, &rpc_ex_url, accounts_mint, accounts_buy)?;
    server.prepare_accounts().await?;

    let mut timer1 = time::interval(time::Duration::from_secs(5));
    let mut timer2 = time::interval(time::Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = timer1.tick() => {
                let list_res = server.get_token_list(&token, 1, 50).await?;
                if let Some(lists) = list_res.data {
                    println!("total lists: {}", lists.len());
                }
                println!("No lists");
            },
            _ = timer2.tick() => println!("Timer 2 ticked!"),
            // 可以添加更多的定时器...
        }
    }

    Ok(())
}
