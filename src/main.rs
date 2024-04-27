mod platform;
mod robot;
mod utils;

use crate::robot::Robot;
use anyhow::Result;
use clap::Parser;
use std::io;
use std::io::Read;
use std::{fs::File, io::Write};
use utils::gen_accounts;
use utils::FraAccount;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = 20)]
    accounts: i32,
}

const ACCOUNTS_FILE: &'static str = "accounts.txt";

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let accounts: Vec<FraAccount> = match File::open(ACCOUNTS_FILE) {
        Ok(mut f) => {
            let mut contents = String::new();
            f.read_to_string(&mut contents)?;
            let accounts = serde_json::from_str(&contents)?;
            accounts
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                let accounts = gen_accounts(args.accounts)?;
                let mut f = File::create(ACCOUNTS_FILE)?;
                let s = serde_json::to_string_pretty(&accounts)?;
                let _ = f.write_all(s.as_bytes())?;
                accounts
            } else {
                panic!("{}", e);
            }
        }
    };

    print!("{:?}", accounts);

    Ok(())
}
