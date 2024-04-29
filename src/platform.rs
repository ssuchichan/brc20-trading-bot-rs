use crate::robot::Robot;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use core::slice;
use dotenv::dotenv;
use finutils::txn_builder::TransactionBuilder;
use finutils::txn_builder::TransferOperationBuilder;
use globutils::wallet;
use ledger::data_model::TX_FEE_MIN_V0;
use ledger::data_model::{b64dec, TransferType, TxoRef, TxoSID, Utxo, ASSET_TYPE_FRA};
use ledger::data_model::{Transaction, BLACK_HOLE_PUBKEY};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::c_char;
use zei::serialization::ZeiFromToBytes;
use zei::xfr::asset_record::{open_blind_asset_record, AssetRecordType};
use zei::xfr::sig::XfrPublicKey;
use zei::xfr::structs::{AssetRecordTemplate, OwnerMemo};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Memo {
    p: String,
    op: String,
    tick: String,
    amt: String,
}

impl Memo {
    fn new(p: String, op: String, tick: String, amt: String) -> Self {
        Self { p, op, tick, amt }
    }
}

#[no_mangle]
pub extern "C" fn get_tx_str(
    from_sig_ptr: *mut u8,
    from_sig_len: u32,
    fra_receiver_ptr: *mut u8,
    fra_receiver_len: u32,
    to_ptr: *mut u8,
    to_len: u32,
    trans_amount_ptr: *mut u8,
    trans_amount_len: u32,
    url_ptr: *mut u8,
    url_len: u32,
    tick_ptr: *mut u8,
    tick_len: u8,
    fra_price_ptr: *mut u8,
    fra_price_len: u32,
    brc_type_ptr: *mut u8,
    brc_type_len: u32,
) -> *const c_char {
    let from_key = unsafe { slice::from_raw_parts(from_sig_ptr, from_sig_len as usize) };
    let to_pub_key = unsafe { slice::from_raw_parts(to_ptr, to_len as usize) };
    let fra_receiver_key =
        unsafe { slice::from_raw_parts(fra_receiver_ptr, fra_receiver_len as usize) };
    let tick = unsafe { slice::from_raw_parts(tick_ptr, tick_len as usize) };
    let trans_amount =
        unsafe { slice::from_raw_parts(trans_amount_ptr, trans_amount_len as usize) };
    let trans_amount_str = std::str::from_utf8(trans_amount).unwrap();
    let url = unsafe { slice::from_raw_parts(url_ptr, url_len as usize) };
    let url_str = std::str::from_utf8(url).unwrap();
    let brc_type = unsafe { slice::from_raw_parts(brc_type_ptr, brc_type_len as usize) };
    let brc_type_str = std::str::from_utf8(brc_type).unwrap();

    let fra_amount = unsafe { slice::from_raw_parts(fra_price_ptr, fra_price_len as usize) };
    let fra_amount_str = std::str::from_utf8(fra_amount).unwrap();
    let num = fra_amount_str.parse::<f64>().unwrap();
    let fra_price = (num * 1000000.0) as u64;
    let from_key_str = std::str::from_utf8(from_key).unwrap();
    let from = wallet::restore_keypair_from_mnemonic_default(from_key_str).unwrap();
    let to_dec = b64dec(to_pub_key).unwrap();
    let to = XfrPublicKey::zei_from_bytes(to_dec.as_slice()).unwrap();
    let fra_dec = b64dec(fra_receiver_key).unwrap();
    let fra_receiver = XfrPublicKey::zei_from_bytes(fra_dec.as_slice()).unwrap();

    let asset_record_type = AssetRecordType::from_flags(false, false);

    let mut op = TransferOperationBuilder::new();

    // build input
    let mut input_amount = 0;
    let mut t_amout;
    let utxos = get_owned_utxos_x(
        url_str,
        wallet::public_key_to_base64(from.get_pk_ref()).as_str(),
    )
    .unwrap();
    for (sid, (utxo, owner_memo)) in utxos.into_iter() {
        let oar = open_blind_asset_record(&utxo.0.record, &owner_memo, &from).unwrap();
        if oar.asset_type != ASSET_TYPE_FRA {
            continue;
        }
        t_amout = oar.amount;
        input_amount += t_amout;

        if t_amout != 0 {
            op.add_input(TxoRef::Absolute(sid), oar, None, None, t_amout)
                .unwrap();
            if input_amount > fra_price + TX_FEE_MIN_V0 {
                // if input big than trans amount
                break;
            }
        }
    }

    if input_amount < fra_price + TX_FEE_MIN_V0 {
        return CString::new("").unwrap().into_raw();
    }

    let memo_struct = Memo::new(
        "brc-20".to_string(),
        brc_type_str.to_string(),
        std::str::from_utf8(tick).unwrap().to_string(),
        trans_amount_str.to_string(),
    );
    let memo = serde_json::to_string(&memo_struct).unwrap();
    let template =
        AssetRecordTemplate::with_no_asset_tracing(0, ASSET_TYPE_FRA, asset_record_type, to);

    let template_from = AssetRecordTemplate::with_no_asset_tracing(
        input_amount - TX_FEE_MIN_V0 - fra_price,
        ASSET_TYPE_FRA,
        asset_record_type,
        from.get_pk(),
    );

    let template_fee = AssetRecordTemplate::with_no_asset_tracing(
        TX_FEE_MIN_V0,
        ASSET_TYPE_FRA,
        asset_record_type,
        *BLACK_HOLE_PUBKEY,
    );

    let receive_fra = AssetRecordTemplate::with_no_asset_tracing(
        fra_price,
        ASSET_TYPE_FRA,
        asset_record_type,
        fra_receiver,
    );
    // build output
    let trans_build = op
        .add_output(&template_fee, None, None, None, None)
        .and_then(|b| b.add_output(&template, None, None, None, Some(memo)))
        .and_then(|b| b.add_output(&template_from, None, None, None, None))
        .and_then(|b| b.add_output(&receive_fra, None, None, None, None))
        .and_then(|b| b.create(TransferType::Standard))
        .and_then(|b| b.sign(&from))
        .and_then(|b| b.transaction())
        .unwrap();

    let mut builder: TransactionBuilder = get_transaction_builder(url_str).unwrap();

    let tx: Transaction = builder
        .add_operation(trans_build)
        .sign_to_map(&from)
        .clone()
        .take_transaction();

    let tx_str = serde_json::to_string(&tx).unwrap();
    let c_string = CString::new(tx_str).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn get_transfer_tx_str(
    from_sig_ptr: *mut u8,
    from_sig_len: u32,
    fra_receiver_ptr: *mut u8,
    fra_receiver_len: u32,
    fra_price_ptr: *mut u8,
    fra_price_len: u32,
    url_ptr: *mut u8,
    url_len: u32,
) -> *const c_char {
    let from_key = unsafe { slice::from_raw_parts(from_sig_ptr, from_sig_len as usize) };
    let fra_receiver_key =
        unsafe { slice::from_raw_parts(fra_receiver_ptr, fra_receiver_len as usize) };

    let url = unsafe { slice::from_raw_parts(url_ptr, url_len as usize) };
    let url_str = std::str::from_utf8(url).unwrap();

    let from_key_str = std::str::from_utf8(from_key).unwrap();
    let from = wallet::restore_keypair_from_mnemonic_default(from_key_str).unwrap();
    let fra_dec = b64dec(fra_receiver_key).unwrap();
    let fra_receiver = XfrPublicKey::zei_from_bytes(fra_dec.as_slice()).unwrap();

    let fra_amount = unsafe { slice::from_raw_parts(fra_price_ptr, fra_price_len as usize) };
    let fra_amount_str = std::str::from_utf8(fra_amount).unwrap();
    let num = fra_amount_str.parse::<f64>().unwrap();
    let fra_price = (num * 1000000.0) as u64;

    let asset_record_type = AssetRecordType::from_flags(false, false);

    let mut op = TransferOperationBuilder::new();

    // build input
    let mut input_amount = 0;
    let mut t_amout;
    let utxos = get_owned_utxos_x(
        url_str,
        wallet::public_key_to_base64(from.get_pk_ref()).as_str(),
    )
    .unwrap();
    for (sid, (utxo, owner_memo)) in utxos.into_iter() {
        let oar = open_blind_asset_record(&utxo.0.record, &owner_memo, &from).unwrap();
        if oar.asset_type != ASSET_TYPE_FRA {
            continue;
        }
        t_amout = oar.amount;
        input_amount += t_amout;

        if t_amout != 0 {
            op.add_input(TxoRef::Absolute(sid), oar, None, None, t_amout)
                .unwrap();
            if input_amount > fra_price + TX_FEE_MIN_V0 {
                // if input big than trans amount
                break;
            }
        }
    }

    if input_amount < fra_price + TX_FEE_MIN_V0 {
        return CString::new("").unwrap().into_raw();
    }

    // 找零
    let template_from = AssetRecordTemplate::with_no_asset_tracing(
        input_amount - TX_FEE_MIN_V0 - fra_price,
        ASSET_TYPE_FRA,
        asset_record_type,
        from.get_pk(),
    );

    // 手续费
    let template_fee = AssetRecordTemplate::with_no_asset_tracing(
        TX_FEE_MIN_V0,
        ASSET_TYPE_FRA,
        asset_record_type,
        *BLACK_HOLE_PUBKEY,
    );

    // 转账
    let receive_fra = AssetRecordTemplate::with_no_asset_tracing(
        fra_price,
        ASSET_TYPE_FRA,
        asset_record_type,
        fra_receiver,
    );

    let trans_build = op
        .add_output(&template_fee, None, None, None, None)
        .and_then(|b| b.add_output(&template_from, None, None, None, None))
        .and_then(|b| b.add_output(&receive_fra, None, None, None, None))
        .and_then(|b| b.create(TransferType::Standard))
        .and_then(|b| b.sign(&from))
        .and_then(|b| b.transaction())
        .unwrap();

    let mut builder: TransactionBuilder = get_transaction_builder(url_str).unwrap();

    let tx: Transaction = builder
        .add_operation(trans_build)
        .sign_to_map(&from)
        .clone()
        .take_transaction();

    let tx_str = serde_json::to_string(&tx).unwrap();
    let c_string = CString::new(tx_str).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn get_seq_id(url_ptr: *mut u8, url_len: u32) -> u64 {
    let url = unsafe { slice::from_raw_parts(url_ptr, url_len as usize) };
    let url_str = std::str::from_utf8(url).unwrap();
    let result = get_transaction_builder(url_str).unwrap();
    result.get_seq_id()
}

fn get_transaction_builder(url: &str) -> Result<TransactionBuilder> {
    let url = format!("{}/global_state", url);
    attohttpc::get(&url)
        .send()
        .and_then(|resp| resp.error_for_status())
        .and_then(|resp| resp.bytes())
        .map_err(|e| anyhow!("{:?}", e))
        .and_then(|bytes| {
            serde_json::from_slice::<(Value, u64, Value)>(&bytes).map_err(|e| anyhow!("{:?}", e))
        })
        .map(|resp| TransactionBuilder::from_seq_id(resp.1))
}

fn get_owned_utxos_x(
    url: &str,
    pubkey: &str,
) -> Result<HashMap<TxoSID, (Utxo, Option<OwnerMemo>)>> {
    let url = format!("{}/owned_utxos/{}", url, pubkey);

    attohttpc::get(url)
        .send()
        .and_then(|resp| resp.bytes())
        .map_err(|e| anyhow! {"{:?}", e})
        .and_then(|b| {
            serde_json::from_slice::<HashMap<TxoSID, (Utxo, Option<OwnerMemo>)>>(&b)
                .map_err(|e| anyhow!("{:?}", e))
        })
}

#[no_mangle]
pub extern "C" fn send_tx(
    tx_prt: *mut u8,
    tx_len: u32,
    url_ptr: *mut u8,
    url_len: u32,
) -> *const c_char {
    let tx_u8 = unsafe { slice::from_raw_parts(tx_prt, tx_len as usize) };
    let tx = std::str::from_utf8(tx_u8).unwrap();
    let tx_bytes = hex::decode(tx.strip_prefix("0x").unwrap_or(tx)).unwrap();
    let url = unsafe { slice::from_raw_parts(url_ptr, url_len as usize) };
    let url_str = std::str::from_utf8(url).unwrap();
    let txn_b64 = URL_SAFE.encode(&tx_bytes);

    let json_rpc =
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"anything\",\"method\":\"broadcast_tx_sync\",\"params\": {{\"tx\": \"{}\"}}}}",
            &txn_b64
        );

    attohttpc::post(url_str)
        .header(attohttpc::header::CONTENT_TYPE, "application/json")
        .text(json_rpc)
        .send()
        .and_then(|v| v.error_for_status())
        .map(|v| println!("{:?}", v))
        .unwrap();

    let tx_hash = Sha256::digest(&tx_bytes);
    let result = hex::encode(tx_hash);
    let c_string = CString::new(result).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn generate_mnemonic_default() -> *const c_char {
    let r = wallet::generate_mnemonic_default();
    let c_string = CString::new(r).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn mnemonic_to_bench32(from_sig_ptr: *mut u8, from_sig_len: u32) -> *const c_char {
    let from_key = unsafe { slice::from_raw_parts(from_sig_ptr, from_sig_len as usize) };
    let from_key_str = std::str::from_utf8(from_key).unwrap();
    let from = wallet::restore_keypair_from_mnemonic_default(from_key_str).unwrap();
    let pub_key = from.get_pk();
    let from_bench32 = wallet::public_key_to_bech32(&pub_key);
    let c_string = CString::new(from_bench32).unwrap();
    c_string.into_raw()
}

#[derive(Serialize)]
struct RobotInitAmount {
    pub account: String,
    pub amount: u64,
}

impl RobotInitAmount {
    fn new(account: String, amount: u64) -> Self {
        Self { account, amount }
    }
}

#[no_mangle]
pub extern "C" fn get_send_robot_batch_tx(
    from_sig_ptr: *mut u8,
    from_sig_len: u32,
    url_ptr: *mut u8,
    url_len: u32,
) -> *const c_char {
    dotenv().ok();
    let from_key = unsafe { slice::from_raw_parts(from_sig_ptr, from_sig_len as usize) };
    let url = unsafe { slice::from_raw_parts(url_ptr, url_len as usize) };
    let url_str = std::str::from_utf8(url).unwrap();

    let from_key_str = std::str::from_utf8(from_key).unwrap();
    let from = wallet::restore_keypair_from_mnemonic_default(from_key_str).unwrap();

    let accounts_result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let db_user = std::env::var("DBUSER").unwrap();
        let db_password = std::env::var("PASSWORD").unwrap();
        let db_host = std::env::var("HOST").unwrap();
        let db_port = std::env::var("PORT").unwrap();
        let db_name = std::env::var("DBName").unwrap();

        let uri = format!(
            "postgres://{}:{}@{}:{}/{}",
            db_user, db_password, db_host, db_port, db_name
        );

        let pg_pool = PgPoolOptions::new().connect(&uri).await.unwrap();
        match Robot::all_accounts(&pg_pool).await {
            Ok(accounts) => accounts,
            Err(_) => {
                vec![]
            }
        }
    });

    if accounts_result.len() != 200 {
        return CString::new("").unwrap().into_raw();
    }

    let mut robot_users: Vec<RobotInitAmount> = Vec::with_capacity(accounts_result.len() as usize);
    let mut fra_price_total = 0;
    let mut rng = rand::thread_rng();
    for account in accounts_result {
        let rand_num = rng.gen_range(80000..100001);
        fra_price_total += rand_num;
        robot_users.push(RobotInitAmount::new(account, rand_num as u64));
    }

    let fra_price = fra_price_total * 1000000;

    let asset_record_type = AssetRecordType::from_flags(false, false);

    let mut op = TransferOperationBuilder::new();

    // build input
    let mut input_amount = 0;
    let mut t_amout;
    let utxos = get_owned_utxos_x(
        url_str,
        wallet::public_key_to_base64(from.get_pk_ref()).as_str(),
    )
    .unwrap();
    for (sid, (utxo, owner_memo)) in utxos.into_iter() {
        let oar = open_blind_asset_record(&utxo.0.record, &owner_memo, &from).unwrap();
        if oar.asset_type != ASSET_TYPE_FRA {
            continue;
        }
        t_amout = oar.amount;
        input_amount += t_amout;

        if t_amout != 0 {
            op.add_input(TxoRef::Absolute(sid), oar, None, None, t_amout)
                .unwrap();
            if input_amount > fra_price + TX_FEE_MIN_V0 {
                // if input big than trans amount
                break;
            }
        }
    }

    if input_amount < fra_price + TX_FEE_MIN_V0 {
        return CString::new("").unwrap().into_raw();
    }

    // 找零
    let template_from = AssetRecordTemplate::with_no_asset_tracing(
        input_amount - TX_FEE_MIN_V0 - fra_price,
        ASSET_TYPE_FRA,
        asset_record_type,
        from.get_pk(),
    );

    // 手续费
    let template_fee = AssetRecordTemplate::with_no_asset_tracing(
        TX_FEE_MIN_V0,
        ASSET_TYPE_FRA,
        asset_record_type,
        *BLACK_HOLE_PUBKEY,
    );

    op.add_output(&template_fee, None, None, None, None)
        .and_then(|b| b.add_output(&template_from, None, None, None, None))
        .unwrap();

    for out in robot_users {
        // 转账
        let receive_fra = AssetRecordTemplate::with_no_asset_tracing(
            out.amount * 1000000,
            ASSET_TYPE_FRA,
            asset_record_type,
            wallet::public_key_from_bech32(&out.account).unwrap(),
        );
        op.add_output(&receive_fra, None, None, None, None).unwrap();
    }

    let trans_build = op
        .create(TransferType::Standard)
        .and_then(|b| b.sign(&from))
        .and_then(|b| b.transaction())
        .unwrap();

    let mut builder: TransactionBuilder = get_transaction_builder(url_str).unwrap();

    let tx: Transaction = builder
        .add_operation(trans_build)
        .sign_to_map(&from)
        .clone()
        .take_transaction();

    let tx_str = serde_json::to_string(&tx).unwrap();
    let c_string = CString::new(tx_str).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn get_user_fra_balance(
    from_sig_ptr: *mut u8,
    from_sig_len: u32,
    url_ptr: *mut u8,
    url_len: u32,
) -> u64 {
    let from_key = unsafe { slice::from_raw_parts(from_sig_ptr, from_sig_len as usize) };
    let url = unsafe { slice::from_raw_parts(url_ptr, url_len as usize) };
    let url_str = std::str::from_utf8(url).unwrap();

    let from_key_str = std::str::from_utf8(from_key).unwrap();
    let from = wallet::restore_keypair_from_mnemonic_default(from_key_str).unwrap();

    // build input
    let mut input_amount = 0;
    let utxos = get_owned_utxos_x(
        url_str,
        wallet::public_key_to_base64(from.get_pk_ref()).as_str(),
    )
    .unwrap();
    for (_, (utxo, owner_memo)) in utxos.into_iter() {
        let oar = open_blind_asset_record(&utxo.0.record, &owner_memo, &from).unwrap();
        if oar.asset_type != ASSET_TYPE_FRA {
            continue;
        }
        input_amount += oar.amount;
    }

    input_amount
}
