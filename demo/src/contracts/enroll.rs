use ethers::types::{Address, U256};
use eyre::Result;
use crate::contracts::common::{get_client, get_vault};
use std::env;
use dotenv::dotenv;

pub async fn enroll(from_binance_id: String, amount: U256, recipient_address: String) -> Result<()> {
    dotenv().ok();
    
    let rpc_url = env::var("MINATO_RPC_URL").expect("MINATO_RPC_URL must be set");
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let vault_address = env::var("MINATO_VAULT_ADDRESS").expect("MINATO_VAULT_ADDRESS must be set");

    let client = get_client(&rpc_url, &private_key).await?;
    let vault = get_vault(client, vault_address.parse::<Address>()?);
    

    println!("Calling enroll with fromBinanceId: {}, amount: {}, recipient_address: {}", from_binance_id, amount, recipient_address);
    let tx = vault.enroll(from_binance_id, recipient_address.parse::<Address>()?, amount).send().await?.await?;
    println!("Enroll transaction completed. Transaction hash: {:?}", tx.unwrap().transaction_hash);
    
    Ok(())
} 