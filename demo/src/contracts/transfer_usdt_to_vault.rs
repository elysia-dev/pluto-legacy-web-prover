use ethers::types::{Address, U256};
use eyre::Result;
use crate::contracts::common::{get_client, get_erc20};
use std::env;
use dotenv::dotenv;

pub async fn transfer_usdt_to_vault() -> Result<()> {
    dotenv().ok();
    
    let rpc_url = env::var("MINATO_RPC_URL").expect("MINATO_RPC_URL must be set");
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let usdt_address = env::var("MINATO_USDT_ADDRESS").expect("MINATO_USDT_ADDRESS must be set");
    let vault_address = env::var("MINATO_VAULT_ADDRESS").expect("MINATO_VAULT_ADDRESS must be set");
    
    let client = get_client(&rpc_url, &private_key).await?;
    let usdt = get_erc20(client.clone(), usdt_address.parse::<Address>()?);
    let sender_address = client.address();
    
    // 1. Mint 100 USDT to sender (if MockUSDT is used)
    let amount = U256::from(100_000_000); // 100 USDT with 6 decimals
    println!("Minting 100 USDT to sender...");
    let tx = usdt.mint(sender_address, amount).send().await?.await?;
    println!("Minted USDT. Transaction hash: {:?}", tx.unwrap().transaction_hash);
    
    // 2. Transfer USDT to Vault
    println!("Transferring USDT to Vault...");
    let tx = usdt.transfer(vault_address.parse::<Address>()?, amount).send().await?.await?;
    println!("Transferred USDT to Vault. Transaction hash: {:?}", tx.unwrap().transaction_hash);
    
    Ok(())
} 