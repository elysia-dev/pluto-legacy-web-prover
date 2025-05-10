use ethers::{
  types::{Address},
  signers::{LocalWallet, Signer},
};
use eyre::Result;
use crate::contracts::common::{get_client, get_erc20};
use std::env;
use dotenv::dotenv;

pub struct Balances {
  pub vault_balance: u64,
  pub sender_balance: u64,
  pub recipient_balance: u64,
}

pub async fn check_usdt_balance() -> Result<Balances> {
  dotenv().ok();
  
  let rpc_url = env::var("MINATO_RPC_URL").expect("MINATO_RPC_URL must be set");
  let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
  let usdt_address = env::var("MINATO_USDT_ADDRESS").expect("MINATO_USDT_ADDRESS must be set");
  let vault_address = env::var("MINATO_VAULT_ADDRESS").expect("MINATO_VAULT_ADDRESS must be set");
  let recipient_address = env::var("RECIPIENT_ADDRESS").expect("RECIPIENT_ADDRESS must be set");

  let client = get_client(&rpc_url, &private_key).await?;
  let usdt = get_erc20(client.clone(), usdt_address.parse::<Address>()?);
  
  // Check balances
  let vault_balance = usdt.balance_of(vault_address.parse::<Address>()?).call().await?;
  let sender_address = client.address();
  let sender_balance = usdt.balance_of(sender_address).call().await?;
  let recipient_balance = usdt.balance_of(recipient_address.parse::<Address>()?).call().await?;
  
  
  // return balances
  let balances = Balances {
    vault_balance: vault_balance.as_u64(),
    sender_balance: sender_balance.as_u64(),
    recipient_balance: recipient_balance.as_u64(),
  };
  Ok(balances)
} 