use clap::Parser;
use client::{config::Config, errors::ClientErrors};
use tracing::Level;
use ethers::{
  providers::{Http, Provider},
  types::{U256, U64},
};
use client::{origo, verify};
use tracing::debug;
use crate::lib::{prover_inner_origo_noir_with_http_body};
use crate::contracts::has_valid_payment_history;

mod lib;
mod contracts;

#[derive(Parser)]
#[clap(name = "Web Proof Client")]
#[clap(about = "A client to generate Web Proofs.", long_about = None)]
struct BinanceDemoArgs {
  #[clap(short, long, required = false, default_value = "DEBUG")]
  log_level: String,

  #[clap(short, long, required = true, default_value = "config.json")]
  config: String,

  // For noir hackathon binance demo
  #[clap( long, required = true)]
  from_binance_id: String,
  #[clap( long, required = true)]
  receiver_binance_id: String,
  #[clap( long, required = true)]
  amount: String,
  #[clap( long, required = true)]
  currency: String,
}

#[tokio::main]
async fn main() -> Result<(), ClientErrors> {
  let args = BinanceDemoArgs::parse();

  let from_binance_id = args.from_binance_id.clone();
  let amount = args.amount.parse::<u64>().unwrap();
  let currency = args.currency.clone();
  let receiver_binance_id = args.receiver_binance_id.clone();
  let amount_u256 = U256::from(amount * 1_000_000);

  let log_level = match args.log_level.to_lowercase().as_str() {
    "error" => Level::ERROR,
    "warn" => Level::WARN,
    "info" => Level::INFO,
    "debug" => Level::DEBUG,
    "trace" => Level::TRACE,
    _ => Level::TRACE,
  };
  tracing_subscriber::fmt().with_max_level(log_level).with_line_number(true).init();

  let _ = rustls::crypto::ring::default_provider().install_default();

  let config_json = std::fs::read_to_string(args.config)?;
  let mut config: Config = serde_json::from_str(&config_json)?;
  let session_id = config.set_session_id();

  let proving_params = std::fs::read(proofs::circuits::PROVING_PARAMS_512)?;

  let (proof, http_body) = prover_inner_origo_noir_with_http_body(config.clone()).await.unwrap();
  let proof_json = serde_json::to_string_pretty(&proof)?;
  println!("#2. Proof generated successfully: proof_len={:?}", proof_json.len());

  let manifest = config.proving.manifest.clone().ok_or(ClientErrors::ManifestMissingError)?;

  // Check if proof is Origo variant and handle accordingly
  if let client::Proof::Origo(mut origo_proof) = proof {
    debug!("sending proof to proxy for verification");
    let verify_response = verify(config, origo::VerifyBody {
      session_id,
      origo_proof: origo_proof.clone(),
      manifest: manifest.into(),
    })
    .await?;
    origo_proof.sign_reply = Some(verify_response);

    debug!("proof.value: {:?}\nproof.verify_reply: {:?}", origo_proof.value, origo_proof.sign_reply);
    println!("#3. Proof verified successfully");
  } else {
    println!("Unexpected proof type, expected Origo proof");
  }

  // check response has valid payment history
  match contracts::has_valid_payment_history(&http_body,  from_binance_id.clone(), amount.to_string(), currency.clone(), receiver_binance_id.clone()) {
    Ok(true) => {
      println!("#4. Valid payment history found.");
      println!("    From Binance ID: {:?}", from_binance_id.clone());
      println!("    Amount: {:?}", amount.clone());
      println!("    Currency: {:?}", currency.clone());
      println!("    Receiver Binance ID: {:?}", receiver_binance_id.clone());

    }
    Ok(false) => println!("No valid payment history found."),
    Err(e) => {
      println!("Error occurred: {}", e);
      return Err(ClientErrors::Other(e));
    }
  }

  match contracts::check_usdt_balance().await {
    Ok(balances) => {
      println!("#5. check_usdt_balance");
      println!("    Vault_balance: {}", balances.vault_balance);
      println!("    Sender_balance: {}", balances.sender_balance);
      println!("    Recipient_balance: {}", balances.recipient_balance);
    }
    Err(e) => println!("check_usdt_balance failed: {}", e),
  }

  match contracts::claim(amount_u256).await {
    Ok(tx_hash) => {
      let soneium_base_url = "https://soneium-minato.blockscout.com/tx/0x";
      let soneium_tx_url = format!("{}{}", soneium_base_url, hex::encode(tx_hash));

      println!("#6. claim success: {}", soneium_tx_url);
    }
    Err(e) => println!("#6. claim failed: {}", e),
  }

  match contracts::check_usdt_balance().await {
    Ok(balances) => {
    println!("#7. check_usdt_balance");
      println!("    Vault_balance: {}", balances.vault_balance);
      println!("    Sender_balance: {}", balances.sender_balance);
      println!("    Recipient_balance: {}", balances.recipient_balance);
    }
    Err(e) => println!("check_usdt_balance failed: {}", e),
  }

  Ok(())
}
