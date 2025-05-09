extern crate core;

pub mod tlsn;
#[cfg(not(target_arch = "wasm32"))] mod tlsn_native;
#[cfg(target_arch = "wasm32")] mod tlsn_wasm32;

pub mod origo;
#[cfg(not(target_arch = "wasm32"))] mod origo_native;
#[cfg(target_arch = "wasm32")] mod origo_wasm32;

pub mod config;
pub mod errors;
mod proof;
mod tls;

pub mod tls_client_async2;
pub mod contracts;

use std::collections::HashMap;

use clap::Arg;
use origo::OrigoProof;
use proofs::{
  circuits::{construct_setup_data_from_fs, CIRCUIT_SIZE_512},
  program::data::UninitializedSetup,
};
use serde::{Deserialize, Serialize};
use tlsn::{TlsnProof, TlsnVerifyBody};
use tlsn_common::config::ProtocolConfig;
pub use tlsn_core::attestation::Attestation;
use tlsn_prover::ProverConfig;
use tracing::{debug, info};
use web_prover_core::{
  manifest::Manifest,
  proof::{SignedVerificationReply, TeeProof},
};

use crate::errors::ClientErrors;
use serde_json::{Value};
use std::str;

use ethers::types::U256;
use std::env;
use dotenv::dotenv;

use clap::{Parser, command};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
  #[clap(short, long, required = false, default_value = "DEBUG")]
  log_level: String,

  #[clap(short, long, required = true, default_value = "config.json")]
  config: String,

  // !NOTE: for noir hackathon
  #[clap( long, required = true)]
  from_binance_id: String,
  #[clap( long, required = true)]
  receiver_binance_id: String,
  #[clap( long, required = true)]
  amount: String,
  #[clap( long, required = true)]
  currency: String,

}


#[derive(Debug, Deserialize)]
struct Response {
    code: String,
    data: Vec<Payment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payment {
    order_id: String,
    amount: String,
    currency: String,
    payer_info: PayerInfo,
    receiver_info: ReceiverInfo,
    _other: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayerInfo {
  name: Option<String>,
  binance_id: Option<u64>,
  _other: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiverInfo {
  binance_id: u64,
  _other: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub enum Proof {
  Tlsn(TlsnProof),
  Origo(OrigoProof),
  TEE(TeeProof),
  Proxy(TeeProof),
}

pub fn get_web_prover_circuits_version() -> String {
  env!("WEB_PROVER_CIRCUITS_VERSION").to_string()
}

pub async fn prover_inner(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
  setup_data: Option<UninitializedSetup>,
) -> Result<Proof, ClientErrors> {
  info!("GIT_HASH: {}", env!("GIT_HASH"));
  match config.mode {
    config::NotaryMode::TLSN => prover_inner_tlsn(config).await,
    config::NotaryMode::Origo => prover_inner_origo(config, proving_params, setup_data).await,
    config::NotaryMode::TEE => prover_inner_tee(config).await,
    config::NotaryMode::Proxy => prover_inner_proxy(config).await,
  }
}

pub async fn prover_inner_tlsn(mut config: config::Config) -> Result<Proof, ClientErrors> {
  let max_sent_data = config
    .max_sent_data
    .ok_or_else(|| ClientErrors::Other("max_sent_data is missing".to_string()))?;
  let max_recv_data = config
    .max_recv_data
    .ok_or_else(|| ClientErrors::Other("max_recv_data is missing".to_string()))?;

  let prover_config = ProverConfig::builder()
    .server_name(config.target_host()?.as_str())
    .protocol_config(
      ProtocolConfig::builder()
        .max_sent_data(max_sent_data)
        .max_recv_data(max_recv_data)
        .build()?,
    )
    .build()?;

  #[cfg(target_arch = "wasm32")]
  let prover = tlsn_wasm32::setup_connection(&mut config, prover_config).await?;

  #[cfg(not(target_arch = "wasm32"))]
  let prover = if config.websocket_proxy_url.is_some() {
    tlsn_native::setup_websocket_connection(&mut config, prover_config).await
  } else {
    tlsn_native::setup_tcp_connection(&mut config, prover_config).await
  };

  let manifest = match config.proving.manifest.clone() {
    Some(m) => m,
    None => return Err(errors::ClientErrors::ManifestMissingError),
  };

  let p = tlsn::notarize(prover, &manifest).await?;

  let verify_response = verify(config, TlsnVerifyBody { manifest, proof: p.clone() }).await?;

  debug!("proof.verify_reply: {:?}", verify_response);

  Ok(Proof::Tlsn(TlsnProof { proof: p, sign_reply: Some(verify_response) }))
}


#[allow(unused_variables)]
pub async fn prover_inner_origo(
  config: config::Config,
  proving_params: Option<Vec<u8>>,
  setup_data: Option<UninitializedSetup>,
) -> Result<Proof, ClientErrors> {
  dotenv().ok();

  let args = Args::parse();


    let from_binance_id = args.from_binance_id.clone();
    let amount = args.amount.clone();
    let currency = args.currency.clone();
    let receiver_binance_id = args.receiver_binance_id.clone();

    let base_amount = 1;

    let amount_number = amount.parse::<u64>().unwrap();
    let amount_u256 = U256::from(amount_number * 1_000_000);

    // when Using fixed inputs
    // let amount = String::from(base_amount.to_string());
    // let currency = String::from("USDT");
    // let receiver_binance_id = 93260646;
    // let from_binance_id = "71035696".to_string();  

  let session_id = config.session_id.clone();

  let setup_data = if let Some(setup_data) = setup_data {
    Ok(setup_data)
  } else if !cfg!(target_os = "ios") && !cfg!(target_arch = "wasm32") {
    // TODO: How do we decide which CIRCUIT_SIZE_* to use here?
    construct_setup_data_from_fs::<{ CIRCUIT_SIZE_512 }>()
      .map_err(|e| ClientErrors::Other(e.to_string()))
  } else {
    Err(ClientErrors::MissingSetupData)
  }?;

  let (mut proof, http_body) =
    origo::proxy_and_sign_and_generate_proof(config.clone(), proving_params, setup_data).await?;
  let origo_proof = Proof::Origo(proof.clone());
  let proof_json = serde_json::to_string_pretty(&origo_proof)?;
  println!("#2. Proof generated successfully: proof_len={:?}", proof_json.len());

  let manifest = config.proving.manifest.clone().ok_or(ClientErrors::ManifestMissingError)?;

  debug!("sending proof to proxy for verification");
  let verify_response = verify(config, origo::VerifyBody {
    session_id,
    origo_proof: proof.clone(),
    manifest: manifest.into(),
  })
  .await?;
  proof.sign_reply = Some(verify_response);

  debug!("proof.value: {:?}\nproof.verify_reply: {:?}", proof.value, proof.sign_reply);

  println!("#3. Proof verified successfully");

  // check response has valid payment history
  match has_valid_payment_history(&http_body,  from_binance_id.clone(), amount.clone(), currency.clone(), receiver_binance_id.clone()) {
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

  // TODO: This is where we should output richer proof data, the verify response has the hash of
  // the target value now. Since this is in the client, we can use the private variables here. We
  // just need to get out the value.
  Ok(Proof::Origo(proof))
}

pub async fn prover_inner_tee(mut config: config::Config) -> Result<Proof, ClientErrors> {
  let session_id = config.set_session_id();

  // TEE mode uses Origo networking stack with minimal changes

  #[cfg(target_arch = "wasm32")]
  let (_origo_conn, tee_proof) = origo_wasm32::proxy(config, session_id).await?;

  #[cfg(not(target_arch = "wasm32"))]
  let (_origo_conn, tee_proof) = origo_native::proxy(config, session_id).await?;

  Ok(Proof::TEE(tee_proof.unwrap()))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyConfig {
  pub target_method:  String,
  pub target_url:     String,
  pub target_headers: HashMap<String, String>,
  pub target_body:    String,
  pub manifest:       Manifest,
}

pub async fn prover_inner_proxy(config: config::Config) -> Result<Proof, ClientErrors> {
  let session_id = config.session_id.clone();

  let url = format!(
    "https://{}:{}/v1/proxy?session_id={}",
    config.notary_host.clone(),
    config.notary_port.clone(),
    session_id.clone(),
  );

  let proxy_config = ProxyConfig {
    target_method:  config.target_method,
    target_url:     config.target_url,
    target_headers: config.target_headers,
    target_body:    config.target_body,
    manifest:       config.proving.manifest.unwrap(),
  };

  // TODO reqwest uses browsers fetch API for WASM target? if true, can't add trust anchors
  #[cfg(target_arch = "wasm32")]
  let client = reqwest::ClientBuilder::new().build()?;

  #[cfg(not(target_arch = "wasm32"))]
  let client = {
    let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();
    if let Some(cert) = config.notary_ca_cert {
      client_builder =
        client_builder.add_root_certificate(reqwest::tls::Certificate::from_der(&cert)?);
    }
    client_builder.build()?
  };

  let response = client.post(url).json(&proxy_config).send().await?;
  assert_eq!(response.status(), hyper::StatusCode::OK);
  let tee_proof = response.json::<TeeProof>().await?;
  Ok(Proof::Proxy(tee_proof))
}

pub async fn verify<T: Serialize>(
  config: crate::config::Config,
  verify_body: T,
) -> Result<SignedVerificationReply, errors::ClientErrors> {
  let url = format!(
    "https://{}:{}/v1/{}/verify",
    config.notary_host.clone(),
    config.notary_port.clone(),
    config.mode.to_string(),
  );

  // TODO reqwest uses browsers fetch API for WASM target? if true, can't add trust anchors
  #[cfg(target_arch = "wasm32")]
  let client = reqwest::ClientBuilder::new().build()?;

  #[cfg(not(target_arch = "wasm32"))]
  let client = {
    let mut client_builder = reqwest::ClientBuilder::new().use_rustls_tls();
    if let Some(cert) = config.notary_ca_cert {
      client_builder =
        client_builder.add_root_certificate(reqwest::tls::Certificate::from_der(&cert)?);
    }
    client_builder.build()?
  };

  let response = client.post(url).json(&verify_body).send().await?;
  assert!(response.status() == hyper::StatusCode::OK, "response={:?}", response);
  let verify_response = response.json::<SignedVerificationReply>().await?;

  debug!("\n{:?}\n\n", verify_response.clone());

  Ok(verify_response)
}

/// Checks if there is a valid Binance payment history for a specific from and receiver_id pair in the HTTP response body.
/// We use this because complex logic cannot be included in the JSON extractor.
///
/// # Arguments
///
/// * `http_body` - API response body (Vec<u8>)
/// * `from_binance_id` - Payer from_binance_id to check
/// * `receiver_id` - Receiver ID to check
///
/// # Returns
///
/// * `Result<bool, String>` - Ok(true) if valid payment history exists, Ok(false) if not, Err on error
fn has_valid_payment_history(
    http_body: &[u8], 
    from_binance_id: String, 
    amount: String,
    currency: String,
    receiver_binance_id: String,
) -> Result<bool, String> {
    // Convert byte array to string
    let body_str = match str::from_utf8(http_body) {
        Ok(s) => s,
        Err(e) => return Err(format!("UTF-8 conversion error: {}", e)),
    };
    
    let response: Response = match serde_json::from_str(body_str) {
      Ok(resp) => resp,
      Err(e) => {
          println!("Failed to parse response: {}", e);
          return Err(format!("Failed to parse response: {}", e));
      }
  };
  
  if response.code != "000000" {
      println!("Invalid response code: {}", response.code);
      return Err(format!("Invalid response code: {}", response.code));
  }
  
  if response.data.is_empty() {
      println!("No payment data found");
      return Err(format!("No payment data found"));
  }
    
  // Find any transaction that matches our criteria
  for payment in response.data {

    let payer_binance_id_from_json = payment.payer_info.binance_id.unwrap_or(0).to_string();

    if payer_binance_id_from_json != from_binance_id {
      continue
    }
    // TODO: check already used payment


    println!("payment.payer_info: {:?}", payment.payer_info);
    println!("payment.receiver_info: {:?}", payment.receiver_info);
    let receiver_binance_id_from_json = payment.receiver_info.binance_id.to_string();
    let amount_from_json = payment.amount;
    let currency_from_json = payment.currency;

    println!("payer_binance_id_from_json: {:?}", payer_binance_id_from_json);
    println!("from_binance_id: {:?}", from_binance_id);
    println!("receiver_binance_id_from_json: {:?}", receiver_binance_id_from_json);
    println!("receiver_binance_id: {:?}", receiver_binance_id);
    println!("currency_from_json: {:?}", currency_from_json);
    println!("currency: {:?}", currency);

    // !NOTE: skip amount check: for demo
    // amount_from_json == amount 
    if  payer_binance_id_from_json == from_binance_id && receiver_binance_id_from_json == receiver_binance_id && currency_from_json == currency {
        return Ok(true);
    }
  }
    
  // No matching payment history found
  Ok(false)
}
