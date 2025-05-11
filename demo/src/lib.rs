use client::{config, errors::ClientErrors};
use client::{origo, Proof, verify};
use tracing::debug;
use serde::Deserialize;
use std::str;

// TODO" mod contracts

#[allow(unused_variables)]
pub async fn prover_inner_origo_noir_with_http_body(
  config: config::Config,
) -> Result<(Proof, Vec<u8>), ClientErrors> {
  debug!("prover_inner_origo_noir");
  let session_id = config.session_id.clone();

  // TODO: reuse the initialized setup

  let (mut proof, http_body) =
    origo::proxy_and_sign_and_generate_proof_noir(config.clone()).await?;

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

  // TODO: This is where we should output richer proof data, the verify response has the hash of
  // the target value now. Since this is in the client, we can use the private variables here. We
  // just need to get out the value.
  Ok((Proof::Origo(proof), http_body))
}

// #[allow(unused_variables)]
// pub async fn prover_inner_origo(
//   config: config::Config,
//   proving_params: Option<Vec<u8>>,
//   setup_data: Option<UninitializedSetup>,
// ) -> Result<Proof, ClientErrors> {
//   debug!("prover_inner_origo");
//   dotenv().ok();

//   // let from_binance_id = args.from_binance_id.clone();
//   // let amount = args.amount.clone();
//   // let currency = args.currency.clone();
//   // let receiver_binance_id = args.receiver_binance_id.clone();

//   // when Using fixed inputs
//   let base_amount = 1;
//   let amount = String::from(base_amount.to_string());
//   let amount_number = amount.parse::<u64>().unwrap();
//   let currency = String::from("USDT");
//   // let receiver_binance_id = 93260646;
//   // let from_binance_id = "71035696".to_string();
//   let receiver_binance_id = "71035696".to_string();
//   let from_binance_id = "93260646".to_string();

//   let amount_u256 = U256::from(amount_number * 1_000_000);
//   let session_id = config.session_id.clone();

//   let setup_data = if let Some(setup_data) = setup_data {
//     Ok(setup_data)
//   } else if !cfg!(target_os = "ios") && !cfg!(target_arch = "wasm32") {
//     // TODO: How do we decide which CIRCUIT_SIZE_* to use here?
//     construct_setup_data_from_fs::<{ CIRCUIT_SIZE_512 }>()
//       .map_err(|e| ClientErrors::Other(e.to_string()))
//   } else {
//     Err(ClientErrors::MissingSetupData)
//   }?;

//   let (mut proof, http_body) =
//     origo::proxy_and_sign_and_generate_proof(config.clone(), proving_params, setup_data).await?;
//   let origo_proof = Proof::Origo(proof.clone());
//   let proof_json = serde_json::to_string_pretty(&origo_proof)?;
//   println!("#2. Proof generated successfully: proof_len={:?}", proof_json.len());

//   let manifest = config.proving.manifest.clone().ok_or(ClientErrors::ManifestMissingError)?;

//   debug!("sending proof to proxy for verification");
//   let verify_response = verify(config, origo::VerifyBody {
//     session_id,
//     origo_proof: proof.clone(),
//     manifest: manifest.into(),
//   })
//   .await?;
//   proof.sign_reply = Some(verify_response);

//   debug!("proof.value: {:?}\nproof.verify_reply: {:?}", proof.value, proof.sign_reply);

//   println!("#3. Proof verified successfully");

//   // check response has valid payment history
//   match has_valid_payment_history(&http_body,  from_binance_id.clone(), amount.clone(), currency.clone(), receiver_binance_id.clone()) {
//     Ok(true) => {
//       println!("#4. Valid payment history found.");
//       println!("    From Binance ID: {:?}", from_binance_id.clone());
//       println!("    Amount: {:?}", amount.clone());
//       println!("    Currency: {:?}", currency.clone());
//       println!("    Receiver Binance ID: {:?}", receiver_binance_id.clone());

//     }
//     Ok(false) => println!("No valid payment history found."),
//     Err(e) => {
//       println!("Error occurred: {}", e);
//       return Err(ClientErrors::Other(e));
//     }
//   }

//   match contracts::check_usdt_balance().await {
//     Ok(balances) => {
//       println!("#5. check_usdt_balance");
//       println!("    Vault_balance: {}", balances.vault_balance);
//       println!("    Sender_balance: {}", balances.sender_balance);
//       println!("    Recipient_balance: {}", balances.recipient_balance);
//     }
//     Err(e) => println!("check_usdt_balance failed: {}", e),
//   }

//   match contracts::claim(amount_u256).await {
//     Ok(tx_hash) => {
//       let soneium_base_url = "https://soneium-minato.blockscout.com/tx/0x";
//       let soneium_tx_url = format!("{}{}", soneium_base_url, hex::encode(tx_hash));

//       println!("#6. claim success: {}", soneium_tx_url);
//     }
//     Err(e) => println!("#6. claim failed: {}", e),
//   }

//   match contracts::check_usdt_balance().await {
//     Ok(balances) => {
//     println!("#7. check_usdt_balance");
//       println!("    Vault_balance: {}", balances.vault_balance);
//       println!("    Sender_balance: {}", balances.sender_balance);
//       println!("    Recipient_balance: {}", balances.recipient_balance);
//     }
//     Err(e) => println!("check_usdt_balance failed: {}", e),
//   }

//   // TODO: This is where we should output richer proof data, the verify response has the hash of
//   // the target value now. Since this is in the client, we can use the private variables here. We
//   // just need to get out the value.
//   Ok(Proof::Origo(proof))
// }
