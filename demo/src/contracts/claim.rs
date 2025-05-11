use ethers::{
    types::{Address, Bytes, U256, H256},
    signers::{LocalWallet, Signer},
    utils::keccak256,
};
use eyre::Result;
use crate::contracts::common::{get_client, get_vault};
use std::env;
use dotenv::dotenv;


pub async fn claim(amount: U256) -> Result<H256> {
    dotenv().ok();

    let rpc_url = env::var("MINATO_RPC_URL").expect("MINATO_RPC_URL must be set");
    let notary_private_key = env::var("NOTARY_PRIVATE_KEY").expect("NOTARY_PRIVATE_KEY must be set");
    let vault_address = env::var("MINATO_VAULT_ADDRESS").expect("MINATO_VAULT_ADDRESS must be set");

    let client = get_client(&rpc_url, &notary_private_key).await?;
    let vault = get_vault(client.clone(), vault_address.parse::<Address>()?);

    // Parse notary wallet to sign
    let notary_wallet = notary_private_key.parse::<LocalWallet>()?;
    let mut packed = Vec::new();

    let recipient_address = env::var("RECIPIENT_ADDRESS").expect("RECIPIENT_ADDRESS must be set");
    let enroll_id = vault.recipient_to_enroll_id(recipient_address.parse::<Address>()?).call().await?;
    let u256_enroll_id = U256::from_big_endian(&enroll_id);
    println!("enroll_id: {:?}", u256_enroll_id);

    let mut enroll_id_bytes = [0u8; 32];
    u256_enroll_id.to_big_endian(&mut enroll_id_bytes);
    packed.extend_from_slice(&enroll_id_bytes);

    // amount: uint256 → fixed 32-byte big-endian
    let mut amount_bytes = [0u8; 32];
    amount.to_big_endian(&mut amount_bytes);
    packed.extend_from_slice(&amount_bytes);

    let message_hash = keccak256(&packed);
    let hash = H256::from_slice(&message_hash);
    let signature = notary_wallet.sign_hash(hash).unwrap();

    // println!("Signature: v={}, r=0x{:x}, s=0x{:x}", signature.v, signature.r, signature.s);
    // Call the claim function with the signature components
    let tx = vault.claim(
        enroll_id,
        amount,
        signature.v as u8,
        signature.r.into(),
        signature.s.into()
    ).send().await?.await?;

    let tx_hash = tx.unwrap().transaction_hash;
    let soneium_base_url = "https://soneium-minato.blockscout.com/tx/0x";
    let soneium_tx_url = format!("{}{}", soneium_base_url, hex::encode(tx_hash));

    // println!("Claim transaction completed. Transaction url: {:?}", soneium_tx_url);

    Ok(tx_hash)
}
