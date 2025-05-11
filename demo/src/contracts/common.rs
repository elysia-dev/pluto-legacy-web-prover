use ethers::{
    prelude::*,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, Signature, U256},
};
use eyre::Result;
use std::sync::Arc;

abigen!(
    Vault,
    r#"[
        function enroll(string fromBinanceId, address recipient, uint256 amount) external
        function claim(bytes32 enrollId, uint256 amount, uint8 v, bytes32 r, bytes32 s) external
        function recipientToEnrollId(address recipient) external view returns (bytes32 enrollId)
    ]"#,
);

abigen!(
    ERC20,
    r#"[
        function balanceOf(address account) external view returns (uint256)
        function transfer(address to, uint256 amount) external returns (bool)
        function approve(address spender, uint256 amount) external returns (bool)
        function mint(address to, uint256 amount) external
    ]"#,
);

pub type Client = SignerMiddleware<Provider<Http>, LocalWallet>;

pub async fn get_client(
    rpc_url: &str,
    private_key: &str,
) -> Result<Arc<Client>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?;
    
    let wallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id.as_u64());
    
    Ok(Arc::new(SignerMiddleware::new(provider, wallet)))
}

pub fn get_vault(client: Arc<Client>, address: Address) -> Vault<Arc<Client>> {
    Vault::new(address, Arc::new(client))
}

pub fn get_erc20(client: Arc<Client>, address: Address) -> ERC20<Arc<Client>> {
    ERC20::new(address, Arc::new(client))
}

pub fn to_eth_signature(v: u8, r: [u8; 32], s: [u8; 32]) -> Signature {
    Signature {
        r: U256::from_big_endian(&r),
        s: U256::from_big_endian(&s),
        v: v.into(),
    }
} 