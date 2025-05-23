//! Brings in circuit from [web-prover-circuits](https://github.com/pluto/web-prover-circuits) and witnesscalc graph binaries to be embedded into the client during compile time.
//! Contains 512B, 256B following circuits:
//! - AES: AES encryption
//! - HTTP: HTTP parsing and locking
//! - JSON: JSON extract
use std::collections::HashMap;
use edge_frontend::program::{Configuration, Switchboard};
use edge_frontend::setup::{Ready, Setup};
use edge_prover::supernova::snark::{CompressedSNARK, VerifierKey};
use proofs::{
  circuits::{construct_setup_data_from_fs, PROVING_PARAMS_512},
  program::data::{CircuitData, Offline, Online, SetupParams},
  E1, F, G1, G2, S1, S2,
};
use tracing::{debug, info};
use proofs::circuits::{PLAINTEXT_AUTHENTICATION_NOIR_PROGRAM, NOIR_SETUP_PATH};
use proofs::program::noir::initialize_circuit_list;
use crate::errors::ProxyError;

pub struct Verifier {
  pub setup_params: SetupParams<Online>,
  pub verifier_key: VerifierKey<E1, S1, S2>,
}

pub fn flatten_rom(rom: Vec<String>) -> Vec<String> {
  rom
    .iter()
    .map(|s| {
      s.rfind('_')
        .and_then(
          |i| if s[i + 1..].chars().all(|c| c.is_ascii_digit()) { Some(&s[..i]) } else { None },
        )
        .unwrap_or(s)
        .to_string()
    })
    .collect()
}

pub fn initialize_noir_verifier() -> Result<Setup<Ready<Configuration>>, ProxyError> {
  let noir_program_paths = vec![PLAINTEXT_AUTHENTICATION_NOIR_PROGRAM];
  // Verify
  let path = std::path::PathBuf::from(NOIR_SETUP_PATH);
  let vsetup = Setup::load_file(&path).unwrap();
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let vswitchboard = Switchboard::<Configuration>::new(noir_programs);
  let vsetup = vsetup.into_ready(vswitchboard);

  Ok(vsetup)
}

pub fn initialize_verifier() -> Result<Verifier, ProxyError> {
  use std::env;
  match env::current_dir() {
    Ok(path) => info!("Current working directory: {}", path.display()),
    Err(e) => panic!("Error getting current directory: {}", e),
  }
  info!("proving_params={:?}", PROVING_PARAMS_512);
  let bytes = std::fs::read(PROVING_PARAMS_512)?;
  info!("done");
  let setup_data = construct_setup_data_from_fs::<{ proofs::circuits::CIRCUIT_SIZE_512 }>()?;
  info!("setup data complete");
  let rom_data = HashMap::from([
    (String::from("PLAINTEXT_AUTHENTICATION"), CircuitData { opcode: 0 }),
    (String::from("HTTP_VERIFICATION"), CircuitData { opcode: 1 }),
    (String::from("JSON_EXTRACTION"), CircuitData { opcode: 2 }),
  ]);

  let setup_params = SetupParams::<Offline> {
    public_params: bytes,
    // TODO: These are incorrect, but we don't know them until the internal parser completes.
    // during the transition to `into_online` they're populated.
    vk_digest_primary: F::<G1>::from(0),
    vk_digest_secondary: F::<G2>::from(0),
    setup_data,
    rom_data,
  }
  .into_online()?;

  let (pk, verifier_key) = CompressedSNARK::<E1, S1, S2>::setup(&setup_params.public_params)?;
  debug!(
    "initialized pk pk_primary.digest={:?}, hex(primary)={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest,
    hex::encode(pk.pk_primary.vk_digest.to_bytes()),
    pk.pk_secondary.vk_digest,
  );

  Ok(Verifier { setup_params, verifier_key })
}
