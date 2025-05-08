use edge_frontend::program::{ROM, Switchboard};
use edge_frontend::setup::Setup;
use proofs::{program, program::manifest::{EncryptionInput, NIVCRom, OrigoManifest}};
use proofs::circuits::{PLAINTEXT_AUTHENTICATION_NOIR_PROGRAM};
use proofs::program::noir::initialize_circuit_list;
use crate::{origo::OrigoProof, ClientErrors};

/// creates NIVC proof from TLS transcript and [`Manifest`] config
/// # Arguments
/// - `proving_params` - proving parameters from edge/prover/src/supernova/mod.rs
pub async fn construct_program_data_and_proof<const CIRCUIT_SIZE: usize>(
    manifest: &OrigoManifest,
    request_inputs: &EncryptionInput,
    response_inputs: &EncryptionInput,
) -> Result<OrigoProof, ClientErrors> {
    let NIVCRom { circuit_data, rom } =
        manifest.build_rom_noir::<CIRCUIT_SIZE>(request_inputs, response_inputs);

    let (switchboard_inputs, initial_nivc_input) = manifest.build_switchboard_inputs::<CIRCUIT_SIZE>(
      request_inputs,
      response_inputs,
      &circuit_data,
      &rom,
    )?;

    let noir_program_paths = vec![PLAINTEXT_AUTHENTICATION_NOIR_PROGRAM];
    let noir_programs = initialize_circuit_list(&noir_program_paths);

    let initial_circuit_index = 0;
    let switchboard = Switchboard::<ROM>::new(
      noir_programs,
      switchboard_inputs,
      initial_nivc_input.to_vec(),
      initial_circuit_index,
    );
    let setup = Setup::new(switchboard).unwrap();

    let recursive_snark = program::noir::run(&setup).await.unwrap();
    let compressed_proof = program::noir::compress_proof(&setup, &recursive_snark).unwrap();
    let proof = compressed_proof.serialize()?;

    Ok(OrigoProof {
        proof,
        rom: NIVCRom { circuit_data, rom },
        ciphertext_digest: initial_nivc_input[0].to_bytes(),
        sign_reply: None,
        value: None,
    })
}
