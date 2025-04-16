use std::sync::Arc;

use edge_frontend::program::{Configuration, ROM, Switchboard, Z0_SECONDARY};
use edge_frontend::setup::Setup;
use edge_prover::supernova::PublicParams;
use proofs::{program, program::{
    data::{InitializedSetup, InstanceParams, NotExpanded, Online, ProofParams, SetupParams},
    manifest::{EncryptionInput, NIVCRom, NivcCircuitInputs, OrigoManifest},
}, E1, F, G1, G2};
use tracing::debug;
use proofs::program::noir::initialize_circuit_list;
use crate::{origo::OrigoProof, ClientErrors};

/// creates NIVC proof from TLS transcript and [`Manifest`] config
/// # Arguments
/// - `proving_params` - proving parameters from edge/prover/src/supernova/mod.rs
pub async fn construct_program_data_and_proof<const CIRCUIT_SIZE: usize>(
    manifest: &OrigoManifest,
    request_inputs: &EncryptionInput,
    response_inputs: &EncryptionInput,
    vks: (F<G1>, F<G2>),
    proving_params: Arc<PublicParams<E1>>,
    setup_data: Arc<InitializedSetup>,
) -> Result<OrigoProof, ClientErrors> {
    let NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input } =
        manifest.build_inputs::<CIRCUIT_SIZE>(request_inputs, response_inputs)?;

    let NIVCRom { circuit_data, rom } =
        manifest.build_rom::<CIRCUIT_SIZE>(request_inputs, response_inputs);

    // FIXME: use paths from NIVCRom
    let noir_program_paths = vec!["../target/collatz_even.json", "../target/collatz_odd.json"];
    let noir_programs = initialize_circuit_list(&noir_program_paths);

    // rom is Vec<string>
    // switchboard_inputs: Vec<InputMap> - Sequence of inputs for each execution step
    //  public_input: Vec<Scalar>,
    // initial_circuit_index
    let switchboard = Switchboard::<ROM>::new(
        noir_programs,
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
