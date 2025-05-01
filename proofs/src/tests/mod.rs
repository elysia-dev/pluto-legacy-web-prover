//! This test module is effectively testing a static (comptime) circuit dispatch supernova
//! program

// TODO: (Colin): I'm noticing this module could use some TLC. There's a lot of lint here!

use std::sync::Arc;
use edge_frontend::noir::{GenericFieldElement, InputMap, InputValue};
use edge_frontend::program::{Configuration, RAM, Switchboard, Z0_SECONDARY, ROM};
use edge_frontend::Scalar;
use edge_frontend::setup::Setup;
use circuits::{
  HTTP_VERIFICATION_512B_GRAPH, HTTP_VERIFICATION_512B_R1CS, JSON_EXTRACTION_512B_GRAPH,
  JSON_EXTRACTION_512B_R1CS, MAX_STACK_HEIGHT, PLAINTEXT_AUTHENTICATION_512B_GRAPH,
  PLAINTEXT_AUTHENTICATION_512B_R1CS,
};
use edge_prover::supernova::RecursiveSNARK;
use halo2curves::grumpkin;
use inputs::{
  complex_manifest, complex_request_inputs, complex_response_inputs, simple_request_inputs,
  simple_response_inputs, one_block_request_inputs, one_block_empty_response_inputs,
  two_block_response_inputs,
};
use web_proof_circuits_witness_generator::polynomial_digest;

use super::*;
use crate::{
  circuits::load_artifact_bytes,
  program::{
    data::{CircuitData, NotExpanded, ProofParams, SetupParams, UninitializedSetup},
    initialize_setup_data,
    manifest::{InitialNIVCInputs, NIVCRom, NivcCircuitInputs, OrigoManifest},
  },
};
use crate::program::noir::initialize_circuit_list;

pub(crate) mod inputs;
mod witnesscalc;

#[allow(unused)]
pub const CIRCUIT_SIZE_256: usize = 256;

#[allow(unused)]
#[cfg(not(target_arch = "wasm32"))]
pub const PROVING_PARAMS_BYTES_256: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/serialized_setup_256b_rom_length_100.bin"
));

pub const PLAINTEXT_AUTHENTICATION_256B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_256b.r1cs"
));
pub const PLAINTEXT_AUTHENTICATION_256B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/plaintext_authentication_256b.bin"
));
// Circuit 1
pub const HTTP_VERIFICATION_256B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_256b.r1cs"
));
pub const HTTP_VERIFICATION_256B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/http_verification_256b.bin"
));
// Circuit 2
pub const JSON_EXTRACTION_256B_R1CS: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_256b.r1cs"
));
pub const JSON_EXTRACTION_256B_GRAPH: &[u8] = include_bytes!(concat!(
  "../../web_proof_circuits/circom-artifacts-256b-v",
  env!("WEB_PROVER_CIRCUITS_VERSION"),
  "/json_extraction_256b.bin"
));

const MAX_ROM_LENGTH: usize = 100;

#[allow(dead_code)]
fn wasm_witness_generator_type_512b() -> [WitnessGeneratorType; 3] {
  [
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-512b-v{}/plaintext_authentication_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("pa.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-512b-v{}/http_verification_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("hv.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-512b-v{}/json_extraction_512b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("je.wtns"),
    },
  ]
}
#[allow(dead_code)]
fn wasm_witness_generator_type_256b() -> [WitnessGeneratorType; 3] {
  [
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-256b-v{}/plaintext_authentication_256b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("pa.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-256b-v{}/http_verification_256b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("hv.wtns"),
    },
    WitnessGeneratorType::Wasm {
      path:      format!(
        "web_proof_circuits/circom-artifacts-256b-v{}/json_extraction_256b.wasm",
        env!("WEB_PROVER_CIRCUITS_VERSION")
      ),
      wtns_path: String::from("je.wtns"),
    },
  ]
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_rom() {
  let noir_program_paths = vec!["../target/add_external.json", "../target/square_zeroth.json", "../target/swap_memory.json"];
  let noir_programs = initialize_circuit_list(&noir_program_paths);

  let switchboard_inputs = vec![
    InputMap::from([
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(1_u64))),
      (
        "external".to_string(),
        InputValue::Vec(vec![
          InputValue::Field(GenericFieldElement::from(5_u64)),
          InputValue::Field(GenericFieldElement::from(7_u64)),
        ]),
      ),
    ]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(2_u64)))]),
    // The next_pc input of swap_memory is -1.
    InputMap::from([(
      "next_pc".to_string(),
      InputValue::Field(GenericFieldElement::from(-1_i128)),
    )]),
  ];
  let initial_circuit_index = 0;
  // public_input is the initial state
  let public_input = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3), Scalar::from(4), Scalar::from(5), Scalar::from(6), Scalar::from(7), Scalar::from(8), Scalar::from(9), Scalar::from(10), Scalar::from(11),];
  let switchboard = Switchboard::<ROM>::new(
    noir_programs,
    switchboard_inputs,
    public_input,
    initial_circuit_index,
  );
  let setup = Setup::new(switchboard).unwrap();

  let recursive_snark = program::noir::run(&setup).await.unwrap();
  let zi_primary = recursive_snark.zi_primary();
  let zi_secondary = recursive_snark.zi_secondary();
  // reg0: 1 + 5 = 6
  // reg1: 2 + 7 = 9
  // reg0: 36
  // reg1: 9
  // reg0: 9
  // reg1: 36
  assert_eq!(zi_primary[0], Scalar::from(9));
  assert_eq!(zi_primary[1], Scalar::from(36));
  assert_eq!(zi_secondary[0], grumpkin::Fr::from(0));

  let compressed_proof = program::noir::compress_proof(&setup, &recursive_snark).unwrap();

  // Verify
  /*
  let path = std::path::PathBuf::from("../target/setup.bytes");
  let vsetup = Setup::load_file(&path).unwrap();
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let vswitchboard = Switchboard::<Configuration>::new(noir_programs);
  let vsetup = vsetup.into_ready(switchboard);
  */

  let vk = setup.verifier_key().unwrap();

  let z0_primary = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3), Scalar::from(4), Scalar::from(5), Scalar::from(6), Scalar::from(7), Scalar::from(8), Scalar::from(9), Scalar::from(10), Scalar::from(11),];
  debug!("z0_primary: {:?}", z0_primary);
  debug!("z0_secondary: {:?}", Z0_SECONDARY);

  let (zn_primary, zn_secondary) = compressed_proof.proof.verify(&setup.params, &vk, &z0_primary, Z0_SECONDARY).unwrap();

  assert_eq!(zn_primary[0], Scalar::from(9));
  assert_eq!(zn_primary[1], Scalar::from(36));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_ram() {
  // Step 1: Create demo programs
  let noir_program_paths = vec!["../target/collatz_even.json", "../target/collatz_odd.json"];
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  // 42 -> 21 -> 64 -> 32 -> 16 -> 8 -> 4 -> 2 -> 1
  let input = 42;

  // Step 2: Create and prepare the switchboard for proving
  let program_index = (input % 2) as usize;
  debug!(
    "Using program index: {} ({})",
    program_index,
    if program_index == 0 { "even" } else { "odd" }
  );

  // Step 2: Create switchboard
  let switchboard = Switchboard::<RAM>::new(
    noir_programs,
    vec![Scalar::from(input)],
    program_index,
  );
  info!("✅ Created switchboard");
  debug!("Switchboard details: {:?}", switchboard);

  // Step 3: Initialize the setup
  let setup = Setup::new(switchboard).unwrap();
  info!("✅ Initialized setup");
  // debug!("Setup details: {:?}", setup);

  // Prove
  let recursive_snark = program::noir::run(&setup).await.unwrap();
  let compressed_proof = program::noir::compress_proof(&setup, &recursive_snark).unwrap();

  // Verify
  let path = std::path::PathBuf::from("../target/setup.bytes");
  let vsetup = Setup::load_file(&path).unwrap();
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let vswitchboard = Switchboard::<Configuration>::new(noir_programs);
  let vsetup = vsetup.into_ready(vswitchboard);

  let vk = vsetup.verifier_key().unwrap();
  info!("✅ Prepared verification key");
  // debug!("Verifier key details: {:?}", vk);

  let z0_primary = [Scalar::from(input)]; // 42
  debug!("z0_secondary: {:?}", Z0_SECONDARY); // 0
  let (zn_primary, zn_secondary) = compressed_proof.proof.verify(&vsetup.params, &vk, &z0_primary, Z0_SECONDARY).unwrap();

  assert_eq!(zn_primary[0], Scalar::from(1));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_plaintext_authentication_noir_store_setup() {
  use web_prover_core::test_utils::TEST_MANIFEST;

  // TODO: later change to 256 or 512
  const CIRCUIT_SIZE_NOIR: usize = 64;
  debug!("Creating `private_inputs`...");

  let request_inputs = one_block_request_inputs();
  let response_inputs = one_block_empty_response_inputs();
  let manifest: OrigoManifest = serde_json::from_str(TEST_MANIFEST).unwrap();

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE_NOIR>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  // The same code from construct_program_data_and_proof<CIRCUIT_SIZE>

  let NIVCRom { circuit_data: rom_data, rom } =
    manifest.build_rom_noir::<CIRCUIT_SIZE_NOIR>(&request_inputs, &response_inputs);
  debug!("circuit_data: {:?}", rom_data);
  debug!("rom: {:?}", rom);

  let noir_program_paths = vec!["../target/plaintext_authentication.json"];
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let (switchboard_inputs, initial_nivc_input) = manifest.build_switchboard_inputs::<CIRCUIT_SIZE_NOIR>(
    &request_inputs,
    &response_inputs,
    &rom_data,
    &rom
  ).unwrap();
  debug!("initial_nivc_input: {:?}", initial_nivc_input);
  debug!("switchboard_inputs: {:?}", switchboard_inputs);
  let initial_circuit_index = 0;

  // Step 2: Create switchboard
  let switchboard = Switchboard::<ROM>::new(
    noir_programs,
    switchboard_inputs,
    initial_nivc_input.to_vec(),
    initial_circuit_index,
  );
  // debug!("switchboard: {:?}", switchboard.switchboard_inputs);

  // Step 3: Initialize the setup
  debug!("Setup::new(switchboard)");
  let setup = Setup::new(switchboard).unwrap();
  setup.store_file(&std::path::PathBuf::from("../target/setup.bytes")).unwrap();
}


#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_plaintext_authentication_noir() {
  use web_prover_core::test_utils::TEST_MANIFEST;

  // TODO: later change to 256 or 512
  const CIRCUIT_SIZE_NOIR: usize = 64;
  debug!("Creating `private_inputs`...");

  let request_inputs = one_block_request_inputs();
  let response_inputs = one_block_empty_response_inputs();
  let manifest: OrigoManifest = serde_json::from_str(TEST_MANIFEST).unwrap();

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE_NOIR>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  // The same code from construct_program_data_and_proof<CIRCUIT_SIZE>

  let NIVCRom { circuit_data: rom_data, rom } =
    manifest.build_rom_noir::<CIRCUIT_SIZE_NOIR>(&request_inputs, &response_inputs);
  debug!("circuit_data: {:?}", rom_data);
  debug!("rom: {:?}", rom);

  let noir_program_paths = vec!["../target/plaintext_authentication_64.json"];
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let (switchboard_inputs, initial_nivc_input) = manifest.build_switchboard_inputs::<CIRCUIT_SIZE_NOIR>(
    &request_inputs,
    &response_inputs,
    &rom_data,
    &rom
  ).unwrap();
  debug!("initial_nivc_input: {:?}", initial_nivc_input);
  debug!("switchboard_inputs: {:?}", switchboard_inputs);
  let initial_circuit_index = 0;

  // Step 2: Create switchboard
  let switchboard = Switchboard::<ROM>::new(
    noir_programs,
    switchboard_inputs,
    initial_nivc_input.to_vec(),
    initial_circuit_index,
  );
  // debug!("switchboard: {:?}", switchboard.switchboard_inputs);

  // Step 3: Initialize the setup
  debug!("Setup::new(switchboard)");
  let setup = Setup::new(switchboard).unwrap();

  debug!("program::noir:run");
  let recursive_snark = program::noir::run(&setup).await.unwrap();

  // assertions
  let zi_primary = recursive_snark.zi_primary();
  let zi_secondary = recursive_snark.zi_secondary();
  // TODO: change 0 to a correct value
  // assert_eq!(zi_primary[0], Scalar::from(0));

  // Verify
  let vk = setup.verifier_key().unwrap();
  // z0_primary is the same as initial_nivc_input
  // https://github.com/pluto/legacy-web-prover/blob/main/proofs/src/program/manifest.rs#L158-L170
  let z0_primary = vec![
    Scalar::from_raw([0x90388e84c482a56b, 0x9581e2342c863840, 0xe97232ce14e7a773, 0x0534bbfb66d6f67b]),
    Scalar::from(1),
    Scalar::from(1),
    Scalar::from_raw([0xce84acba3d8f890f, 0x0879ef3620d7870f, 0x274926ac72df2fa8, 0x1d783777ffc2c504]),
    Scalar::from_raw([0xf76a4c5afa465bb8, 0x882ae91f44335037, 0x44a11442d0b93142, 0x08e9414b8831fb98]),
    Scalar::from(6),
    Scalar::from(0),
    Scalar::from(1),
    Scalar::from(0),
    Scalar::from_raw([0x7546e43a7231dac3, 0x313ebce4de805951, 0x3d9003310dd1c909, 0x072c5a3f63e524e4]),
    Scalar::from(0),
  ];

  let compressed_proof = program::noir::compress_proof(&setup, &recursive_snark).unwrap();

  let (zn_primary, zn_secondary) = compressed_proof.proof.verify(&setup.params, &vk, &z0_primary, Z0_SECONDARY).unwrap();
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_plaintext_authentication_noir_split() {
  use web_prover_core::test_utils::TEST_MANIFEST;

  const CIRCUIT_SIZE: usize = 64;
  debug!("Creating `private_inputs`...");

  let request_inputs = one_block_empty_response_inputs(); // all padding 64 bytes
  let response_inputs = two_block_response_inputs(); // 76 bytes
  let manifest: OrigoManifest = serde_json::from_str(TEST_MANIFEST).unwrap();

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  // The same code from construct_program_data_and_proof<CIRCUIT_SIZE>

  let NIVCRom { circuit_data: rom_data, rom } =
    manifest.build_rom_noir::<CIRCUIT_SIZE>(&request_inputs, &response_inputs);
  debug!("circuit_data: {:?}", rom_data);
  debug!("rom: {:?}", rom);

  let noir_program_paths = vec!["../target/plaintext_authentication_64.json"];
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let (switchboard_inputs, initial_nivc_input) = manifest.build_switchboard_inputs::<CIRCUIT_SIZE>(
    &request_inputs,
    &response_inputs,
    &rom_data,
    &rom
  ).unwrap();
  let initial_circuit_index = 0;
  debug!("switchboard_inputs: {:?}", switchboard_inputs);
  debug!("initial_nivc_input: {:?}", initial_nivc_input);

  // Step 2: Create switchboard
  let switchboard = Switchboard::<ROM>::new(
    noir_programs,
    switchboard_inputs,
    initial_nivc_input.to_vec(),
    initial_circuit_index,
  );

  // Step 3: Initialize the setup
  debug!("Setup::new(switchboard)");
  let setup = Setup::new(switchboard).unwrap();

  debug!("program::noir:run");
  let recursive_snark = program::noir::run(&setup).await.unwrap();

  // assertions
  let zi_primary = recursive_snark.zi_primary();
  let zi_secondary = recursive_snark.zi_secondary();
  assert_eq!(zi_primary[0], Scalar::from(0));

  let compressed_proof = program::noir::compress_proof(&setup, &recursive_snark).unwrap();
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_get_noir() {
  use web_prover_core::test_utils::TEST_MANIFEST;

  const CIRCUIT_SIZE: usize = 512;
  debug!("Creating `private_inputs`...");

  let request_inputs = simple_request_inputs();
  let response_inputs = simple_response_inputs();
  let manifest: OrigoManifest = serde_json::from_str(TEST_MANIFEST).unwrap();

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  // The same code from construct_program_data_and_proof<CIRCUIT_SIZE>

  let NIVCRom { circuit_data: rom_data, rom } =
    manifest.build_rom_noir::<CIRCUIT_SIZE>(&request_inputs, &response_inputs);
  debug!("circuit_data: {:?}", rom_data);
  debug!("rom: {:?}", rom);

  let noir_program_paths = vec!["../target/plaintext_authentication.json"];
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let (switchboard_inputs, initial_nivc_input) = manifest.build_switchboard_inputs::<CIRCUIT_SIZE>(
    &request_inputs,
    &response_inputs,
    &rom_data,
    &rom
  ).unwrap();
  let initial_circuit_index = 0;
  debug!("switchboard_inputs: {:?}", switchboard_inputs);
  debug!("initial_nivc_input: {:?}", initial_nivc_input);

  // Step 2: Create switchboard
  let switchboard = Switchboard::<ROM>::new(
    noir_programs,
    switchboard_inputs,
    initial_nivc_input.to_vec(),
    initial_circuit_index,
  );

  // Step 3: Initialize the setup
  debug!("Setup::new(switchboard)");
  let setup = Setup::new(switchboard).unwrap();

  debug!("program::noir:run");
  let recursive_snark = program::noir::run(&setup).await.unwrap();

  // assertions
  let zi_primary = recursive_snark.zi_primary();
  let zi_secondary = recursive_snark.zi_secondary();
  // assert_eq!(zi_primary[0], Scalar::from(0));

  let compressed_proof = program::noir::compress_proof(&setup, &recursive_snark).unwrap();

  // Verify
  let path = std::path::PathBuf::from("../target/setup.bytes");
  let vsetup = Setup::load_file(&path).unwrap();
  let noir_programs = initialize_circuit_list(&noir_program_paths);
  let vswitchboard = Switchboard::<Configuration>::new(noir_programs);
  let vsetup = vsetup.into_ready(vswitchboard);

  let vk = vsetup.verifier_key().unwrap();
  info!("✅ Prepared verification key");
  // debug!("Verifier key details: {:?}", vk);

  let z0_primary = initial_nivc_input;
  debug!("z0_secondary: {:?}", Z0_SECONDARY); // 0
  let (zn_primary, zn_secondary) = compressed_proof.proof.verify(&vsetup.params, &vk, &z0_primary, Z0_SECONDARY).unwrap();
  // TODO: verify the proof
  // assert_eq!(zn_primary[0], Scalar::from(1));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_get() {
  use web_prover_core::test_utils::TEST_MANIFEST;

  const CIRCUIT_SIZE: usize = 256;
  let setup_data = UninitializedSetup {
    r1cs_types:              vec![
      R1CSType::Raw(PLAINTEXT_AUTHENTICATION_256B_R1CS.to_vec()),
      R1CSType::Raw(HTTP_VERIFICATION_256B_R1CS.to_vec()),
      R1CSType::Raw(JSON_EXTRACTION_256B_R1CS.to_vec()),
    ],
    witness_generator_types: vec![
      WitnessGeneratorType::Raw(PLAINTEXT_AUTHENTICATION_256B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(HTTP_VERIFICATION_256B_GRAPH.to_vec()),
      WitnessGeneratorType::Raw(JSON_EXTRACTION_256B_GRAPH.to_vec()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);

  debug!("Creating `private_inputs`...");

  let request_inputs = simple_request_inputs();
  let response_inputs = simple_response_inputs();
  let manifest: OrigoManifest = serde_json::from_str(TEST_MANIFEST).unwrap();

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  let NIVCRom { circuit_data: rom_data, rom } =
    manifest.build_rom::<CIRCUIT_SIZE>(&request_inputs, &response_inputs);
  let NivcCircuitInputs { initial_nivc_input, fold_inputs: _, private_inputs } =
    manifest.build_inputs::<CIRCUIT_SIZE>(&request_inputs, &response_inputs).unwrap();

  let val = "world".as_bytes();
  let value_digest = &polynomial_digest(val, ciphertext_digest, 0);
  dbg!(value_digest);

  let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let vk_digest_primary = pk.pk_primary.vk_digest;
  let vk_digest_secondary = pk.pk_secondary.vk_digest;
  let initialized_setup = initialize_setup_data(&setup_data).unwrap();
  let proof_params = ProofParams { rom: rom.clone() };
  let instance_params = InstanceParams::<NotExpanded> {
    nivc_input:     initial_nivc_input.to_vec(),
    private_inputs: (private_inputs, HashMap::new()),
  }
  .into_expanded(&proof_params)
  .unwrap();
  let setup_params = SetupParams::<Online> {
    public_params: Arc::new(public_params),
    vk_digest_primary,
    vk_digest_secondary,
    setup_data: Arc::new(initialized_setup),
    rom_data,
  };

  let recursive_snark = program::run(&setup_params, &proof_params, &instance_params).await.unwrap();

  let proof = program::compress_proof_no_setup(
    &recursive_snark,
    &setup_params.public_params,
    vk_digest_primary,
    vk_digest_secondary,
  )
  .unwrap();

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), *value_digest);

  let (z0_primary, _) =
    setup_params.extend_public_inputs(&proof_params.rom, &instance_params.nivc_input).unwrap();

  let z0_secondary = vec![F::<G2>::ZERO];
  let (zn_primary, _) =
    proof.proof.verify(&setup_params.public_params, &vk, &z0_primary, &z0_secondary).unwrap();

  assert_eq!(zn_primary[0], *value_digest);
  assert_eq!(zn_primary[5], F::<G1>::ZERO);
  assert_eq!(zn_primary[8], F::<G1>::ZERO);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_end_to_end_proofs_post() {
  let manifest = complex_manifest();
  let request_inputs = complex_request_inputs();
  let response_inputs = complex_response_inputs();

  const CIRCUIT_SIZE: usize = 512;

  let setup_data = UninitializedSetup {
    r1cs_types:              vec![
      R1CSType::Raw(load_artifact_bytes(format!("../{}", PLAINTEXT_AUTHENTICATION_512B_R1CS).as_str()).unwrap()),
      R1CSType::Raw(load_artifact_bytes(format!("../{}", HTTP_VERIFICATION_512B_R1CS).as_str()).unwrap()),
      R1CSType::Raw(load_artifact_bytes(format!("../{}", JSON_EXTRACTION_512B_R1CS).as_str()).unwrap()),
    ],
    witness_generator_types: // wasm_witness_generator_type_512b().to_vec(),
    vec![
      WitnessGeneratorType::Raw(load_artifact_bytes(format!("../{}", PLAINTEXT_AUTHENTICATION_512B_GRAPH).as_str()).unwrap()),
      WitnessGeneratorType::Raw(load_artifact_bytes(format!("../{}", HTTP_VERIFICATION_512B_GRAPH).as_str()).unwrap()),
      WitnessGeneratorType::Raw(load_artifact_bytes(format!("../{}", JSON_EXTRACTION_512B_GRAPH).as_str()).unwrap()),
    ],
    max_rom_length:          MAX_ROM_LENGTH,
  };
  debug!("Setting up `Memory`...");
  let public_params = program::setup(&setup_data);

  debug!("Creating ROM");

  let InitialNIVCInputs { ciphertext_digest, .. } = manifest
    .initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(
      &request_inputs.ciphertext,
      &response_inputs.ciphertext,
    )
    .unwrap();

  let NIVCRom { circuit_data, rom } =
    manifest.build_rom::<CIRCUIT_SIZE>(&request_inputs, &response_inputs);
  let NivcCircuitInputs { initial_nivc_input, fold_inputs: _, private_inputs } =
    manifest.build_inputs::<CIRCUIT_SIZE>(&request_inputs, &response_inputs).unwrap();

  debug!("rom: {:?}", rom);
  debug!("inputs: {:?}", private_inputs.len());

  let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
  let vk_digest_primary = pk.pk_primary.vk_digest;
  let vk_digest_secondary = pk.pk_secondary.vk_digest;
  let initialized_setup = initialize_setup_data(&setup_data).unwrap();
  let setup_params = SetupParams::<Online> {
    public_params: Arc::new(public_params),
    vk_digest_primary,
    vk_digest_secondary,
    setup_data: Arc::new(initialized_setup),
    rom_data: circuit_data.clone(),
  };
  let proof_params = ProofParams { rom: rom.clone() };
  let instance_params = InstanceParams::<NotExpanded> {
    nivc_input:     initial_nivc_input.to_vec(),
    private_inputs: (private_inputs, HashMap::new()),
  }
  .into_expanded(&proof_params)
  .unwrap();

  let recursive_snark = program::run(&setup_params, &proof_params, &instance_params).await.unwrap();

  let proof = program::compress_proof_no_setup(
    &recursive_snark,
    &setup_params.public_params,
    setup_params.vk_digest_primary,
    setup_params.vk_digest_secondary,
  )
  .unwrap();

  let target_value = "ord_67890".as_bytes();
  let value_digest = polynomial_digest(target_value, ciphertext_digest, 0);

  assert_eq!(*recursive_snark.zi_primary().first().unwrap(), value_digest);

  let (z0_primary, _) =
    setup_params.extend_public_inputs(&proof_params.rom, &initial_nivc_input.to_vec()).unwrap();

  let z0_secondary = vec![F::<G2>::ZERO];

  proof.proof.verify(&setup_params.public_params, &vk, &z0_primary, &z0_secondary).unwrap();
}
