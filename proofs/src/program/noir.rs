use edge_frontend::error::FrontendError;
use edge_frontend::noir::NoirProgram;
use edge_frontend::program::{Memory, run as run_noir, compress as compress_noir};
use edge_frontend::setup::{Ready, Setup};
use edge_frontend::CompressedSNARK;
use super::*;

pub async fn run<M: Memory>(
  psetup: &Setup<Ready<M>>,
) -> Result<RecursiveSNARK<E1>, FrontendError> {
  let recursive_snark = run_noir(psetup)?;
  Ok(recursive_snark)
}


/// # Returns
/// verifier_digest is pk_primary.vk_digest
/// https://github.com/ModoriLabs/pluto-legacy-web-prover/blob/feat/use-edge/proofs/src/program/mod.rs#L322
pub fn compress_proof<M: Memory>(
  setup: &Setup<Ready<M>>,
  recursive_snark: &RecursiveSNARK<E1>,
) -> Result<CompressedProof, FrontendError> {
  let proof = FoldingProof {
    proof:           compress_noir(setup, recursive_snark)?,
    verifier_digest: setup.vk_digest_primary,
  };
  Ok(proof)
}

pub fn compress_proof_no_setup<M: Memory>(
  recursive_snark: &RecursiveSNARK<E1>,
  public_params: &PublicParams<E1>,
  vk_digest_primary: <E1 as Engine>::Scalar,
  vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
) -> Result<CompressedProof, FrontendError> {
  let pk = CompressedSNARK::initialize_pk(
    public_params,
    vk_digest_primary,
    vk_digest_secondary,
  )?;
  debug!(
    "initialized pk pk_primary.digest={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest, pk.pk_secondary.vk_digest
  );

  debug!("`CompressedSNARK::prove STARTING PROVING!");
  let proof = FoldingProof {
    proof:           CompressedSNARK::prove(public_params, &pk, recursive_snark)?,
    verifier_digest: pk.pk_primary.vk_digest,
  };
  debug!("`CompressedSNARK::prove completed!");

  Ok(proof)
}

pub fn initialize_circuit_list(paths: &Vec<&str>) -> Vec<NoirProgram> {
  paths
    .iter()
    .enumerate()
    .map(|(i, path)| {
      let mut program = read_noir_program(path).unwrap();
      program.index = i;
      program
    })
    .collect::<Vec<_>>()
}

pub fn read_noir_program(path: &str) -> Result<NoirProgram, ProofError> {
  let path = std::path::PathBuf::from(path);

  // Get the current working directory
  let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
  let absolute_path = current_dir.join(&path);

  match std::fs::read(&path) {
    Ok(bytecode) => Ok(NoirProgram::new(&bytecode)),
    Err(e) => {
      panic!(
        "Failed to read Noir program file.\nRelative path: '{}'\nAbsolute path: '{}'\nError: {}",
        path.display(),
        absolute_path.display(),
        e
      );
    },
  }
}
