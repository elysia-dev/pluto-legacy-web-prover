use edge_frontend::error::FrontendError;
use edge_frontend::noir::NoirProgram;
use edge_frontend::program::{Memory, run as run_noir, compress as compress_noir};
use edge_frontend::setup::{Ready, Setup};
use edge_frontend::CompressedSNARK;
use super::*;

// FIXME: psetup input must be online
pub async fn run<M: Memory>(
  psetup: &Setup<Ready<M>>,
) -> Result<RecursiveSNARK<E1>, FrontendError> {
  let recursive_snark = run_noir(psetup)?;
  Ok(recursive_snark)
}

pub fn compress<M: Memory>(
  setup: &Setup<Ready<M>>,
  recursive_snark: &RecursiveSNARK<E1>,
) -> Result<CompressedSNARK, FrontendError> {
  let compressed_snark = compress_noir(setup, recursive_snark)?;
  Ok(compressed_snark)
}

// paths: "target/collatz_even.json"
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
