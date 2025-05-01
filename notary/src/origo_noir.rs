use std::{
  sync::{Arc, Mutex},
};

use axum::{
  extract::{self, Query, State},
  Json,
};
use client::origo::{SignBody, VerifyBody};
use proofs::{
  circuits::{CIRCUIT_SIZE_512, MAX_STACK_HEIGHT},
  errors::ProofError,
  program::manifest::{compute_ciphertext_digest, InitialNIVCInputs},
  proof::FoldingProof,
  F, G1, G2,
};
use tracing::{debug, error, info};
use web_proof_circuits_witness_generator::polynomial_digest;
use web_prover_core::proof::SignedVerificationReply;

use crate::{
  errors::{NotaryServerError, ProxyError},
  origo_verifier,
  verifier::VerifyOutput,
  SharedState,
  origo::find_ciphertext_permutation,
};

pub async fn verify(
  State(state): State<Arc<SharedState>>,
  extract::Json(payload): extract::Json<VerifyBody>,
) -> Result<Json<SignedVerificationReply>, NotaryServerError> {
  let proof = FoldingProof {
    proof:           payload.origo_proof.proof.proof.clone(),
    verifier_digest: payload.origo_proof.proof.verifier_digest.clone(),
  }
  .deserialize()?;

  debug!("verifier_digest: {:?}", proof.verifier_digest.clone());

  // Form verifier inputs
  let verifier_inputs =
    state.verifier_sessions.lock().unwrap().get(&payload.session_id).cloned().unwrap();

  // TODO: might be incorrect to check ciphertext in this manner, but for now, we play along
  // Find the correct ciphertext from permutation of the ciphertexts
  let expected_ciphertext_digest =
    F::<G1>::from_bytes(&payload.origo_proof.ciphertext_digest).unwrap();
  let response_messages = find_ciphertext_permutation::<CIRCUIT_SIZE_512>(
    expected_ciphertext_digest,
    verifier_inputs.request_messages.clone(),
    verifier_inputs.response_messages.clone(),
  );

  // DEBUG: Use this digest to pin the proving behavior. You must also override
  // `client/src/tls.rs#decrypt_tls_ciphertext`
  //
  // let ciphertext_digest = F::<G1>::from_bytes(&hex::decode(
  //   "66ab857c95c11767913c36e9341dbe4d46915616a67a5f47379e06848411b32b"
  // ).unwrap().try_into().unwrap()).unwrap();

  debug!("circuits {:?}", payload.origo_proof.rom.circuit_data);
  debug!("rom {:?}", payload.origo_proof.rom.rom);
  let verifier = &state.noir_verifier;

  let InitialNIVCInputs { initial_nivc_input, ciphertext_digest, .. } =
    payload.manifest.initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE_512>(
      &verifier_inputs.request_messages,
      &response_messages,
    )?;
  assert_eq!(ciphertext_digest, expected_ciphertext_digest);

  // let (z0_primary, _) = verifier.setup_params.extend_public_inputs(
  //   &origo_verifier::flatten_rom(payload.origo_proof.rom.rom),
  //   &initial_nivc_input.to_vec(),
  // )?;
  let z0_secondary = vec![F::<G2>::from(0)];

  let verify_output = match proof.proof.verify(
    &verifier.params,
    &verifier.verifier_key().unwrap(),
    &initial_nivc_input,
    &z0_secondary,
  ) {
    Ok((output, _)) => {
      println!("output: {:?}", output);
      // TODO: We should also check that the full extended ROM was correct? Although maybe that's
      // implicit in this.
      if output[5] != F::<G1>::from(0) {
        debug!("HTTP header match: {:?}", output[5]);
        return Err(ProofError::VerifyFailed(String::from("HTTP header match failed")).into());
      } else if output[8] != F::<G1>::from(0) {
        debug!("JSON final state: {:?}", output[8]);
        return Err(ProofError::VerifyFailed(String::from("JSON final state invalid")).into());
      } else if output[10] != ciphertext_digest {
        debug!("expected ciphertext_digest: {:?}", ciphertext_digest);
        debug!("calculated ciphertext digest {:?}", output[10]);
        return Err(
          ProofError::VerifyFailed(String::from("invalid calculated ciphertext digest")).into(),
        );
      } else if output[0]
        != polynomial_digest(
          payload.origo_proof.value.clone().unwrap().as_bytes(),
          ciphertext_digest,
          0,
        )
      {
        debug!("output[0]: {:?}", output[0]);
        debug!("value: {:?}", payload.origo_proof.value.clone().unwrap());
        debug!(
          "value_polynomial_digest: {:?}",
          polynomial_digest(
            payload.origo_proof.value.clone().unwrap().as_bytes(),
            ciphertext_digest,
            0,
          )
        );
        return Err(ProofError::VerifyFailed(String::from("inccorect final circuit value")).into());
      } else {
        // TODO: add the manifest digest?
        debug!("output from verifier: {output:?}");
        // This unwrap should be safe for now as the value will always be present
        VerifyOutput {
          value:    payload.origo_proof.value.unwrap(),
          manifest: payload.manifest.into(),
        }
      }
    },
    Err(e) => {
      error!("Error verifying proof: {:?}", e);
      return Err(ProofError::SuperNova(e).into());
    },
  };

  crate::verifier::sign_verification(verify_output, State(state)).map(Json)
}
