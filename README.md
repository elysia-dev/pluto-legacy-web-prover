# Noir Hackathon Participation

🧞‍♂️ **Genie** is a zk-TLS based on-ramp system that bridges Web2 payments (e.g. Binance) to on-chain assets.

- [`legacy-web-prover`](https://github.com/elysia-dev/pluto-legacy-web-prover): ZK-TLS proof generation via HTTPS traffic interception.
- [`‍️noir-web-prover-circuits`](https://github.com/elysia-dev/noir-web-prover-circuits): Core ZK circuits implemented in Noir (ChaCha20, HTTP, JSON, etc).
- [`‍️zk-vault`](https://github.com/elysia-dev/zk-vault): Smart contract logic of `enroll` and `claim` for on-chain USDT distribution.

### legacy-web-prover

The main logic of the legacy-web-prover is to run zk-tls logic using SuperNova.
However, the circuit used in the legacy code is made with circom base.

### What we implemented

We implemented a noir-based zk-tls circuit at <https://github.com/elysia-dev/noir-web-prover-circuits>.

To run this code in the current codebase(legacy-web-prover), we need to implement new interface.
So We implemented a SuperNova interface that takes a noir file as input.

We also do zk-tls attestation for the binance payment api, for which we implemented a manifest for that api.

## Getting Started

### Run locally

Run notary server

```sh
cargo run -p notary -- --config ./fixture/notary-config.toml
```

Prove & verify a test api response `{"hello":"world"}`

```sh
cargo run -p client -- --config ./fixture/client.origo_noir_tcp_local.json
```

### Run the demo

The actual execution of this package is a bit complicated.
We haven't implemented generating proofs in the browser yet, so calling it from the command line to generate/prove the proofs contains a lot of private data in the env, so We couldn't package it all at once and upload it.
So you need to follow the steps below to reproduce the process shown in the demo.

1. In genie vault(<https://github.com/elysia-dev/zk-vault>)
   Deploy the vault. Make sure to put the private_key that will be used as the contract owner in the env.

2. In legacy-web-prover
   Put the generated vault address into MINATO_VAULT_ADDRESS in the env.
   Put the same private_key as used above into PRIVATE_KEY, NOTARY_PRIVATE_KEY.

3. In Binance
   Get a Binance API.
   Write the api_key to target_headers.x-mbx-apikey in fixture/client.origo_tcp_local_binance.json. Write the secret to BINANCE_SECRET.

4. In legacy-web-prover
   In the script that calls client Replace receiver-binance-id with the ID of the BINANCE account that issued the API.

  ```sh
  cargo run -p client -- --config ./fixture/client.origo_tcp_local_binance.json \
  --log-level=INFO --from-binance-id 93260646 --receiver-binance-id 71035696 \
  --currency USDT --amount 1
  ```
