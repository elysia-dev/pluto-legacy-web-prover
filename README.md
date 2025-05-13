# Noir Hackathon Participation

🧞‍♂️ **Genie** is a zk-TLS based on-ramp system that bridges Web2 payments (e.g. Binance) to on-chain assets.

- [`legacy-web-prover`](https://github.com/elysia-dev/pluto-legacy-web-prover): ZK-TLS proof generation via HTTPS traffic interception.
- [`noir-web-prover-circuits`](https://github.com/elysia-dev/noir-web-prover-circuits): Core ZK circuits implemented in Noir (ChaCha20, HTTP, JSON, etc).
- [`zk-vault`](https://github.com/elysia-dev/zk-vault): Smart contract logic of `enroll` and `claim` for on-chain USDT distribution.

### legacy-web-prover

The main logic of the legacy-web-prover is to run zk-tls logic using SuperNova.
However, the circuit used in the legacy code is made with a circom base.

### What we implemented

We implemented a noir-based zk-tls circuit at <https://github.com/elysia-dev/noir-web-prover-circuits>.

To run this code in the current codebase (legacy-web-prover), we needed to implement a new interface.
So we implemented a SuperNova interface that takes a noir file as input.

We also implemented zk-tls attestation for the Binance payment API, for which we created a manifest.

## Getting Started

### Run locally

Run notary server:

```sh
cargo run -p notary -- --config ./fixture/notary-config.toml
```

Prove & verify a test API response `{"hello":"world"}`:

```sh
cargo run -p client -- --config ./fixture/client.origo_noir_tcp_local.json
```

## Demo

[![Demo Video](https://img.youtube.com/vi/Tf8v8zD6Bb4/0.jpg)](https://youtu.be/Tf8v8zD6Bb4)

### How to run the demo

We haven't implemented generating proofs in the browser yet. The command line approach requires private data in environment variables. Follow these steps to reproduce the process shown in the demo:

1. In genie [vault](https://github.com/elysia-dev/zk-vault):
   1. Deploy the vault. Make sure to put the private_key that will be used as the contract owner in the env.

2. In legacy-web-prover (this repo):
   1. Put the generated vault address into `MINATO_VAULT_ADDRESS` in `.env`.
   2. Put the same private_key as used above into `PRIVATE_KEY` and `NOTARY_PRIVATE_KEY`.

3. In Binance:
   1. Get a Binance API key.
   2. Write the api_key to `target_headers.x-mbx-apikey` in `fixture/client.origo_tcp_local_binance.json`.
   3. Write the secret to `BINANCE_SECRET` in your environment variables.

4. In legacy-web-prover:
   Run the client script, replacing the receiver-binance-id with the ID of the Binance account that issued the API:

    ```sh
    cargo run -p demo --bin demo -- --config ./fixture/client.origo_tcp_local_binance.json \
    --log-level=INFO --from-binance-id 93260646 --receiver-binance-id 71035696 --amount 1 --currency USDT
    ```
