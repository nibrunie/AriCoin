# AriCoin
Crypto currency with useful proof of work: Table Maker Dilemna, listing hardest to round cases


# Introduction
AriCoin is a simple crypto-currency. Currency exchange are registered into a blockchain, in a similar manner to bitcoin.
Most crypto-currencies are based on proof-of-work: solving a hard algorithm challenge is required to validate a block of transaction, thus integrating them into the growing chain of transactio blocks.
The reward for validating the transaction, and solving the hard challenge, is given as a currency reward to the crypto currency minors.
This work is energy consuming and apart from validating transactions, the challenge responses are useless.

AriCoin has been designed to provide both a blockchain to log transactions and a useful proof of work: namely searching hardest to round cases.
Contrary to must crypto-currencies the proof-of-work challenges.

# The challenge: TMD and hardest to round cases

# How to use ariCoin

AriCoin is delivered with an utility called `aricoin` which performs most of the basis actions.

## Creating a wallet

To create a wallet (private):
```
python3 aricoin.py generate_wallet --output <output file>
```

You can extract a public id from a private wallet:
```
python3 aricoin.py generate_public_id <private wallet file> <public id output file>
```

## Sending and Receiving coins

AriCoin uses 2-sided transactions: first the sender creates an half transaction as follows:

```
python aricoin.py transfer_coin <receiver public id file> <amoun> --wallet <sender private wallet file> --output <half transaction output file>
```

then the receiver must sign this half transaction before it can be submitted to a validator

```
python3 aricoin.py receive_coin --wallet <receiver private wallet> --output <output signed transaction file> <input half transaction file>
```

## Submitting a transaction to a validator

A transaction must be submitted to a validator to be recorded in the blockchain.

```
python3 aricoin.py submit_transaction <transaction file> <validtor URL>
```

## Initializing a blockchain

The `aricoin` utility can be used to initialize an empty blockchain.

```
python3 aricoin.py init_blockchain <blockchain file>
```

# Miner/Validator

This repo also contains the source code for an AriCoin validator/miner.

## Launching a validator

```
python3 launch_miner.py [--port <server port>] [--load-blockchain <saved blockhain>] [--miner-id <miner private wallet>]
```

By default the server will be accessible at `http://localhost:8080`, the blockchain can be inspected at `http://localhost:8080/blockchain` and a list a solved TMD challenges extracted from the blockchain is available at `http://localhost:8080/tmd`

# History

- Proof of concept released on April 1st, 2021

# References
- Jean-Michel Muller's page on the TMD: http://perso.ens-lyon.fr/jean-michel.muller/Intro-to-TMD.htm
- Slides by Vincent Lefevre: http://www.vinc17.net/research/slides/tamadi2010-10.pdf

