import argparse
import requests

from core.wallet import Wallet, PublicWallet
from core.core_engine import (
    UnsignedTransaction, HalfTransaction, FullTransaction,
    BlockChain)


def generate_wallet(args):
    """ generate a new random wallet """
    newWallet = Wallet.generateNewWallet()
    walletJson = newWallet.jsonExport()
    print(walletJson)
    if args.output:
        with open(args.output, "w") as outStream:
            outStream.write(walletJson)

def generate_empty_blockchain(args):
    newBlockChain = BlockChain()
    blockChainExport = newBlockChain.jsonExport()
    print(blockChainExport)
    with open(args.output, "w") as outStream:
        outStream.write(blockChainExport)

def transfer_coin(args):
    """ initiate a two-sided coin transfer """
    with open(args.wallet, "r") as walletStream:
        wallet = Wallet.jsonImport(walletStream.read())
        with open(args.receiver, "r") as receiverIdStream:
            receiver = PublicWallet.jsonImport(receiverIdStream.read())
            newTransaction = UnsignedTransaction(wallet.id, receiver.id, args.amount)
            halfNewTransaction = newTransaction.sign(wallet)
            jsonTransaction = halfNewTransaction.jsonExport()
            print(jsonTransaction)
            with open(args.output, "w") as transStream:
                transStream.write(jsonTransaction)

def generate_public_id(args):
    """ generate a public-id file from a private wallet file """
    with open(args.wallet, "r") as walletStream:
        wallet = Wallet.jsonImport(walletStream.read())
        publicWallet = wallet.extractPublicWallet()
        jsonPublicWallet = publicWallet.jsonExport()
        print(jsonPublicWallet)
        with open(args.output, "w") as walletStream:
            walletStream.write(jsonPublicWallet)


def receive_coin(args):
    """ finalize a two-sided coin transfer """
    with open(args.transaction, "r") as transactionStream:
        transaction = HalfTransaction.jsonImport(transactionStream.read())
        with open(args.wallet, "r") as walletStream:
            wallet = Wallet.jsonImport(walletStream.read())
            assert transaction.receiver == wallet.id, "signature must be done by intended recipient"
            fullTransaction = transaction.sign(wallet)
            jsonFullTransaction = fullTransaction.jsonExport()
            print(jsonFullTransaction)
            with open(args.output, "w") as fullTransactionStream:
                fullTransactionStream.write(jsonFullTransaction)

def submit_transaction(args):
    """ submit a new transaction to a miner for validation """
    with open(args.transaction, "r") as transactionStream:
        transaction = FullTransaction.jsonImport(transactionStream.read())
        answer = requests.get(f"{args.miner_url}/transfer_coin", params=transaction.dictExport()) 
        print(f"server responded with:\n{answer.text}")
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AriCoin command line interface')
    subparsers = parser.add_subparsers(help='sub-command help')

    # create the parser for the "a" command
    parser_generate_wallet = subparsers.add_parser('generate_wallet', help='generating a new wallet')
    parser_generate_wallet.add_argument('--output', action='store', default=None,
                                        help='output file')
    parser_generate_wallet.set_defaults(func=generate_wallet)

    # transfering coin (from sender)
    parser_transfer_coin = subparsers.add_parser('transfer_coin', help='sign a transaction')
    parser_transfer_coin.add_argument('receiver', action='store',
                                  help='transaction receiver')
    parser_transfer_coin.add_argument('amount', action='store',
                                  help='amount of transaction')
    parser_transfer_coin.add_argument('--wallet', action='store', default=None,
                                  help='wallet file')
    parser_transfer_coin.add_argument('--output', action='store', default=None,
                                  help='output file')
    parser_transfer_coin.set_defaults(func=transfer_coin)

    # generate public-id from private-id target
    parser_generate_public_id = subparsers.add_parser('generate_public_id', help='generating the public version of a private wallet')
    parser_generate_public_id.add_argument('wallet', action='store', help='private wallet file')
    parser_generate_public_id.add_argument('output', action='store', default=None,
                                        help='output file')
    parser_generate_public_id.set_defaults(func=generate_public_id)

    # receive coin target
    parser_receive_coin = subparsers.add_parser('receive_coin', help='sign a transaction')
    parser_receive_coin.add_argument('transaction', action='store',
                                     help='half transaction file (signed by sender)')
    parser_receive_coin.add_argument('--wallet', action='store', default=None,
                                     help='wallet file')
    parser_receive_coin.add_argument('--output', action='store', default=None,
                                     help='output file for fully signed transaction')
    parser_receive_coin.set_defaults(func=receive_coin)

    # initialize an empty blockchain
    parser_init_blockchain = subparsers.add_parser('init_blockchain', help='initialize an empty blockchain')
    parser_init_blockchain.add_argument("output", action='store', help='blockchain output file')
    parser_init_blockchain.set_defaults(func=generate_empty_blockchain)

    # submit a transaction for validation
    parser_submit_transaction = subparsers.add_parser('submit_transaction', help='submit a transaction for validation')
    parser_submit_transaction.add_argument("transaction", action='store', help='transaction description file')
    parser_submit_transaction.add_argument("miner_url", action='store', help='miner url')
    parser_submit_transaction.set_defaults(func=submit_transaction)

    args = parser.parse_args()
    args.func(args)
    
