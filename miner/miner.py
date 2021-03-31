from tg import expose, TGController
import ecdsa

from core.core_engine import BlockChain, FullTransaction
import core.core_engine as core_engine
from core.wallet import Wallet, PublicWallet
from core.utils import strToBytes

class RootController(TGController):
    def __init__(self, blockChainFile=None, minerId=None):
        super().__init__()
        # local blockchain
        self.blockChain = None
        # miner identify (private), used to sign blocks
        self.miner = None
        if blockChainFile is None:
            self.blockChain = BlockChain()
        else:
            with open(blockChainFile, "r") as blockChainStream:
                self.blockChain = BlockChain.jsonImport(blockChainStream.read())
                chainCheck = self.blockChain.verifyChain()
                assert chainCheck, "loaded blockchain could not be verified"
        if minerId is None:
            self.miner = Wallet.generateNewWallet()
        else:
            with open(minerId, "r") as minerIdStream:
                self.miner = Wallet.jsonImport(minerIdStream.read())
        self.publicWallet = {}

    def getPublicWallet(self, publicId):
        if not publicId in self.publicWallet:
            self.publicWallet[publicId] = PublicWallet(strToBytes(publicId))
        return self.publicWallet[publicId]

    def addTransaction(self, newTransaction):
        check = self.blockChain.addTransaction(newTransaction)
        if not check:
            return False
        # temporary: closing a block after each transaction
        self.closeBlock()
        return True

    def closeBlock(self):
        lastBlock = self.blockChain.lastOpenBlock
        self.blockChain.closeBlock(self.miner.id,
                                   lastBlock.signBlock(self.miner),
                                   lastBlock.blockChallenge.solve())

    @expose(content_type="text/plain")
    def index(self):
        return 'AriCoin miner (for more info https://github.com/nibrunie/AriCoin)'

    @expose(content_type="text/json")
    def blockchain(self):
        return self.blockChain.jsonExport()

    @expose(content_type="text/plain")
    def tmd(self):
        text = ""
        for block in self.blockChain.blockList:
            challenge = block.challengeResponse
            desc = challenge.challenge.staticDict
            text += (f"|{desc['funcTag']}_rnd{desc['roundedPrecision']}({challenge.response}) - {challenge.responseImage}| <= {desc['bound']}\n")
        return text

    @expose(content_type="text/json")
    def transfer_coin(self, sender=None,
                      receiver=None,
                      amount=None,
                      senderSignature=None,
                      receiverSignature=None,
                      nonce=None):
        transaction = FullTransaction.dictImport({
            "type": "FullTransaction",
            "receiverSignature": receiverSignature,
            "senderSignature": senderSignature,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "nonce": nonce
        })
        # checking transaction
        senderWallet = self.getPublicWallet(sender)
        receiverWallet = self.getPublicWallet(receiver)
        try:
            check = transaction.verify(senderWallet, receiverWallet)
        except ecdsa.keys.BadSignatureError:
            return f"transaction signature could not be verified: {transaction.jsonExport()}"
        else:
            try:
                check = self.addTransaction(transaction)
            except core_engine.DuplicateTransaction:
                return "invalid transaction: duplicate"
            except core_engine.InsufficientResource:
                return "invalid transaction: not enough resources"
            except core_engine.InvalidTransactionAmount:
                return "invalid transaction"
            if check:
                return "transaction verified"
            else:
                return "transaction could not be verified"
