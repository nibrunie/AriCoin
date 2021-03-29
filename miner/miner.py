from tg import expose, TGController
import ecdsa

from core.core_engine import BlockChain

class RootController(TGController):
    def __init__(self, blockChainFile=None):
        super().__init__()
        if blockChainFile is None:
            self.blockChain = BlockChain()
        else:
            with open(blockChainFile, "r") as blockChainStream:
                self.blockChain = BlockChain.jsonImport(blockChainStream.read())
                chainCheck = self.blockChain.verifyChain()
                assert chainCheck, "loaded blockchain could not be verified"
        self.publicWallet = {}
        self.lastBlock 
    firstBlock = OpenBlock(0, aricCoinChain.rootDigest)
    firstBlock.addTransaction(fullNewTransaction)

    def getPublicWallet(self, publicId):
        if not publicId in self.publicWallet:
            self.publicWallet[publicId] = PublicWallet(publicId)
        return self.publicWallet[publicId]

    @expose(content_type="text/plain")
    def index(self):
        return 'AriCoin miner (for more info https://github.com/nibrunie/AriCoin)'

    @expose(content_type="text/json")
    def blockchain(self):
        return self.blockChain.jsonExport()

    @expose(content_type="text/json")
    def transfer_coin(self, sender=None,
                      receiver=None,
                      amount=None,
                      senderSignature=None,
                      receiverSignature=None):
        transaction = FullTransaction.dictImport({
            "type": "FullTransaction",
            "receiverSignature": receiverSignature,
            "senderSignature": senderSignature,
            "sender": sender,
            "receiver": receiver,
            "amount": amount
        })
        # checking transaction
        senderWallet = self.getPublicWallet(sender)
        receiverWallet = self.getPublicWallet(receiver)
        try:
            check = transaction.verify(sender, receiver)
        except ecdsa.keys.BadSignatureError:
            return f"transaction signature could not be verified: {transaction.jsonExport()}"
        else:
            return "transaction verified"
