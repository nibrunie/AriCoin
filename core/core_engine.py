from ecdsa import SigningKey, NIST384p, VerifyingKey
import ecdsa
import bigfloat
import random
import json
import hashlib
import collections

class PublicWallet:
    """ Public part of a wallet with only the public key to verify transaction """
    def __init__(self, vk_string):
        self.vk = VerifyingKey.from_string(vk_string, curve=NIST384p)

    def verify(self, signature, msg):
        return self.vk.verify(signature, msg)

    def export(self):
        return self.vk.to_string()

    def jsonExport(self):
        return json.dumps({
            "type": "publicWallet",
            "vk_string": self.export()
        })

    @property
    def id(self):
        return self.export()

    @staticmethod
    def jsonImport(pw_str):
        pw_dict = json.loads(pw_str)
        assert pw_dict["type"] == "publicWallet"
        return PublicWallet(pw_dict["vk_string"])

class Wallet(PublicWallet):
    """ Coin wallet with a pair private,public key to sign (and verify)
        transaction """
    def __init__(self, sk_string):
        sk = SigningKey.from_string(sk_string, curve=NIST384p)
        PublicWallet.__init__(self, sk.verifying_key.to_string())
        self.sk = sk

    def sign(self, msg):
        signature = self.sk.sign(msg)
        return signature

    #def verify(self, signature, msg):
    #    vk = self.sk.verifying_key
    #    return vk.verify(signature, msg)

    def privateExport(self):
        return self.sk.to_string()

    @property
    def privateId(self):
        return self.privateExport()

    def extractPublicWallet(self):
        return PublicWallet(self.sk.verifying_key.to_string())

    @staticmethod
    def generateNewWallet():
        sk = SigningKey.generate(curve=NIST384p)
        sk_string = sk.to_string()
        return Wallet(sk_string)


class UnsignedTransaction:
    """ Transaction of <amount> coin between sender and receiver signed
        by neither sender nor receiver """
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

    def dictExport(self):
        return {
            "type": "UnsignedTransaction",
            "sender": bytesToStr(self.sender),
            "receiver": bytesToStr(self.receiver),
            "amount": self.amount
        }

    def jsonExport(self):
        return json.dumps(self.dictExport())
    @staticmethod
    def jsonImport(ut_str):
        utDict = json.loads(ut_str)
        return UnsignedTransaction.dictImport(utDict)

    @staticmethod
    def dictImport(utDict):
        assert utDict["type"] in ["UnsignedTransaction", "HalfTransaction", "FullTransaction"]
        return UnsignedTransaction(strToBytes(utDict["sender"]),
                                   strToBytes(utDict["receiver"]),
                                   utDict["amount"])

    def sign(self, privateWallet):
        transcript = bytes(self.jsonExport(), encoding='utf8')
        signature = privateWallet.sign(transcript)
        return HalfTransaction(self, signature)

class HalfTransaction:
    """ Transaction of <amount> coin between sender and receiver signed
        by sender only """
    def __init__(self, unsignedTransaction, senderSignature):
        self.unsignedTransaction = unsignedTransaction
        self.senderSignature = senderSignature

    def dictExport(self):
        dictTranscript = self.unsignedTransaction.dictExport()
        dictTranscript.update({
            "type": "HalfTransaction",
            "senderSignature": bytesToStr(self.senderSignature),
        })
        return dictTranscript
    def jsonExport(self):
        return json.dumps(self.dictExport())
    def sign(self, privateWallet):
        transcript = bytes(self.jsonExport(), encoding='utf8')
        signature = privateWallet.sign(transcript)
        return FullTransaction(self, signature)

    def verify(self, publicSenderWallet):
        """ verify the validity of the sender signature """
        transcript = bytes(self.unsignedTransaction.jsonExport(), encoding='utf8')
        return publicSenderWallet.verify(self.senderSignature, transcript)

    @property
    def sender(self):
        return self.unsignedTransaction.sender
    @property
    def receiver(self):
        return self.unsignedTransaction.receiver
    @property
    def amount(self):
        return self.unsignedTransaction.amount

    @staticmethod
    def jsonImport(ht_str):
        htDict = json.loads(ht_str)
        return HalfTransaction.dictImport(htDict)

    @staticmethod
    def dictImport(htDict):
        assert htDict["type"] in ["HalfTransaction", "FullTransaction"]
        return HalfTransaction(UnsignedTransaction.dictImport(htDict),
                               strToBytes(htDict["senderSignature"]))


class FullTransaction:
    """ Transaction of <amount> coin between sender and receiver signed
        by both sender and receiver """
    def __init__(self, halfTransaction, receiverSignature):
        self.halfTransaction = halfTransaction
        self.receiverSignature = receiverSignature

    @property
    def sender(self):
        return self.halfTransaction.sender
    @property
    def receiver(self):
        return self.halfTransaction.receiver
    @property
    def amount(self):
        return self.halfTransaction.amount

    def dictExport(self):
        dictTranscript = self.halfTransaction.dictExport()
        dictTranscript.update({
            "type": "FullTransaction",
            "receiverSignature": bytesToStr(self.receiverSignature),
        })
        return dictTranscript
    def jsonExport(self):
        return json.dumps(self.dictExport())

    def verify(self, publicSenderWallet, publicReceiverWallet):
        """ verify the validity of the sender signature """
        transcript = bytes(self.halfTransaction.jsonExport(), encoding='utf8')
        return publicReceiverWallet.verify(self.receiverSignature, transcript) and self.halfTransaction.verify(publicSenderWallet)

    @staticmethod
    def jsonImport(ft_str):
        ftDict = json.loads(ft_str)
        return FullTransaction.dictImport(ftDict)

    @staticmethod
    def dictImport(ftDict):
        assert ftDict["type"] == "FullTransaction"
        return FullTransaction(HalfTransaction.dictImport(ftDict),
                               strToBytes(ftDict["receiverSignature"]))

class OpenBlock:
    """ on-going block gathering multiple transactions without having being
        closed nor signed yet """
    def __init__(self, blockId, previousBlockSignature, transactionList=None):
        self.transactionList = [] if transactionList is None else transactionList
        self.blockId = blockId
        self.previousBlockSignature = previousBlockSignature

    def addTransaction(self, newTransaction):
        self.transactionList.append(newTransaction)

    def dictExport(self):
        return {
            "type": "OpenBlock",
            "blockId": self.blockId,
            "previousBlockSignature": self.previousBlockSignature,
            "transactionList": [t.dictExport() for t in self.transactionList],
        }
    def jsonExport(self):
        return json.dumps(self.dictExport())

    @property
    def blockDigest(self):
        digest = hashlib.sha256()
        digest.update(bytes(self.jsonExport(), encoding='utf8'))
        return digest.hexdigest()

    @property
    def blockChallenge(self):
        """ build a Challenge specific to this block """
        hexDigest = int(self.blockDigest, base=16)
        startInput = bigfloat.BigFloat(hexDigest % 2**53 -1) * 2.0**-50
        return Challenge(startInput=startInput)

    def signBlock(self, validatorPrivateWallet):
        return validatorPrivateWallet.sign(bytes(self.blockDigest, encoding='utf8'))

    def closeBlock(self, validatorSignature, blockSignature, challengeReponse):
        return ClosedBlock(self, validatorSignature, blockSignature, challengeReponse)

    @staticmethod
    def dictImport(obDict):
        assert obDict["type"] in ["ClosedBlock", "OpenBlock"]
        return OpenBlock(obDict["blockId"],
                         obDict["previousBlockSignature"],
                         [FullTransaction.dictImport(t) for t in obDict["transactionList"]])

def bytesToStr(rawBytes):
    return rawBytes.hex()
def strToBytes(raw_str):
    return bytes.fromhex(raw_str)

class ClosedBlock:
    def __init__(self, block, validatorSignature, blockSignature, challengeResponse):
        self.block = block
        self.validatorSignature = validatorSignature
        self.blockSignature = blockSignature
        self.challengeResponse = challengeResponse

    def dictExport(self):
        transcript = self.block.dictExport()
        transcript.update({
            "type": "ClosedBlock",
            "validatorSignature": bytesToStr(self.validatorSignature),
            "blockSignature": bytesToStr(self.blockSignature),
            "challengeResponse": str(self.challengeResponse),
        })
        return transcript
    def jsonExport(self):
        return json.dumps(self.dictExport())

    @staticmethod
    def dictImport(cbDict):
        assert cbDict["type"] == "ClosedBlock"
        return ClosedBlock(OpenBlock.dictImport(cbDict),
                           strToBytes(cbDict["validatorSignature"]),
                           strToBytes(cbDict["blockSignature"]),
                           bigfloat.BigFloat(cbDict["challengeResponse"], context=bigfloat.precision(53)))
    @staticmethod
    def jsonImport(cb_str):
        return ClosedBlock.dictImport(json.loads(cb_str))

    def verify(self, walletMap, validatorSignature):
        validatorPublicWallet = PublicWallet(self.validatorSignature)
        byteDigest = bytes(self.block.blockDigest, encoding='utf8')
        validSignature = validatorPublicWallet.verify(self.blockSignature, byteDigest)
        validResponse = self.block.blockChallenge.checkResponse(self.challengeResponse)
        # checking transaction validity
        for transaction in self.block.transactionList:
            # verifying sender solvability
            if walletMap[transaction.sender] < transaction.amount:
                print(f"[ERROR] {transaction.sender} has no sufficient resources")
                return False
            walletMap[transaction.sender] -= transaction.amount
            walletMap[transaction.receiver] += transaction.amount
        walletMap[validatorSignature] += BlockChain.VALIDATOR_REWARD
        print(f"validSignature={validSignature}, validResponse={validResponse}")
        return validSignature and validResponse

class BlockChain:
    VALIDATOR_REWARD = 1
    def __init__(self, blockList=None):
        self.rootDigest = 0x1337
        self.blockList = [] if blockList is None else blockList

    def addBlock(self, newBlock):
        self.blockList.append(newBlock)

    def verifyChain(self):
        previousSignature = self.rootDigest
        walletMap = collections.defaultdict(lambda: 0)
        for index, closedBlock in enumerate(self.blockList):
            if not closedBlock.block.previousBlockSignature == previousSignature:
                print(f"[ERROR] block {index} previousSignature mismatch")
                return False
            if not closedBlock.verify(walletMap, closedBlock.validatorSignature):
                print(f"[ERROR] block {index} could not be verified")
                return False
        return True

    def dictExport(self):
        return {
            "type": "BlockChain",
            "rootDigest": self.rootDigest,
            "blockList": [b.dictExport() for b in self.blockList]
        }
    def jsonExport(self):
        return json.dumps(self.dictExport())

    @staticmethod
    def jsonImport(bc_str):
        bcDict = json.loads(bc_str)
        assert bcDict["type"] == "BlockChain"
        # TODO factorize rootDigest constant
        assert bcDict["rootDigest"] == 0x1337
        return BlockChain(blockList=[ClosedBlock.dictImport(cb) for cb in bcDict["blockList"]])

    def countCoins(self):
        walletMap = collections.defaultdict(lambda: 0)
        for index, closedBlock in enumerate(self.blockList):
            for transaction in closedBlock.block.transactionList:
                walletMap[transaction.sender] -= transaction.amount
                walletMap[transaction.receiver] += transaction.amount
            walletMap[closedBlock.validatorSignature] += BlockChain.VALIDATOR_REWARD
        return walletMap

FUNC_MAP = {
    "exp2": bigfloat.exp2
}

REVERSE_FUNC_MAP = dict((FUNC_MAP[k], k) for k in FUNC_MAP)

class Challenge:
    """ Hardest-to-round cases for arbitrary function, precision and bound """
    def __init__(self,
                 func=bigfloat.exp2,
                 bound=2.0**-60,
                 startInput=None,
                 roundedPrecision=53,
                 extendedPrecision=106):

        # considered function
        self.func = func
        # input to start with when looking for hardest to round cases
        self.startInput = startInput
        # target upper bound on the error
        self.bound = bound
        # destination format
        self.roundedFormat = bigfloat.precision(roundedPrecision)
        # arbitrary-precision format
        self.extendedFormat = bigfloat.precision(extendedPrecision)
        self.jsonCoding = {
            "type": "challenge",
            "bound": bound,
            "roundedPrecision": roundedPrecision,
            "extendedPrecision": extendedPrecision,
            "func": REVERSE_FUNC_MAP[func],
        }

    def dictExport(self):
        return self.jsonCoding

    def jsonExport(self):
        return json.dumps(self.jsonCoding)

    @staticmethod
    def jsonImport(enc_str):
        decode_dict = json.loads(enc_str)
        assert decode_dict["type"] == "challenge"
        return Challenge(
            func=FUNC_MAP[decode_dict["func"]],
            bound=float(decode_dict["bound"]),
            roundedPrecision=int(decode_dict["roundedPrecision"]),
            extendedPrecision=int(decode_dict["extendedPrecision"])
        )

    def solve(self, watchdog=1000000):
        localInput = self.startInput if not self.startInput is None else bigfloat.BigFloat(random.random())
        for _ in range(watchdog):
            delta = self.delta(localInput)
            if delta < self.bound:
                return localInput
            localInput = bigfloat.next_up(localInput, context=self.roundedFormat)
        return None

    def delta(self, localInput):
        roundedValue = self.func(localInput, context=self.roundedFormat)
        extendedValue = self.func(localInput, context=self.extendedFormat)
        delta = abs(extendedValue - roundedValue) / roundedValue
        return delta

    def checkResponse(self, response):
        return self.delta(response) < self.bound

class ChallengeResponse:
    def __init__(self, challenge, response):
        self.challenge = challenge
        self.response = response

    def dictExport(self):
        transcript = self.challenge.dictExport()
        transcript.update({
            "type": "ChallengeResponse",
            "response": response,
        })
        return transcript

    def jsonExport(self):
        return json.dumps(self.dictExport())

if __name__ == "__main__":
    # Wallet generation
    newWallet = Wallet.generateNewWallet()
    message = b"hellow world.\n"

    # Wallet sign & verify
    signature = newWallet.sign(message)
    print(signature)
    check = newWallet.verify(signature, message)
    print(newWallet.export())

    # TMD challenge
    newChallenge = Challenge(bound=2.0**-60)
    jsonExport = newChallenge.jsonExport()
    print(jsonExport)
    newChallenge = Challenge.jsonImport(jsonExport)

    answer = newChallenge.solve() # bigfloat.BigFloat(random.random()))
    print(f"answer={answer}")
    print(f"delta={newChallenge.delta(answer)}")

    # Transaction signing and verification
    alice = Wallet.generateNewWallet()
    bob = Wallet.generateNewWallet()
    claire = Wallet.generateNewWallet()

    newTransaction = UnsignedTransaction(alice.id, bob.id, 0)
    halfNewTransaction = newTransaction.sign(alice)
    fullNewTransaction = halfNewTransaction.sign(bob)

    verifyTransaction = fullNewTransaction.verify(alice, bob)
    print(f"verifyTransaction={verifyTransaction}")
    try:
        wrongTransaction = fullNewTransaction.verify(claire, bob)
        print(f"wrongTransaction={wrongTransaction}")
    except ecdsa.keys.BadSignatureError:
        print("failed to verify transaction (expected failure)")

    # block-chain
    aricCoinChain = BlockChain()
    print(f"aricCoin init wallets: {aricCoinChain.countCoins().items()}")

    firstBlock = OpenBlock(0, aricCoinChain.rootDigest)
    firstBlock.addTransaction(fullNewTransaction)
    # alice is signing the first block
    aricCoinChain.addBlock(firstBlock.closeBlock(alice.id, firstBlock.signBlock(alice), firstBlock.blockChallenge.solve()))

    print(f"aricCoin after one transaction wallets: {aricCoinChain.countCoins().items()}")
    print("verifying chain")
    print(aricCoinChain.verifyChain())

    print("exporting blockchain")
    exportedBlockChain = aricCoinChain.jsonExport()
    print(exportedBlockChain)

    print("importing blockchain")
    importedChain = BlockChain.jsonImport(exportedBlockChain)
    print(importedChain.jsonExport())
    print(importedChain.verifyChain())
