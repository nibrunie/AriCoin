from ecdsa import SigningKey, NIST384p, VerifyingKey
import bigfloat
import random
import json

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
        self.sender = bytes(sender)
        self.receiver = bytes(receiver)
        self.amount = amount

    def dictExport(self):
        return {
            "type": "UnsignedTransaction",
            "sender": str(self.sender),
            "receiver": str(self.receiver),
            "amount": self.amount
        }

    def jsonExport(self):
        return json.dumps(self.dictExport())
    @staticmethod
    def jsonImport(ut_str):
        utDict = json.loads(ut_str)
        assert utDict["type"] in ["UnsignedTransaction", "HalfTransaction", "FullTransaction"]
        return UnsignedTransaction(utDict["sender"], utDict["receiver"], utDict["amount"])

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
            "senderSignature": str(self.senderSignature)
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

    @staticmethod
    def jsonImport(ht_str):
        htDict = json.loads(ht_str)
        assert htDict["type"] in ["HalfTransaction", "FullTransaction"]
        return HalfTransaction(UnsignedTransaction.jsonImport(ht_str), htDict["senderSignature"])


class FullTransaction:
    """ Transaction of <amount> coin between sender and receiver signed
        by both sender and receiver """
    def __init__(self, halfTransaction, receiverSignature):
        self.halfTransaction = halfTransaction
        self.receiverSignature = receiverSignature

    def dictExport(self):
        dictTranscript = self.halfTransaction.dictExport()
        dictTranscript.update({
            "type": "FullTransaction",
            "receiverSignature": str(self.receiverSignature)
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
        assert htDict["type"] == "FullTransaction"
        return FullTransaction(HalfTransaction.jsonImport(ht_str), htDict["receiverSignature"])

class Block:
    pass

FUNC_MAP = {
    "exp2": bigfloat.exp2
}

REVERSE_FUNC_MAP = dict((FUNC_MAP[k], k) for k in FUNC_MAP)

class Challenge:
    """ Hardest-to-round cases for arbitrary function, precision and bound """
    def __init__(self, func=bigfloat.exp2, bound=2.0**-60, roundedPrecision=53, extendedPrecision=106):

        # considered function
        self.func = func
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

    def solve(self, localInput, watchdog=1000000):
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

if __name__ == "__main__":
    newWallet = Wallet.generateNewWallet()
    message = b"hellow world.\n"

    signature = newWallet.sign(message)
    print(signature)
    check = newWallet.verify(signature, message)
    print(newWallet.export())

    newChallenge = Challenge(bound=2.0**-60)
    jsonExport = newChallenge.jsonExport()
    print(jsonExport)
    newChallenge = Challenge.jsonImport(jsonExport)

    answer = newChallenge.solve(bigfloat.BigFloat(random.random()))
    print(f"answer={answer}")
    print(f"delta={newChallenge.delta(answer)}")

    alice = Wallet.generateNewWallet()
    bob = Wallet.generateNewWallet()
    claire = Wallet.generateNewWallet()

    newTransaction = UnsignedTransaction(alice.id, bob.id, 17)
    halfNewTransaction = newTransaction.sign(alice)
    fullNewTransaction = halfNewTransaction.sign(bob)

    verifyTransaction = fullNewTransaction.verify(alice, bob)
    print(f"verifyTransaction={verifyTransaction}")
    try:
        wrongTransaction = fullNewTransaction.verify(claire, bob)
        print(f"wrongTransaction={wrongTransaction}")
    except:
        print("failed to verify transaction")
