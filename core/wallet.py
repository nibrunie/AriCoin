from ecdsa import SigningKey, NIST384p, VerifyingKey
import json

from .utils import JsonTranslatable, strToBytes, bytesToStr

class PublicWallet:
    """ Public part of a wallet with only the public key.
        It can only be used to verify transaction """
    def __init__(self, vk_string):
        self.vk = VerifyingKey.from_string(vk_string, curve=NIST384p)

    def verify(self, signature, msg):
        """ check that signature for msg is valid """
        return self.vk.verify(signature, msg)

    def export(self):
        return self.vk.to_string()

    def jsonExport(self):
        return json.dumps({
            "type": "PublicWallet",
            "vk_string": bytesToStr(self.export())
        })

    @property
    def id(self):
        return self.export()

    @staticmethod
    def jsonImport(pw_str):
        pw_dict = json.loads(pw_str)
        return PublicWallet.dictImport(pw_dict)

    @staticmethod
    def dictImport(pwDict):
        assert pwDict["type"] in ["PublicWallet", "Wallet"]
        return PublicWallet(strToBytes(pwDict["vk_string"]))

class Wallet(PublicWallet, JsonTranslatable):
    """ Coin wallet with a pair private,public key to sign (and verify)
        transaction """
    def __init__(self, sk_string):
        sk = SigningKey.from_string(sk_string, curve=NIST384p)
        PublicWallet.__init__(self, sk.verifying_key.to_string())
        self.sk = sk

    def sign(self, msg):
        """ evaluate the signature for msg """
        signature = self.sk.sign(msg)
        return signature

    def privateExport(self):
        return self.sk.to_string()

    @property
    def privateId(self):
        return self.privateExport()

    def extractPublicWallet(self):
        return PublicWallet(self.sk.verifying_key.to_string())

    def dictExport(self):
        return {
            "type": "Wallet",
            "sk": bytesToStr(self.privateExport())
        }
    @staticmethod
    def dictImport(wDict):
        assert wDict["type"] == "Wallet"
        return Wallet(strToBytes(wDict["sk"]))

    @staticmethod
    def generateNewWallet():
        sk = SigningKey.generate(curve=NIST384p)
        sk_string = sk.to_string()
        return Wallet(sk_string)

if __name__ == "__main__":
    newWallet = Wallet.generateNewWallet()

    message = b'hellow world'
    signature = newWallet.sign(message)

    exportedWallet = newWallet.jsonExport()
    importedWallet = Wallet.jsonImport(exportedWallet)

    check = importedWallet.verify(signature, message)
