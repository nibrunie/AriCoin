from ecdsa import SigningKey, NIST384p
import bigfloat
import random

class Wallet:
    def __init__(self, sk_string):
        self.sk = SigningKey.from_string(sk_string, curve=NIST384p)

    def sign(self, msg):
        signature = self.sk.sign(msg)
        return signature

    def verify(self, signature, msg):
        vk = self.sk.verifying_key
        return vk.verify(signature, msg)

    def export(self):
        return self.sk.to_string()

    @staticmethod
    def generateNewWallet():
        sk = SigningKey.generate(curve=NIST384p)
        sk_string = sk.to_string()
        return Wallet(sk_string)

class Transaction:
    pass

class Block:
    pass

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

    newChallenge = Challenge(bound=2.0**-70)
    answer = newChallenge.solve(bigfloat.BigFloat(random.random()))
    print(f"answer={answer}")
    print(f"delta={newChallenge.delta(answer)}")
