import ecdsa

from .wallet import Wallet


def test_wallet_generation():
    # Wallet generation
    newWallet = Wallet.generateNewWallet()
    newPublicWallet = newWallet.extractPublicWallet()

def test_wallet_signature():
    newWallet = Wallet.generateNewWallet()
    # Wallet sign & verify
    message = b'hellow world'
    signature = newWallet.sign(message)
    assert signature
    check = newWallet.verify(signature, message)
    assert check
    failedCheck = True
    try:
        failedCheck = newWallet.verify(b'bad signature', message)
    except ecdsa.keys.BadSignatureError:
        failedCheck = False
    assert not failedCheck

def test_wallet_export():
    newWallet = Wallet.generateNewWallet()

    message = b'hellow world'
    signature = newWallet.sign(message)

    exportedWallet = newWallet.jsonExport()
    importedWallet = Wallet.jsonImport(exportedWallet)

    check = importedWallet.verify(signature, message)
    assert check

