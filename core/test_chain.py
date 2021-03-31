import pytest
import ecdsa

from .wallet import Wallet
from .core_engine import UnsignedTransaction, BlockChain, OpenBlock

class TestBlockChain:
    alice = Wallet.generateNewWallet()
    bob = Wallet.generateNewWallet()
    claire = Wallet.generateNewWallet()
    aricCoinChain = BlockChain()
    transaction = None

    def setup(self):
        pass

    def test_transaction_signing(self):
        # Transaction signing and verification

        newTransaction = UnsignedTransaction(self.alice.id, self.bob.id, 0)
        halfNewTransaction = newTransaction.sign(self.alice)
        fullNewTransaction = halfNewTransaction.sign(self.bob)

        verifyTransaction = fullNewTransaction.verify(self.alice, self.bob)
        print(f"verifyTransaction={verifyTransaction}")
        try:
            wrongTransaction = fullNewTransaction.verify(self.claire, self.bob)
            print(f"wrongTransaction={wrongTransaction}")
        except ecdsa.keys.BadSignatureError:
            print("failed to verify transaction (expected failure)")
        TestBlockChain.transaction = fullNewTransaction

    def test_block_one(self):
        lastOpenBlock = self.aricCoinChain.lastOpenBlock
        assert lastOpenBlock.blockId == 0
        # block-chain
        lastOpenBlock.addTransaction(self.transaction)
        assert self.aricCoinChain.verifyChain()
        # alice is signing the first block
        self.aricCoinChain.closeBlock(self.alice.id,
                                      lastOpenBlock.signBlock(self.alice),
                                      lastOpenBlock.blockChallenge.solve())
        assert self.aricCoinChain.verifyChain()

    def test_block_two(self):
        lastOpenBlock = self.aricCoinChain.lastOpenBlock
        assert lastOpenBlock.blockId == 1
        lastOpenBlock.addTransaction(self.transaction)
        assert self.aricCoinChain.verifyChain()
        # bob is signing the first block
        self.aricCoinChain.closeBlock(self.bob.id,
                                      lastOpenBlock.signBlock(self.bob),
                                      lastOpenBlock.blockChallenge.solve())
        assert self.aricCoinChain.verifyChain()

    def test_block_three(self):
        assert self.aricCoinChain.addTransaction(self.transaction)

    def test_verify_chain(self):
        assert self.aricCoinChain.verifyChain()

    def test_export_import_chain(self):
        exportedBlockChain = self.aricCoinChain.jsonExport()
        importedChain = BlockChain.jsonImport(exportedBlockChain)
        assert importedChain.verifyChain()
