import json

class JsonTranslatable:
    """ Helper class to factorize dictImport/jsonImport
        and dictExport/jsonExport """
    def jsonExport(self):
        return json.dumps(self.dictExport())
    @classmethod
    def jsonImport(cls, json_str):
        pyDict = json.loads(json_str)
        return cls.dictImport(pyDict)

    def dictExport(self):
        raise NotImplementedError

def bytesToStr(rawBytes):
    """ convert bytes to str such that strToBytes can
        convert it back to bytes properly """
    return rawBytes.hex()

def strToBytes(raw_str):
    """ convert str to bytes after bytesToStr conversion to return
        the original bytes content """
    return bytes.fromhex(raw_str)

