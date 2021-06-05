from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

class DigitalSignature:
    # signature là chữ kí cuối cùng là chữ kí
    signature = None
    # key của RSA
    privatekey = None
    publickey = None
    # giá trị sau khi hash
    hash_value = None

    # Hàm này dùng để tạo key cho RSA
    def GenerateKey(self):
        # Tạo một private key
        rand = Random.new().read
        self.publickey = RSA.generate(2048, rand)

        # Tạo một public key
        self.privatekey = self.publickey.publickey()

        # Lưu lại publickey
        file = open("publickey.pem", 'wb')
        file.write(self.publickey.exportKey('PEM'))
        file.close()

    # Hàm này dùng để tạo chữ ký số (Mã hoá)
    def CreateSignature(self,input):
        # Sử dụng tiêu chuẩn PKCS1_OAEP để mã hoá
        rsa_encryption_cipher = PKCS1_OAEP.new(self.privatekey)
        self.signature = rsa_encryption_cipher.encrypt(input)
        return self.signature

    # Hàm này dùng để convert signature to hash_value (Giải mã)
    def DecryptSignature(self, file_key,chuki):
        # Lấy dữ liệu từ file_key (nơi chứa key)
        self.publickey = RSA.importKey(open(file_key).read())

        # Sử dụng tiêu chuẩn PKCS1_OAEP để giải mã
        rsa_decryption_cipher = PKCS1_OAEP.new(self.publickey)
        # self.hash_value = rsa_decryption_cipher.decrypt(self.signature)
        self.hash_value = rsa_decryption_cipher.decrypt(chuki)
        return self.hash_value







