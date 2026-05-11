from aes import AESCipher
from block import Block
from byte_value import Byte
from gcm import GCMCipher
from gf256 import xtime
from polynomial import Polynomial
from test_vectors import read_test_vector, read_gcm_test_vectors

def main() -> None:
    # GF and helper class demo
    a = Byte(0x57)
    b = Byte(0x13)
    print(f"Byte add (XOR): {a + b}")
    print(f"Byte mul (GF): {a * b}")
    print(f"xtime(0x57): 0x{xtime(0x57):02X}")

    p = Polynomial([0x57, 0x13, 0x01])
    print(f"Polynomial + Byte: {p + b}")
    print(f"Polynomial * Byte: {p * b}")

    # AES-128 known-answer test (FIPS-197 Appendix C.1)
    vectors = ['128', '192', '256']
    for vector in vectors:
        test_vectors = read_test_vector(vector)
        print('-'*100)
        print(f"ECBKeySbox{vector}.rsp")
        for entry in test_vectors:
            key = entry[0]
            plaintext = entry[1]
            ciphertext = entry[2]
            cipher = AESCipher(key)
            encrypted = cipher.encrypt_block(plaintext)
            decrypted = cipher.decrypt_block(ciphertext)
            print(f"Encrypt status: {'OK' if encrypted == ciphertext else 'ERR'} | Expected: {ciphertext.hex()} | Got: {encrypted.hex()}")
            print(f"Decrypt status: {'OK' if decrypted == plaintext else 'ERR'} | Expected: {plaintext.hex()} | Got: {decrypted.hex()}")


    #print(f"Plaintext : {plaintext.hex()}")
    #print(f"Ciphertext: {ciphertext.hex()}")
    #print(f"Expected  : {expected_ciphertext.hex()}")
    #print(f"Decrypt OK: {recovered == plaintext}")
    #print(f"Encrypt OK: {ciphertext == expected_ciphertext}")

    #block = Block.from_bytes(plaintext)
    #print(f"Block bytes: {block.to_bytes().hex()}")

    
    # k = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c")
    # p= bytes.fromhex("d9313225f88406e5a55909c5aff5269a"\
    #                 "86a7a9531534f7da2e4c303d8a318a72"\
    #                 "1c3c0c95956809532fcf0e2449a6b525"\
    #                 "b16aedf5aa0de657ba637b39")
    # a = bytes.fromhex("")
    # iv = bytes.fromhex("cafebabefacedbad")

    # gcm_cipher = GCMCipher(k)
    # gcm_ciphertext, tag = gcm_cipher.encrypt_data(plaintext=p, aad=a, iv=iv)
    # gcm_plaintext = gcm_cipher.decrypt_data(ciphertext=gcm_ciphertext, tag=tag, iv=iv)
    #print(f"GCM Status: {'OK' if p==gcm_plaintext else 'ERR'} | C: {gcm_ciphertext.hex()} | T: {tag.hex()}")
    gcm_vectors = read_gcm_test_vectors()
    index=1
    for vector in gcm_vectors:
        k, p, a, iv, c, t = vector
        gcm = GCMCipher(k)
        ciphertext, tag = gcm.encrypt_data(plaintext=p, iv=iv, aad=a)
        decrypted = gcm.decrypt_data(ciphertext=c, tag=t, iv=iv, aad=a)
        print('*'*100)
        print(f"Test case {index}")
        print(f"Encrypted:{'Success' if ciphertext==c and tag==t else 'ERR'}")
        print(f"Expected:\nCiphertext {c.hex()}\nTag {t.hex()}")
        print(f"Got:\nCiphertext {ciphertext.hex()}\nTag {tag.hex()}")
        print(f"Decrypted:{'Success' if decrypted==p else 'ERR'}")
        print(f"Expected:\n{p.hex()}\nGot:\n{decrypted.hex()}")
        index+=1

    

if __name__ == "__main__":
    main()
