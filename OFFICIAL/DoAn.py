import AES_ECB as aes_ecb
import SHA as sha
import RSA as rsa
import os
import time

s=time.time()
#Tạo key mã hoá, giải mã. AES_ECB
key=os.urandom(16)
file=open("KEY_AES_ECB.txt",'wb').write(key)
KEY=open("KEY_AES_ECB.txt",'rb').read()

#Mã hoá
print("----------- Mã Hoá ----------------")
data=open("INPUT.txt").read()
cipher=aes_ecb.Encrypt(data,KEY)
print("cipher: ",cipher)
print("len(cipher): ",len(cipher))
print("type(cipher): ",type(cipher))

pt=aes_ecb.Decrypt(cipher,KEY)
print("pt: ",pt)
print("len(pt): ",len(pt))
print("type(pt): ",type(pt))


#Băm SHA-256 ( --> 64bit)
print("----------- SHA - 256 ----------------")
out_sha=sha.SHA_256(cipher)
print("out_sha: ",out_sha)
print(len(out_sha))


#RSA
print("----------- RSA ----------------")
digtl_sig = rsa.DigitalSignature()
digtl_sig.GenerateKey()
chuki=digtl_sig.CreateSignature(out_sha)
print("chuki: ",chuki)
print(len(chuki))


# #Gắn thông điệp
print("----------- GẮN THÔNG ĐIỆP ----------------")
print("ct: ",cipher)
print("chuki: ",chuki)
str_send=cipher+chuki
# print(str_send)
file=open("Send.txt",'wb').write(str_send)


# #Tách Thông Điệp
print("----------- TÁCH THÔNG ĐIỆP ----------------")
str_input=open("Send.txt",'rb').read()
rsa_l=str_input[-256:]
ct=str_input[:-256]
print("left: ",rsa_l)
print("right: ",ct)

# #Băm SHA-256 vs ct
print("----------- BĂM SHA256 ----------------")
hash_r=sha.SHA_256(ct)
print("hash_r: ",hash_r)

#Giải mã RSA
print("----------- GIẢI MÃ RSA ----------------")
digtl_sig = rsa.DigitalSignature()
out=digtl_sig.DecryptSignature("publickey.pem",rsa_l)
print(out)

#Kiểm tra
print("----------- XÁC THỰC ----------------")
check=False
if hash_r==out:
    check=True
else:
    check=False
print(check)

#Giải mã ct --> pt
print("----------- GIẢI MÃ CIPHERTEXT ----------------")
key=open("KEY_AES_ECB.txt",'rb').read()
if check==True:
    pt=aes_ecb.Decrypt(ct,key)
    file=open("Out.txt",'w').write(pt)
    print("pt: ",pt)

print("timne: ",time.time()-s)
#Gắn thông điệp
# ThongDiep=cipher+chuki
# print(ThongDiep)
# print(cipher)
# print(chuki)
# file = open("ThongDiep.txt", 'wb')
# file.write(ThongDiep)

# print(ThongDiep)
# print(ThongDiep[:-256])
# print(ThongDiep[-256:])

