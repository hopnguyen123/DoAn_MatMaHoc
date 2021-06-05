import hashlib

#Có thể Hasb cả 'String' và 'bytes'


#Input -> Output (256bit data)
def SHA_256(data):
    hash = hashlib.sha256(data).digest()        # .digest => băm ra byte, .hexdigest => băm ra byte kiểu hex
    return hash

#Input -> Output: (384bit data)
def SHA_384(data):
    hash = hashlib.sha384(data).digest()
    return hash

#Input -> Ouput: (512bit data)
def SHA_512(data):
    hash = hashlib.sha512(data).digest()
    return hash
