from Crypto.Cipher import AES

#Padding data
List_pad=["\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0A","\x0B","\x0C","\x0D","\x0E","\x0F"]
def pading(data):
    n=len(data)
    SoLuongDem=16-n%16
    if SoLuongDem>0 and SoLuongDem!=16:                 #padding theo BLOCK_SIZE = 16
        data = data + List_pad[SoLuongDem-1]*SoLuongDem
    return data

#UnPadding data
def unpad(data):
    last = ord(data[-1])                        # Tính giá trị kí tự cuối cùng
    if last == 0 or last > 15:                  #Nếu kí tự cuối cùng có giá trị == 0, hoặc > 15 => return data
        return data
    if len(set(map(ord, data[-last:]))) == 1:  # N kí tự cuối cùng có giá trị = N, vd: 4 kí tự cuối cùng đều = 4
        return data[:-last]

#Mã hoá      AES_ECB_mode
def Encrypt(info,KEY):
    info=pading(info)                              #Padding data
    cipher = AES.new(KEY,AES.MODE_ECB)             #Cài đặt MODE encrypt
    result=cipher.encrypt(info.encode('utf-8'))    #Mã hoá
    return result

#Giải Mã    AES_ECB_mode
def Decrypt(info,KEY):
    deciper=AES.new(KEY,AES.MODE_ECB)          #Cài đặt chế độ giải mã
    pt=deciper.decrypt(info).decode('utf-8')     #Giải mã
    pt=unpad(pt)
    return pt
