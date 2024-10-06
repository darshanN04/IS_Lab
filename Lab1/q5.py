def find(cipher, plain):
    x=ord(plain[0])-ord(cipher[0])
    return x

def decrypt(cipher, x=22):
    a=[]
    for i in cipher:
        a.append(i)
    l=[]
    for i in a:
        ch=(ord(i)-65+x)%26
        l.append(chr(ch+65))
        print(l)
    return ''.join(l)



cipher_text = "XVIEWYWI"
x=find("CIW", "YES")
print(decrypt(cipher_text))



