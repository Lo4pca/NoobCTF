# Ledengre_revenge

```py
from Crypto.Util.number import *
from Crypto.Cipher import AES
from sympy.ntheory.residue_ntheory import sqrt_mod
p=251
p_=71583805456773770888820224577418671344500223401233301642692926000191389937709
e=65537
target=1679283667939124174051653611794421444808492935736643969239278575726980681302
def function(x,p):
    y=0
    if x>=p:
        y=x
    elif pow(x,(p-1)//2,p)==1:
        y=pow(x,2,p)
    else:
        y=pow(x,3,p)
    return y
def matrix_to_str(matrix):
    b = bytes(sum([[matrix[row][col] for col in range(4)] for row in range(4)], []))
    return b.rstrip(b'\0')
def str2matrix(s):
    return [[s[row + 4*col] for row in range(4)] for col in range(4)]
key = None
for k in range(1<<16):
    if pow(k,2*e,p_) == target:
        key = k
        break
print("[+] Found key:", key)
lis0=[[341, 710, 523, 1016], [636, 366, 441, 790], [637, 347, 728, 426], [150, 184, 421, 733]]
lis1=[[133, 301, 251, 543], [444, 996, 507, 1005], [18, 902, 379, 878], [235, 448, 836, 263]]
a=[[239, 239, 251, 239], [233, 227, 233, 251], [251, 239, 251, 233], [233, 227, 251, 233]]
cipher=AES.new(long_to_bytes(key<<107), AES.MODE_ECB)
def brute(row,col,matrix,lis):
    for i in range(256): #幸好直接这样爆破不会出现多个可能值
        num=function(i,p)
        if (num>a[row][col]//2)==lis[row][col]&1 and function(num,a[row][col])==matrix[row][col]:
            return i
def solve(text_,lis):
    matrix=str2matrix(text_)
    for i in range(10):
        enc=b''
        for row in range(4):
            for col in range(4):
                enc+=bytes([brute(row,col,matrix,lis)])
                lis[row][col]>>=1
        matrix=str2matrix(cipher.decrypt(enc))
    return matrix_to_str(matrix)
text=26588763961966808496088145486940545448967891102453278501457496293530671899568
root=long_to_bytes(sqrt_mod(text,p_))
print(solve(root[:16],lis0)+solve(root[16:],lis1))
```