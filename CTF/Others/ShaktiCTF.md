# ShaktiCTF

Here are some challenges that I (remember) solved during the competition. Notice that I wrote this tiny writeup after the competition ends almost a week, so there may be some mistakes.

## Filters

Thanks https://radham0wn1ka.github.io/shakthiCTF/ for the source code.

We were given a php file, and we can execute any php codes as long as they don't match the regex. We can use `highlight_file` to read files in php, but in the file name "flag.txt", `a` is in the regex. And it seems like we can't use `highlight_file("fl*")` to match the flag file. I searched it online, and according to https://www.cnblogs.com/meng-han/p/16735478.html , we can use `\xnum` to represent a character in php. First I did `?command="\x73\x79\x73\x74\x65\x6d"("mv%20fl*%20fl");` , to rename `flag.txt` to `fl`; after this we can use `?command=highlight_file("fl");` to read the flag.

## NotBabyRev

There is a software called [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy), it can easily detect that the challenge program was packed by upx. So we use `upx -d file` to unpack it, then just load it in Ghidra. Now all we need to do is just reverse the process in the program. First it encodes the flag with some easily-reversed logics, then it uses a lot of if statements to check if the result is correct. A very obvious hint for using Z3.
```py
from z3 import *
s = []
s_length=36
for i in range(s_length):
	byte = Int("%s" % i)
	s.append(byte)
z = Solver()
z.add(s[16] + s[6] - s[18] ==0x6a)
z.add(s[32] + s[10] - s[29] ==  0xae)
z.add(s[2] + s[34] - s[17] ==0x6f)
z.add(s[18] + s[14] - s[28]== 0x13)
z.add(s[9] + s[23] - s[2]== 0x10)
z.add(s[21] + s[1] -s[27] == 0x4b)
z.add(s[5] + s[26] -s[6] == 0x6f)
z.add(s[13] + s[20] -s[33] == 0x53)
z.add(s[8] + s[27] -s[26] == 0x71)
z.add(s[20] + s[2] -s[5] == 0x59)
z.add(s[26] + s[17] -s[35] == 0x8d)
z.add(s[6] + s[5] -s[15] == 0x73)
z.add(s[14] + s[29] -s[31] == 0x12)
z.add(s[30] + s[25] -s[3] == 0x9b)
z.add(s[0] + s[21] -s[19] == 0x54)
z.add(s[22] + s[7] -s[13] == 0x1f)
z.add(s[11] + s[15] -s[24] == 0xbb)
z.add(s[27] + s[3] -s[7] == 0x66)
z.add(s[4] + s[13]- s[32] == 0x33)
z.add(s[17] +s[28] -s[14] == 0x8d)
z.add(s[10] +s[19] -s[0] == 0x66)
z.add(s[35] +s[22] -s[20] == 0x28)
z.add(s[1] +s[24] -s[12] == 0x16)
z.add(s[28] +s[11] -s[8] == 0x6d)
z.add(s[23] +s[18] -s[25] == 0x5f)
z.add(s[7] +s[0] +s[34] == 0xb8)
z.add(s[25] +s[12] -s[1] == 0x3c)
z.add(s[19] +s[8] -s[21] == 0x60)
z.add(s[33] +s[30] -s[10] == 0x49)
z.add(s[3] +s[35] +s[30] == 0x87)
z.add(s[29] +s[16] -s[9] ==0x82)
z.add(s[15] +s[9] +s[22] ==  0xb3)
z.add(s[34]+ s[31] - s[4] == 0x57)
z.add(s[12] +s[4]- s[16] == 0x53)
z.add(s[31] +s[33] -s[23] == 0x40)
z.add(s[0] +s[1] +s[2] +s[3] +s[4] +s[5] ==  0x1ca)
z.add(s[6] + s[7] +s[8] +s[9] +s[10] +s[11] == 0x1a9)
z.add(s[12] +s[13] +s[14] +s[15] +s[16] +s[17] == 0x1bd)
z.add(s[18] +s[19] +s[20] +s[21] +s[22] +s[23] == 0x20e)
z.add(s[24] +s[25] +s[26] +s[27] +s[28] +s[29] == 0x1a2)
z.add(s[30] +s[31] +s[32] +s[33] +s[34] +s[35] == 0x20a)
z.add(s[0] +s[6] +s[12] +s[18] +s[24] +s[30] == 0x18a)
z.add(s[1] +s[7] +s[13] +s[19] +s[25] +s[31] ==  0x17e)
z.add(s[2] +s[8] +s[14] +s[20] +s[26] +s[32] ==0x230)
z.add(s[3] +s[9] +s[15] +s[21] +s[27] +s[33] ==  0x165)
z.add(s[4] +s[10] +s[16] +s[22] +s[28] +s[34]== 599)
z.add(s[5]+ s[11] +s[17]+ s[23] +s[29]+ s[35] == 0x1f6)
if z.check() == sat:
	solution = z.model()
	print(solution)
elif z.check() == unsat:
	print("Failed:" + str(z.check()))
z3_res={6 : 86,
 25 : 75,
 16 : 90,
 26 : 94,
 17 : 90,
 12 : 74,
 28 : 98,
 9 : 6,
 30 : 86,
 19 : 71,
 31 : 75,
 23 : 100,
 4 : 99,
 27 : 98,
 33 : 89,
 5 : 103,
 11 : 120,
 15 : 74,
 18 : 70,
 14 : 47,
 32 : 118,
 10 : 102,
 8 : 109,
 3 : 6,
 35 : 43,
 22 : 99,
 7 : 2,
 0 : 71,
 21 : 84,
 1 : 89,
 24 : 7,
 13 : 70,
 20 : 102,
 2 : 90,
 34 : 111,
 29 : 46}
for b in range(6):
    local_1b4 = z3_res[b * 6 + 3]
    z3_res[b * 6 + 3] = z3_res[b * 6 + 2]
    z3_res[b * 6 + 2] = local_1b4
for a in range(6):
    local_1f4 = z3_res[a + 0x1e]
    z3_res[a + 0x1e] = z3_res[a + 6]
    z3_res[a + 6] = local_1f4
for n in range(6):
    local_234 = z3_res[n * 6 + 4]
    z3_res[n * 6 + 4] = z3_res[n * 6 + 1]
    z3_res[n * 6 + 1] = local_234
for m in range(6):
    local_274 = z3_res[m+0x12]
    z3_res[m+0x12] = z3_res[m]
    z3_res[m] = local_274
xor_transform_one=[0]*36
index=0
for k in range(6):
    for l in range(6):
        xor_transform_one[index]=z3_res[l + k * 6]
        index+=1
for i in range(36):
    xor_transform_one[i]=xor_transform_one[i]+5
input=[0]*36
for i in range(0x24):
    if ((i & 1 ^ i >> 0x1f) == i >> 0x1f):
        input[i] = xor_transform_one[i] ^ 0x38
    else:
        input[i] = xor_transform_one[i]
print(bytes(input))
```

## Sim

Out of bound read & write with both positive and negative indices relative to BSS segment data. At first the program uses gets to read user input, but it's not a BOF challenge cause it has canary enabled. `show` functions can leak data from an address, `add` function can write some data into an address. Given it's relative to BSS segment data, we can leak libc address from GOT tables and calculate the libc base and then the `system` function address. At the last step, we write the `system` function address into the GOT table of `printf` function. Why? Because at the end the main function calls `printf(input);`, where `input` is the buffer where our we input data stores. If we change the GOT table of `printf` to `system`, it will be equivalent to `system(input)`. Do you still remember at the beginning it calls `gets(input)`? If we input `/bin/sh`, we can just get a shell easily.

## Binary_Heist

In main/vault/input, there is a buffer overflow. There is also a function `infiltrate`, a classic "backdoor" function for these kind of return2win challenge. But before calling the backdoor function, we need to pass 2 parameters through rdi and rsi. Because I don't have the binary anymore(I recall this challenge from my Ghidra cache), I can't confirm it, but there are just two options:
1. Using ropper/ROPgadget to search all the gadgets in the binary to see that if there are any gadgets could just control rdi and rsi.
2. Do classic ret2libc.

At address `0x00401207`, we have a gadget `pop rdi;pop rsi;ret;`, which is the gadget we want. Now we can know that it's the first option.

## Looking_Mirror

I don't remember the details of this challenge, and no cache found in my Ghidra. But I somehow remember it's a format string challenge? The flag is readed into the stack, you just have to test `%offset$p`(or `$s`? Always get confused) to see where it is on the stack.

## cyber kingdom

Another challenge that I recall my memory thanks to https://radham0wn1ka.github.io/shakthiCTF/ . It just uses xor to encode the flag then compares them with a list that is hardcoded on the stack. The xor key was generated by `rand()&0xf`. Usually it's random, but with `srand(0x7b)` it's not anymore. You can just get the values by running a C file to see what's the output, or just use python:
```py
from ctypes import *
libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(0x7b)
cipher=[...]
for i in range(35):
    print(chr(cipher[i]^(libc.rand()&0xf)),end='')
```

## ultimate spider man

Yet another challenge that I recall my memory thanks to https://radham0wn1ka.github.io/shakthiCTF/ . But I remember my solution was completely different than this. There is a Spider Surprize, but we don't have enough money to buy it. In that writeup the author modifies the JWT cookie so that we can have enough money to buy it, but I remember I solved it by just changing the value of `product_id` in the post request to `/buy`? I may be wrong though.