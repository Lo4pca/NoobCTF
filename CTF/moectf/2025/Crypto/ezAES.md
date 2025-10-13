# ezAES

让我们恭喜chatgpt耗时1m 14s独立完成此题（

陷阱在shift_rows函数中。`grid[i::4] = grid[i::4][i:] + grid[i::4][:i]`是切片赋值，会影响传进来的对象；但在i=0时等同于什么也没做。紧接着`grid=xxx`在局部创建了一个新的grid，因此后续的切片赋值和原本传入的对象无关了，操控的都是局部变量grid。逆向时需跳过shift_rows
```py
# We'll implement the corrected decryption for the provided "AES-like" cipher,
# taking into account that the original shift_rows() is effectively a NO-OP for the caller.
# Then we'll decrypt the given ciphertext with the fixed inverse routine and print the plaintext.
s_box = 
s_box_inv = 
rc = 

def key_expansion(grid):
    for i in range(10 * 4):
        r = grid[-4:]
        if i % 4 == 0:
            for j, v in enumerate(r[1:] + r[:1]):
                r[j] = s_box[v >> 4][v & 0xf] ^ (rc[i // 4] if j == 0 else 0)
        for j in range(4):
            grid.append(grid[-16] ^ r[j])
    return grid

def add_round_key(grid, round_key):
    for i in range(16):
        grid[i] ^= round_key[i]

def inv_sub_bytes(grid):
    for i, v in enumerate(grid):
        grid[i] = s_box_inv[v >> 4][v & 0xf]

def gf_mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return res

def inv_mix_columns(grid):
    def inv_mix_column(c):
        return [
            gf_mul(c[0],0x0e) ^ gf_mul(c[1],0x0b) ^ gf_mul(c[2],0x0d) ^ gf_mul(c[3],0x09),
            gf_mul(c[0],0x09) ^ gf_mul(c[1],0x0e) ^ gf_mul(c[2],0x0b) ^ gf_mul(c[3],0x0d),
            gf_mul(c[0],0x0d) ^ gf_mul(c[1],0x09) ^ gf_mul(c[2],0x0e) ^ gf_mul(c[3],0x0b),
            gf_mul(c[0],0x0b) ^ gf_mul(c[1],0x0d) ^ gf_mul(c[2],0x09) ^ gf_mul(c[3],0x0e),
        ]
    for i in range(0,16,4):
        grid[i:i+4] = inv_mix_column(grid[i:i+4])

def decrypt_block(b, expanded_key):
    # Final round inverse
    add_round_key(b, expanded_key[-16:])
    # shift_rows was a NO-OP in encryption, so skip inverse shift
    inv_sub_bytes(b)

    # Rounds 9..1
    for i in range(9, 0, -1):
        add_round_key(b, expanded_key[i*16:])
        inv_mix_columns(b)
        # no inverse shift
        inv_sub_bytes(b)

    # Round 0 inverse
    add_round_key(b, expanded_key[:16])
    return b

def aes_decrypt(key, ciphertext):
    expanded = key_expansion(bytearray(key))
    b = bytearray(ciphertext)
    for i in range(0, len(b), 16):
        block = bytearray(b[i:i+16])
        b[i:i+16] = decrypt_block(block, expanded)
    return bytes(b).rstrip(b'\x00')

key = b'Slightly different from the AES.'
ciphertext = b'%\x98\x10\x8b\x93O\xc7\xf02F\xae\xedA\x96\x1b\xf9\x9d\x96\xcb\x8bT\r\xd31P\xe6\x1a\xa1j\x0c\xe6\xc8'
plaintext = aes_decrypt(key, ciphertext)
print(plaintext)
```