For beginners to CV, such as myself; I personally think targetting these easier challenges is a great start to anyone who is interested in reversing CV based protections, etc.

## The CrackMe
• While looking for a simple virtualization based challenge, I stumbled upon a CrackMe which I believe was originally written by NWMonster here https://github.com/zzz66686/simple-virtual-machine/tree/master/VM_crackme. Although it is open-source, I decided it'd be a good challenge to reverse it, then jump into the source and see how accurate my findings were after successfully getting the flag.

# Starting
• After loading up `vm_crackme.exe` into IDA for the first time and jumping into `main`, I noticed the obvious virtual function calls and allocations, and some data initialization.

![Imgur Image](https://i.imgur.com/XNHRJHd.png)

So I fired up ClassInformer and as expected, a class named `VM` is listed, with 29 methods.

![Imgur Image](https://i.imgur.com/HSti5tt.png)

We'll need this later. Back into main, we can see that the first allocations are related to a `VM` structure creation. We can see some data intialization 
```cpp
v12 = operator new(0x24u);
v16 = v12;
v12[1] = 0;
v16[2] = 0;
v16[3] = 0;
v11 = (void *)j_unknown_libname_1(0x64u);
Dst = v11;
v10 = (void *)j_unknown_libname_1(0x50u);
v14 = v10;
j_memcpy(v11, argv[1], 0x32u);
v16[5] = v11;
v16[6] = v14;
v16[8] = &unk_41C000;
```
We can also see immediately after that the data structure at `v16` is passed onto the first called virtual function.
```cpp
(*(void (__thiscall **)(void *, _DWORD *))(*(_DWORD *)v17 + 104))(v17, v16);
```

I *highly* recommend to create structures within IDA to represent anything you may find commonly used. 

With more digging, we'll find that `v17` is the ptr to a `VM` class. We can assume `v16` is probably the VM's context.

More interestingly, is the `unk_41C000` which is set 32 bytes from `v16`.

Clicking on `unk_41C000` will lead us to a large chunk of data..
![Imgur Image](https://i.imgur.com/mr72VVK.png)

I automatically suspected this to be the byte code for the VM, which is correct, but now to good stuff.

Remember the first virtual function called, that passes the context data `v16`? `104/4` = idx 26. So lets count down from `419B34` starting from 0 to 26. Then click on the subroutine.

![Imgur Image](https://i.imgur.com/uFTs7lR.png)

We land here
```asm
.text:004113AC vm__vm_begin    proc near               ; DATA XREF: .rdata:00419B9C↓o
.text:004113AC                 jmp     sub_4121A0
.text:004113AC vm__vm_begin    endp
.text:004113AC
```
Follow the `jmp` and jump into pseudocode (F5)
I called this `vm::vm_start`, but you're free to choose your own naming.
```cpp
int __thiscall vm::vm_start(int this, _DWORD *a2)
{
  *(_DWORD *)(this + 4) = *a2;
  *(_DWORD *)(this + 8) = a2[1];
  *(_DWORD *)(this + 12) = a2[2];
  *(_DWORD *)(this + 16) = a2[3];
  *(_DWORD *)(this + 20) = 0;
  *(_DWORD *)(this + 24) = a2[5];
  *(_DWORD *)(this + 28) = a2[6];
  *(_DWORD *)(this + 32) = a2[6] + 40;
  *(_DWORD *)(this + 36) = a2[8];
  return 0;
}
```
If you're following along, it is highly ideal to right click on `this` and hit "Create new structure." This will make IDA generate a new structure based on variables that are known.
Now, we have this... 
```cpp
int __thiscall vm::vm_start(VM *this, _DWORD *a2)
{
  this->dword4 = *a2;
  this->dword8 = a2[1];
  this->dwordC = a2[2];
  this->dword10 = a2[3];
  this->dword14 = 0;
  this->dword18 = a2[5];
  this->dword1C = a2[6];
  this->dword20 = a2[6] + 40;
  this->dword24 = a2[8];
  return 0;
}
```
Already much cleaner. Also, remember that 32 bytes down was the ptr to the VM byte code.. So `dword24` is probably the instruction pointer.. Lets rename `dword24` to `rip` (short for reg. instruction pointer).

Lets jump into vfunc 28, which was called inbetween the other 2 virtual functions. Go back to the VM structure ClassInformer told us about, and go 2 functions down. Follow the `jmp` again and you will land at
```asm
.text:00411096 sub_411096      proc near               ; DATA XREF: .rdata:00419BA4↓o
.text:00411096                 jmp     sub_417280
.text:00411096 sub_411096      endp
```

You will quickly realize what this is once you jump into pseudocode.
```cpp
int __thiscall vm::vm_run(VM *this)
{
  int result; // eax
  int v2; // [esp+Ch] [ebp-DCh]
  unsigned __int8 *v3; // [esp+D4h] [ebp-14h]
  VM *v4; // [esp+E0h] [ebp-8h]

  v4 = this;
  while ( 1 )
  {
    v3 = (unsigned __int8 *)v4->rip;
    v2 = *v3;
    v2 -= 0x66;
    result = v2;
    switch ( v2 )
    {
      case 0:
        return result;
      case 1:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 16))(v4);
        break;
      case 2:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 20))(v4);
        break;
      case 3:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 24))(v4);
        break;
      case 4:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 28))(v4);
        break;
      case 5:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 32))(v4);
        break;
      case 6:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 36))(v4);
        break;
      case 7:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 40))(v4);
        break;
      case 8:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 44))(v4);
        break;
      case 9:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 48))(v4);
        break;
      case 10:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 52))(v4);
        break;
      case 11:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 56))(v4);
        break;
      case 12:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 60))(v4);
        break;
      case 13:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 64))(v4);
        break;
      case 14:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 68))(v4);
        break;
      case 15:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 72))(v4);
        break;
      case 16:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 76))(v4);
        break;
      case 17:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 80))(v4);
        break;
      case 18:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 84))(v4);
        break;
      case 19:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 88))(v4);
        break;
      case 20:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 92))(v4);
        break;
      case 21:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 96))(v4);
        break;
      case 22:
        (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 100))(v4);
        break;
    }
  }
}
```

It's the dispatcher which executes the byte code by calling all associated handlers. I won't be going over each handler 1 by 1, but I will be going over a couple. The rest will be shown later, but you are 100% free and encouraged to attempt figuring them out yourself!

As you can see, the dispatcher takes the current opcode, subtracts 0x66 and attempts to process the opcode via a handler. Each handler is a virtual function, which will be easy to find since we have the virtual function table. 

As you can see, the first handler starts at vfunc 4
```cpp
case 1:
      (*(void (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 16))(v4);
      break;
```
And keeps going down in numerical order (opcode 2 = vfunc 5).

If we jump into the 4th virtual function, we'll get this.
```cpp
VM *__thiscall sub_4177F0(VM *this)
{
  int v1; // esi
  int v2; // eax
  VM *result; // eax
  VM *v4; // [esp+D0h] [ebp-8h]

  v4 = this;
  v1 = (**(int (__thiscall ***)(VM *))this->gap0)(this);
  v2 = (*(int (__thiscall **)(VM *))(*(_DWORD *)v4->gap0 + 4))(v4);
  (*(void (__thiscall **)(VM *, int))(*(_DWORD *)v4->gap0 + 8))(v4, v2 + v1);
  result = v4;
  v4->rip += 2;
  return result;
}
```
So, by the looks of it, we need vfunc 0, 1, 2 as well to continue with our reversing, since they're all called here.

So, now if we jump into the first vfunc, we'll see this. I've commented this function to make it easier.
```cpp
int __thiscall sub_412D40(VM *this)
{
  int result; // eax

  // Check the high bits of the next byte in the byte-code for a match (0-4)
  switch ( (unsigned __int8)((signed int)*(unsigned __int8 *)(this->rip + 1) >> 4) )
  {
    case 0u:
      result = this->dword4;
      break;
    case 1u:
      result = this->dword8;
      break;
    case 2u:
      result = this->dwordC;
      break;
    case 3u:
      result = this->dword10;
      break;
    case 4u:
      result = this->dword14;
      break;
  }
  return result;
}
```
So depending if the high bits result to 0-4, we'll get a different member in the class each time. So, I figured that this is actually returning the VM's registers. So I've renamed them from `r0` (register 0) down to `r4`. We can't be sure yet that these registers are only used for general purposes, but we'll find out later if any of them needs to be renamed.

Lets check the next function down.
```cpp
int __thiscall sub_412E10(VM *this)
{
  int result; // eax

  switch ( *(_BYTE *)(this->rip + 1) & 0xF )
  {
    case 0:
      result = this->r0;
      break;
    case 1:
      result = this->r1;
      break;
    case 2:
      result = this->r2;
      break;
    case 3:
      result = this->r3;
      break;
    case 4:
      result = this->r4;
      break;
  }
  return result;
}
```
Alternatively, this checks the low bits, but does the same thing. Let's check the 3rd vfunc to find out more info.
```cpp
VM *__thiscall sub_412EE0(VM *this, int a2)
{
  VM *result; // eax

  switch ( (unsigned __int8)((signed int)*(unsigned __int8 *)(this->rip + 1) >> 4) )
  {
    case 0u:
      result = this;
      this->r0 = a2;
      break;
    case 1u:
      result = this;
      this->r1 = a2;
      break;
    case 2u:
      result = this;
      this->r2 = a2;
      break;
    case 3u:
      result = this;
      this->r3 = a2;
      break;
  }
  return result;
}
```

We can safely assume that the high bits are specifying the destination register. So we can name this `vm::setdst`, and the other 2 `vm::getdst` and `vm::getsrc`.

Lets generate a structure from the VTable.
![Imgur Image](https://i.imgur.com/WsIuJvD.png)

Jump back into the function which called, `getdst`, `getsrc`, and `setdst`, and lets make it much more readable. Change the `this` to the `VM` structure we made earlier, and change `gap0`'s type by pressing `Y` or right-clicking and clicking `Set Field Type`
![Imgur Image](https://i.imgur.com/WUiAH1E.png) 

Change it to a ptr to the structure we generated from the VTable. Rename any functions appropriately and now we'll have this.
```cpp
VM *__thiscall vm::add(VM *this)
{
  int dst; // esi
  int src; // eax
  VM *result; // eax
  VM *v4; // [esp+D0h] [ebp-8h]

  v4 = this;
  dst = ((int (__thiscall *)(VM *))this->vt->getdst)(this);
  src = ((int (__thiscall *)(VM *))v4->vt->getsrc)(v4);
  ((void (__thiscall *)(VM *, int))v4->vt->setdst)(v4, src + dst);
  result = v4;
  v4->rip += 2;
  return result;
}
```
MUCH cleaner. And we can easily see what this function does. Add the source and destination registers and store them in `dst`. It then advanced the instruction pointer 2 bytes forward, so this instruction length is 2 bytes long. We can appropriately call this function `vm::add`.

For the purpose of not making this tutorial extremely long, I'll be only going over the `push`, `loop`, `cmp`, `jl/jg/je`, and an `inc` instruction.

--- If you'd like to figure out the handlers yourself. Pause here as the next piece of code I'll be sharing shows the dispatcher with named functions.

So, after going through the tedious work of figuring out all the handlers, I've named them to what I thought was correct.
```cpp
int __thiscall vm::vm_run(VM *this)
{
  int result; // eax
  int curOpcode; // [esp+Ch] [ebp-DCh]
  unsigned __int8 *ptrToCode; // [esp+D4h] [ebp-14h]
  VM *v4; // [esp+E0h] [ebp-8h]

  v4 = this;
  while ( 1 )
  {
    ptrToCode = v4->rip;
    curOpcode = *ptrToCode;
    curOpcode -= 'f';                           // ? (vm_opcode - 0x66) = cur_opcode 
    result = curOpcode;
    switch ( curOpcode )
    {
      case 0:
        return result;
      case 1:
        ((void (__thiscall *)(VM *))v4->vfptr->vm_add)(v4);// vfunc 4 : vm__Opcode1Handler
        break;
      case 2:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_sub)(v4);// vfunc 5
        break;
      case 3:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_mul)(v4);// 6
        break;
      case 4:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_div)(v4);// 7
        break;
      case 5:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_inc)(v4);// 8
        break;
      case 6:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_dec)(v4);
        break;
      case 7:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_xor)(v4);
        break;
      case 8:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_and)(v4);
        break;
      case 9:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_push)(v4);
        break;
      case 0xA:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_push_imm)(v4);
        break;
      case 0xB:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_pop)(v4);
        break;
      case 0xC:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_mov)(v4);
        break;
      case 0xD:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_mov_id)(v4);
        break;
      case 0xE:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_mov_di)(v4);
        break;
      case 0xF:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_loop)(v4);
        break;
      case 0x10:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_cmpi)(v4);
        break;
      case 0x11:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_jl)(v4);
        break;
      case 0x12:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_jg)(v4);
        break;
      case 0x13:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_je)(v4);
        break;
      case 0x14:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_inc_ui)(v4);
        break;
      case 0x15:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_dec_ui)(v4);
        break;
      case 0x16:
        (*(void (__thiscall **)(VM *))&v4->vfptr->vm_xor16_66h)(v4);
        break;
    }
  }
}
```

So if we jump into `push` this will reveal another member name.
```cpp
VM *__thiscall vm::vm_push(VM *this)
{
  VM *result; // eax
  int v2; // [esp+D0h] [ebp-14h]
  VM *v3; // [esp+DCh] [ebp-8h]

  v3 = this;
  v2 = ((int (__thiscall *)(VM *))this->vfptr->vm_getd)(this);
  v3->dword20 -= 4;  // this seems to be the stack pointer
  *(_DWORD *)v3->dword20 = v2; // allocates 4 bytes then sets this space of the stack to the `dst` register (e.g `push r0`)
  result = v3;
  v3->rip += 2; //2 byte instruction len
  return result;
}
```
But, there is also another `push` instruction.
```cpp
// this on the other hand pushes a immediate value 
VM *__thiscall vm::vm_push_imm(VM *this)
{
  int v1; // STD4_4
  VM *result; // eax
  // e.g 'push 0xDEADBEEF`
  v1 = (this->rip[1] << 24) + (this->rip[2] << 16) + (this->rip[3] << 8) + this->rip[4]; // resolve an int from the next 4 bytes.
  this->dword20 -= 4;
  *(_DWORD *)this->dword20 = v1;
  result = this;
  this->rip += 5; // 5 byte instruction len
  return result;
}
```
Now, the `loop` instruction, which we'll find out later is used by the bytecode several times.
```cpp
VM *__thiscall vm::vm_loop(VM *this)
{
  VM *result; // eax
  unsigned __int8 *newIp; // ecx
  int lcode_len; // [esp+D0h] [ebp-14h]
  VM *v4; // [esp+DCh] [ebp-8h]

  v4 = this;
  lcode_len = this->rip[1];
  if ( this->r3 )                               // reg3 used as a loop counter
  {
    --this->r3;                                 // dec the loop counter reg3
    result = this;
    newIp = &this->rip[-lcode_len];             // set the new instruction ptr
  }
  else
  {
    result = this;
    newIp = this->rip + 2;                      // break out the loop once the loop counter hits 0 (2 byte instr len)
  }
  v4->rip = newIp;
  return result;
}
```
This will either jump back in the code to continue the loop or break out by advancing 2 bytes once `r3` hits 0. 

The `cmp` instruction also reveals another bit of information.
```cpp
VM *__thiscall vm::vm_cmpi(VM *this)
{
  int dst; // esi
  unsigned int dst_; // esi
  unsigned int dst__; // esi
  VM *result; // eax
  VM *v5; // [esp+D0h] [ebp-8h]

  v5 = this;
  dst = (this->vfptr->vm_getd)(this);
  if ( dst == (v5->vfptr->vm_gets)(v5) )
    v5->r4 = 0;                                 // r4 is actually ends up being a flag used when a cmp instruction is executed
  dst_ = (v5->vfptr->vm_getd)(v5);
  if ( dst_ < (v5->vfptr->vm_gets)(v5) )
    v5->r4 = -1;
  dst__ = (v5->vfptr->vm_getd)(v5);
  if ( dst__ > (v5->vfptr->vm_gets)(v5) )
    v5->r4 = 1;
  result = v5;
  v5->rip += 2;
  return result;
}
```
We can safely rename `r4` to `cflag` (compare flag) instead, since it is only used by `cmp` and its relative jump instructions.

So if we jump to `jg` handler, we'll see this, which checks out with the `cmp` handler we just reversed.

```cpp
VM *__thiscall vm::vm_jg(VM *this)
{
  VM *result; // eax
  unsigned __int8 *v2; // ecx
  VM *v3; // [esp+DCh] [ebp-8h]

  v3 = this;
  if ( this->cflag == 1 )                       // if cflag is set to 1 (greater than results to true), take the jmp.
  {
    result = this;
    v2 = &this->rip[this->rip[1] + 2];
  }
  else                                          // else just continue to the next instruction (2 byte len)
  {
    result = this;
    v2 = this->rip + 2;
  }
  v3->rip = v2;
  return result;
}
```

And lastly, a `inc` instruction, that doesn't increment a register, but rather a ptr we supplied earlier. If you looked in `main`, you would see the program's argument passed into the vm ctx structure.
```cpp
v11 = (void *)j_unknown_libname_1(0x64u);
j_memcpy(v11, argv[1], 0x32u);
..
*(_DWORD *)(v16 + 20) = v11;
```
If we jump into the handler I named `inc_ui`, we'll see this
```cpp
VM *__thiscall vm::vm_inc_ui(VM *this)
{
  VM *result; // eax

  ++this->dword18; // this is actually the `argv[1]` that was passed earlier. We can figure this out by checking vfunc 26.
  result = this;
  ++this->rip; // 1 byte instruction length
  return result;
}
```
So I renamed `dword18` to `ud` (user data). It has it's brother I called `dec_ui` which does the opposite.

So with all the handlers named, reversed, and their instruction lengths known, I wrote a small disassembler to translate the byte code to its mnemonic, which you can find [here.](https://github.com/ayyMike/solving-vm-crackme-1/blob/master/crackme.cpp)

This results in this output [here](https://github.com/ayyMike/solving-vm-crackme-1/blob/master/output).

Now, you might immediately notice this line.
```asm
dxor 46, 39, 37, 45, 57, 50, 46, 35, 57, 54, 42, 39, 40, 35, 50 ; XOR'd -> 72, 65, 67, 75, 95, 84, 72, 69, 95, 80, 76, 65, 78, 69, 84
```

The `dxor` handler simply XOR's the next 15 bytes with `0x66`. This results in the string `HACK_THE_PLANET`, which admittedly, I tried feeding the program to check if that was the correct key (and obviously, it wasn't).

So if we look at the generated output, we'll see this (which I've commented)

```asm
0010 | push 2F   
0015 | loop 10
0017 | pop r3		    ; r3 = 47, r3 is used as the loop counter if you remember, so we can see that this program expects input with a length of 48 (loop goes down to 0) characters
0019 | movd r0     ; movd handler moves a character from user data into the dst register
001B | xor r2, r2  ; zero out r2
001D | cmp r0, r2  ; null terminator check
001F | je 54       ; jump to 0x54 if its null
0021 | inc_ui      ; inc_ui handler increments the user data ptr, so in other words advances to the next character.
0022 | push 46     ; now if we check the code below, we'll see a bunch of checks as to whether the character is valid for the input
0027 | pop r1      ; it's checking to see if each character is a valid hexadecimal digit
0029 | cmp r0, r1  ; if it is not valid, it will exit out the code (see 0x54)
002B | jg 54
002D | push 30
0032 | pop r1
0034 | cmp r0, r1
0036 | jl 4e
0038 | push 39
003D | pop r1
003F | cmp r0, r1
0041 | jl 4e
0043 | push 41
0048 | pop r0
004A | cmp r0, r1
004C | jl 54
004E | xor r0, r0
0050 | cmp r0, r0
0052 | je 59
; Code will jump here when it confirms the string is invalid
0054 | xor r0, r0
0056 | inc r0
0058 | end
0059 | loop 19 ; once the loop (48 iterations) is done and all characters are checked, it will continue to the next instruction
```

Now, we get to actually see some code which will reveal how to get the correct key!

```asm
005B | push 7
0060 | pop r3     ; r3 = 7, we can expect a loop instruction later.
0062 | xor r1, r1 ; 
0064 | dec_ui     ; if you recalled earlier, there was 48 'inc_ui' instructions, but the program never called 'dec_ui' to reset the user ptr back to original.
0065 | movd r0    ; because of this, we'll be working in 'reverse', meaning, the part of the key discovered here will be tagged on the end rather than the front.
0067 | push 30    ; push '0'
006C | pop r2     ; r2 = 0x30 ('0')
006E | sub r0, r2 ; subtract the user input character by 0x30
0070 | push A     
0075 | pop r2     ; r2 = 0xA
0077 | cmp r0, r2 ; check if (user char < 0xA)
0079 | jl 84
007B | push 7     ; more stuff here that does some arithmetic with the user data character fetched into r0.
0080 | pop r2     ; we'll see soon why this isn't exactly important to know.
0082 | sub r0, r2
0084 | push 10
0089 | pop r2
008B | mul r1, r2
008D | add r1, r0  ; seems like the final arithmetic instruction is stores in r1
008F | loop 64    ; jump to 0x64 and continue (8 iterations)
0091 | push F33746E6 ; You may be thinking what this is? Check the next few instructions
0096 | pop r2        ; r2 = 0xF33746E6
0098 | cmp r1, r2    ; remember r1 was the final value after the code manipulated the last 8 characters of our input,
009A | xor r0, r0    
009C | je a1         ; if the last 8 characters were equal to '6E64733F' (remember endianess), jmp to 0xA1 and continue checking the input.
009E | inc r0        ; also important to note how the code keeps adjusting r0 before ending the program
00A0 | end
```

Now if we keep looking at the output. We'll notice, there is a LOT more instructions, but the good part is we don't need 90% of it. As we saw before, the program pushes part of the key on the stack then just checks the manipulated input for a match. So we just need the part which pushes the correct part of the key.

So lets continue, so far we have `6E64733F` at the end of the string.. so the next relevant `push` is

```asm
00D7 | push 54962766
00DC | pop r2
00DE | cmp r1, r2
```

Just like that, we have another part of the key. Now we have `66726945`.

```asm
011D | dec r1
011F | push 2542601
0124 | pop r2
0126 | cmp r1, r2
0128 | xor r0, r0
```

So now we have `1062452`, right? *No.* The final input value is decremented before being compared! So the value is actually, 0x02542602, or `20624520` for our key.

```asm
0165 | inc r1
0167 | push 547702E7
016C | pop r2
016E | cmp r1, r2
```

Another trick, an `inc` before the compare, it should be `547702E6` for our input, `6E207745` for our key.

```asm
01AD | push 1636C2F6
01B2 | pop r2
01B4 | cmp r1, r2
..
01F3 | push 16865747
01F8 | pop r2
01FA | cmp r1, r2
```

No edits here, we should be able to concatenate all the acquired parts and form a key 48 characters long!

So starting from the end, we have
`74756861`
`6F2C6361`
`6E207745`
`20624520`
`66726945`
`6E64733F`

And combined
`747568616F2C63616E20774520624520667269456E64733F`

Notice at the end
```asm
01FA | cmp r1, r2 ; compare r1 with valid key part
01FC | xor r0, r0 ; zero out the r2 register
01FE | je 202     ; if its a match, end the program
0200 | inc r0     ; inc r0 if it isn't
0202 | end        
```

So it would seem if `r0` is > 0, the key is incorrect. We'll confirm that in `main`.

```cpp
if ( !vm_ctx->r0 )
 printf("Nice!!! U got it!\n", v4);
 ```
 
 So, lets feed the program our key.
 
 ![Imgur Image](https://i.imgur.com/xMUhPAg.png)
 
 
