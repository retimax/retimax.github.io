---
layout: post
title: Crackme-not - Crackmes
categories: [Reversing, Crackmes]
tags: [Challenges, Ghidra]
---

Este es un reto creado por **_weissi1994_** en el cual tendremos que bypassear un login, he de avisar que 
no esta basado en una contraseña especifica si no en cumplir unas serie de reglas para que se cumpla 
una condicional. Puedes encontrarlo en la plataforma de [crackmes.one](https://crackmes.one) la cual
es de bastante utilidad para todos los amantes del reversing, es un challenge de nivel 1, es decir, tiene
un nivel de dificultad **"facil"**.

## Resolución
Podemos ver mediante la utilidad `file` el tipo de archivo al que nos estamos enfrentando:

```bash
❯ file hello
hello: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
 ```

Este ejecutable es un binario de 64 bits para Linux, al ejecutarlo en nuestra terminal veremos una
sesion tipo login en la cual se nos pide introducir un nombre y una contraseña:

```bash
❯ ./hello
Please enter your name: test
Hello test
Enter your Password: test
Wrong Credentials
```

Ahora realizaremos el desensamblado para analizarlo utilizando la herramienta **radare2**:

```shell
❯ radare2 hello
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x00401000]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
```

Listando las funciones podemos ver que solo incluye una llamada `entry0`:

```bash
[0x00401000]> afl
0x00401000    8    301 entry0
```

Si la visualizamos en terminal nos dará el siguiente código en **assembly**:

```bash
[0x00401000]> pdf @entry0
            ;-- section..text:
            ;-- segment.LOAD1:
            ;-- _start:
            ;-- rip:
┌ 301: entry0 ();
│           0x00401000      b801000000     mov eax, 1                  ; [02] -r-x section size 301 named .text
│           0x00401005      bf01000000     mov edi, 1
│           0x0040100a      48be002040..   movabs rsi, loc.msg         ; 0x402000 ; "Please enter your name: "
│           0x00401014      ba19000000     mov edx, 0x19               ; 25
│           0x00401019      0f05           syscall
│           0x0040101b      b800000000     mov eax, 0
│           0x00401020      bf00000000     mov edi, 0
│           0x00401025      48be742040..   movabs rsi, loc.buf         ; 0x402074
│           0x0040102f      ba20000000     mov edx, 0x20               ; 32
│           0x00401034      0f05           syscall
│           0x00401036      4883f800       cmp rax, 0
│       ┌─< 0x0040103a      0f8cd4000000   jl loc._start.error
│       │   0x00401040      4989c6         mov r14, rax
│       │   0x00401043      4983c606       add r14, 6
│       │   0x00401047      488b042519..   mov rax, qword [loc.hello]  ; [0x402019:8]=0x4500206f6c6c6548 ; "Hello "
│       │   0x0040104f      4889042594..   mov qword [loc.welcome], rax ; [0x402094:8]=0
│       │   0x00401057      488b042574..   mov rax, qword [loc.buf]    ; [0x402074:8]=0
│       │   0x0040105f      488904259a..   mov qword [0x40209a], rax   ; [0x40209a:8]=0
│       │   0x00401067      b801000000     mov eax, 1
│       │   0x0040106c      bf01000000     mov edi, 1
│       │   0x00401071      48be942040..   movabs rsi, loc.welcome     ; 0x402094
│       │   0x0040107b      4c89f2         mov rdx, r14
│       │   0x0040107e      0f05           syscall
│       │   0x00401080      b801000000     mov eax, 1
│       │   0x00401085      bf01000000     mov edi, 1
│       │   0x0040108a      48be202040..   movabs rsi, loc.prompt      ; 0x402020 ; "Enter your Password: "
│       │   0x00401094      ba16000000     mov edx, 0x16               ; 22
│       │   0x00401099      0f05           syscall
│       │   0x0040109b      b800000000     mov eax, 0
│       │   0x004010a0      bf00000000     mov edi, 0
│       │   0x004010a5      48be742040..   movabs rsi, loc.buf         ; 0x402074
│       │   0x004010af      ba20000000     mov edx, 0x20               ; 32
│       │   0x004010b4      0f05           syscall
│       │   0x004010b6      4989c7         mov r15, rax
│       │   0x004010b9      49ffcf         dec r15
│       │   ;-- _start.l1:
│       │   ; CODE XREF from entry0 @ 0x4010d8(x)
│      ┌──> 0x004010bc      4d89fe         mov r14, r15
│      ╎│   0x004010bf      4983c605       add r14, 5
│      ╎│   0x004010c3      418a869420..   mov al, byte [r14 + loc.welcome] ; [0x402094:1]=0
│      ╎│   0x004010ca      0405           add al, 5
│      ╎│   0x004010cc      413a877320..   cmp al, byte [r15 + 0x402073]
│     ┌───< 0x004010d3      7522           jne loc._start.wrong
│     │╎│   0x004010d5      49ffcf         dec r15
│     │└──< 0x004010d8      75e2           jne loc._start.l1
│     │ │   0x004010da      b801000000     mov eax, 1
│     │ │   0x004010df      bf01000000     mov edi, 1
│     │ │   0x004010e4      48be532040..   movabs rsi, loc.success     ; 0x402053
│     │ │   0x004010ee      ba18000000     mov edx, 0x18               ; 24
│     │ │   0x004010f3      0f05           syscall
│     │┌──< 0x004010f5      eb25           jmp loc._start.exit
│     │││   ;-- _start.wrong:
│     │││   ; CODE XREF from entry0 @ 0x4010d3(x)
│     └───> 0x004010f7      b801000000     mov eax, 1
│      ││   0x004010fc      bf01000000     mov edi, 1
│      ││   0x00401101      48be362040..   movabs rsi, loc.wrong       ; 0x402036
│      ││   0x0040110b      ba18000000     mov edx, 0x18               ; 24
│      ││   0x00401110      0f05           syscall
│     ┌───< 0x00401112      eb08           jmp loc._start.exit
│     │││   ;-- _start.error:
│     │││   ; CODE XREF from entry0 @ 0x40103a(x)
│     ││└─> 0x00401114      4889042570..   mov qword [loc.ret_code], rax ; [0x402070:8]=0
│     ││    ;-- _start.exit:
│     ││    ; CODE XREFS from entry0 @ 0x4010f5(x), 0x401112(x)
│     └└──> 0x0040111c      b83c000000     mov eax, 0x3c               ; '<' ; 60
│           0x00401121      48bf702040..   movabs rdi, loc.ret_code    ; 0x402070
└           0x0040112b      0f05           syscall
```


Lo que hace este código es alojar nuestros inputs en dos espacios distintos de memoria, en primera instancia
pareciera que no debido a que el espacio que se le asigna a password es el mismo que el que se le asigna a
el nombre que nosotros introducimos como primer campo, pero antes de esto, este input se copia a la dirección
de memoria referenciada como `loc.welcome`:

```bash
│           0x0040100a      48be002040..   movabs rsi, loc.msg         ; 0x402000 ; "Please enter your name: "
│           0x00401014      ba19000000     mov edx, 0x19               ; 25
│           0x00401019      0f05           syscall
│           0x0040101b      b800000000     mov eax, 0
│           0x00401020      bf00000000     mov edi, 0
│           0x00401025      48be742040..   movabs rsi, loc.buf <- Primer alojamiento de name
│           0x0040102f      ba20000000     mov edx, 0x20               ; 32
│           0x00401034      0f05           syscall
│           0x00401036      4883f800       cmp rax, 0
│       ┌─< 0x0040103a      0f8cd4000000   jl loc._start.error
│       │   0x00401040      4989c6         mov r14, rax
│       │   0x00401043      4983c606       add r14, 6
│       │   0x00401047      488b042519..   mov rax, qword [loc.hello]  ; [0x402019:8]=0x4500206f6c6c6548 ; "Hello "
│       │   0x0040104f      4889042594..   mov qword [loc.welcome], rax <- Segundo alojamiento (solo los primeros 8 bytes)
│       │   0x00401057      488b042574..   mov rax, qword [loc.buf]
│       │   0x0040105f      488904259a..   mov qword [0x40209a], rax
```


Después de esto el programa procede a leer el input que introducimos como password para alojarlo en la misma dirección
referenciada como `loc.buff`:

```bash
│       │   0x00401080      b801000000     mov eax, 1
│       │   0x00401085      bf01000000     mov edi, 1
│       │   0x0040108a      48be202040..   movabs rsi, loc.prompt      ; 0x402020 ; "Enter your Password: "
│       │   0x00401094      ba16000000     mov edx, 0x16               ; 22
│       │   0x00401099      0f05           syscall
│       │   0x0040109b      b800000000     mov eax, 0
│       │   0x004010a0      bf00000000     mov edi, 0
│       │   0x004010a5      48be742040..   movabs rsi, loc.buf         ; 0x402074
│       │   0x004010af      ba20000000     mov edx, 0x20               ; 32
```


Ya que se almacenan estos inputs el programa realiza una comparación, y aquí es donde radica el truco
para pasar este challenge, debido a que antes de la comparación modifica nuestro input de una manera un
particular:

```bash
│       │   ;-- _start.l1:
│       │   ; CODE XREF from entry0 @ 0x4010d8(x)
│      ┌──> 0x004010bc      4d89fe         mov r14, r15
│      ╎│   0x004010bf      4983c605       add r14, 5
│      ╎│   0x004010c3      418a869420..   mov al, byte [r14 + loc.welcome] ; [0x402094:1]=0
│      ╎│   0x004010ca      0405           add al, 5
│      ╎│   0x004010cc      413a877320..   cmp al, byte [r15 + 0x402073]
│     ┌───< 0x004010d3      7522           jne loc._start.wrong
│     │╎│   0x004010d5      49ffcf         dec r15
│     │└──< 0x004010d8      75e2           jne loc._start.l1
│     │ │   0x004010da      b801000000     mov eax, 1
│     │ │   0x004010df      bf01000000     mov edi, 1
│     │ │   0x004010e4      48be532040..   movabs rsi, loc.success     ; 0x402053
│     │ │   0x004010ee      ba18000000     mov edx, 0x18               ; 24
│     │ │   0x004010f3      0f05           syscall
│     │┌──< 0x004010f5      eb25           jmp loc._start.exit
```

Desglozando este código sabemos que r14 itera por cada carácter de nuestro inpu **name** saltándose los primeros seis
debido a que estos pertenecen a "Hello ", para después de esto cargarlos dentro de `al` y posteriormente agregarle 5
al valor **_ASCII_** de cada carácter leído previamente:

```bash
│      ╎│   0x004010bf      4983c605       add r14, 5 <-- apunta a cada caracter de name
│      ╎│   0x004010c3      418a869420..   mov al, byte [r14 + loc.welcome] <-- aloja el input en al
│      ╎│   0x004010ca      0405           add al, 5 <-- agrega 5 a el valor de cada caracter iterado en ASCII
```


Después de esto empieza el bucle condicional en el cual se valida la contraseña con el name + 5:

```bash
│      ╎│   0x004010cc      413a877320..   cmp al, byte [r15 + 0x402073] <-- direccion donde empieza a iterar (la passwd empieza en 0x402074)
│     ┌───< 0x004010d3      7522           jne loc._start.wrong <-- si no coincide corta el bucle y redirecciona a la función de passwd invalida 
│     │╎│   0x004010d5      49ffcf         dec r15
│     │└──< 0x004010d8      75e2           jne loc._start.l1 <-- si aun quedan caracteres vuelve a repetir el bucle
``` 

Si todo esto es correcto nos mandará a la función `_start.exit`, la cual regresa un código de finalización exitoso.

Básicamente, para aprobar este challenge tenemos que introducir una contraseña la cual contenga el valor correspondiente a cada carácter 
de `name + 5` en la tabla ASCII. Un ejemplo de esto seria introducir como nombre 1234 y como contraseña 6789, debido a que estos son los valores
de 1 + 5, 2 + 5, etc.

![pwned](/assets/img/posts/crackme-not/pwned.png)
