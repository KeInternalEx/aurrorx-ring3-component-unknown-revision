use32
org 0



SocketBlockCall:
        push ebp
        mov ebp, esp

        mov ebx, 0xaaaaaaaa ;key0
        mov edx, 0xbbbbbbbb ;key1
        mov ecx, .call_end - .call_begin

        mov eax, [ebp + 8] ; eax = whisperer context
        mov eax, [eax] ; eax = whisperer framework
        mov eax, [eax + 16] ; eax = decryption function

        call eax

.call_begin:
dq 0x2222222222222222 ; delimiter, gets filled with nops at run time


        mov ebx, [ebp + 8] ; ebx = whisperer context
        mov eax, [ebx] ; eax = whisperer framework
        mov eax, [eax + 20] ; eax = socket

        mov cl, byte [ebx + 28] ; cl = Use6
        test cl, cl
        jz .set_v4

        mov ecx, 23 ; ecx = AF_INET6
        jmp .push_args

.set_v4:
        mov ecx, 2 ; ecx = AF_INET

.push_args:

        push 6 ; IPPROTO_TCP
        push 1 ; SOCK_STREAM
        push ecx  ; Address Family

        call eax ; call socket, eax = socket handle



        mov ebx, [ebp + 8] ; ebx = context
        mov dword [ebx + 32], eax ; set SocketHandle

        pop ebp
        ret 4

.call_end: