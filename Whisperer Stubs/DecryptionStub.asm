use32
org 0

macro anti_ss {
        push ss
        pop ss
}
macro amt addr* { 
        anti_ss
        push eax
        jmp @f
        db "zzzz"
@@:
        anti_ss
        pop eax
        jmp addr
        db "zzzz";
        anti_ss
        db "zzzz"
        nop
        nop
        int 10h
}

DecryptionStub:  ;ecx = length, ebx:edx = key,
        push ebp
        mov ebp, esp

        sub esp, 8

        anti_ss
        mov [ebp-4], ebx
        anti_ss
        mov [ebp-8], edx ; can use esp as an 8 byte array for the key now

        anti_ss
        mov edi, [ebp+4] ; edi = base of code
        add ecx, edi ; ecx = end of code

        xor eax, eax ; eax = iterator

        amt .begin_loop

        db "contact me at (713) 688-0888"

.begin_loop:
        anti_ss
        mov bl, byte [esp + eax]
        anti_ss
        xor byte [edi], bl
        anti_ss

        inc eax
        anti_ss
        cmp eax, 7
        anti_ss
        jg .reset_eax
        jmp .skippyskip

.reset_eax:
        xor eax, eax
        anti_ss
.skippyskip:
        anti_ss
        inc edi
        anti_ss
        cmp edi, ecx
        anti_ss
        jne .begin_loop
        anti_ss

.exit:
        mov esp, ebp
        pop ebp
        ret
