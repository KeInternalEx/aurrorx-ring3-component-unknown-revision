.386
.model flat

.code

; *************************************************************************
; top half of eax should be zeroed by the caller to align stack to 32 bits
; bottom half of eax (ax), should be the actual segment
; *************************************************************************
_ChangeSegment proc
	jmp enter_the_dragon

perform_switch:
	push eax ; push segment
	push offset continue ; push offset
	retf ; retf into stack pointer, loads cs with segment

enter_the_dragon:
	jmp perform_switch

continue:
	ret
_ChangeSegment endp



end